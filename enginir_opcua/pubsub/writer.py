"""
Publisher side of PubSub (OPC 10000-14 v1.05, 6.2.4, 6.2.6, 7.2.4). Not implemented: delta frames (KeyFrameCount above 1
still sends key frames), chunking, JSON, event-driven publishing, fixed layouts.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections import Counter
from datetime import UTC
from typing import TYPE_CHECKING, Any, Self

from ..common import instantiate_util
from ..common.node import Node
from ..ua import WriterGroupDataType
from ..ua.object_ids import ObjectIds
from ..ua.status_codes import StatusCodes
from ..ua.uaerrors import UaError
from ..ua.uaprotocol_auto import (
    DatagramWriterGroupTransport2DataType,
    DataSetFieldContentMask,
    DataSetFieldFlags,
    DataSetOrderingType,
    DataSetWriterDataType,
    Duration,
    JsonWriterGroupMessageDataType,
    NetworkAddressUrlDataType,
    PubSubState,
    UadpDataSetMessageContentMask,
    UadpDataSetWriterMessageDataType,
    UadpNetworkMessageContentMask,
    UadpWriterGroupMessageDataType,
    Variant,
    VersionTime,
)
from ..ua.uatypes import (
    DataValue,
    DateTime,
    Int16,
    Int32,
    LocalizedText,
    NodeId,
    StatusCode,
    String,
    UInt16,
    UInt32,
    VariantType,
)
from .dataset import PublishedDataSet, select_value_parts, worst_status
from .information_model import PubSubInformationModel, write_typed
from .protocols import IPubSub, PubSubSender
from .uadp import (
    UadpDataSetDataValue,
    UadpDataSetKeepAlive,
    UadpDataSetMessage,
    UadpDataSetMessageHeader,
    UadpDataSetRaw,
    UadpDataSetVariant,
    UadpGroupHeader,
    UadpNetworkMessage,
    raw_layout_error,
)
from .utils import RateLimitedLog

if TYPE_CHECKING:
    from ..server.server import Server

logger = logging.getLogger(__name__)


class DataSetWriter(PubSubInformationModel):
    """
    Write of an Dataset
    """

    _node: Node | None = None

    def __init__(self, cfg: DataSetWriterDataType | None):
        if cfg is None:
            self._cfg = DataSetWriterDataType()
        else:
            self._cfg = cfg
        self._seq_no = 0
        self._last_message_time: float | None = None
        self._warned: set[str] = set()
        super().__init__()

    def get_id(self) -> UInt16:
        return self._cfg.DataSetWriterId

    def get_name(self) -> String:
        return self._cfg.Name

    @classmethod
    def new_uadp(
        cls,
        name: String,
        dataset_name: String,
        dataset_writer_id: UInt16,
        datavalue: bool | None = False,
        raw: bool | None = False,
        enabled: bool | None = True,
        *,
        message_timestamp: bool | None = None,
        message_status: bool | None = None,
    ) -> Self:
        """
        Create a DataSetWriter for UADP with sane defaults
        name: Name of the DataSetWriter
        dataset_name: Name of the Dataset this is used to get a PublishedDataSet
        dataset_writer_id: Id for the subscriber to identify the DataSetWriter
        enabled: if not enabled no msg are generated
        datavalue: each value sends ServerTimestamp, SourceTimestamp and StatusCode otherwise only a variant is send or binary data (raw flag).
        raw: sends raw value. data either datavalue or raw can be used
        message_timestamp: whether the timestamp is added to message header
        message_status: whether the overall status is added to message header
        """
        message_mask = UadpDataSetMessageContentMask.SequenceNumber
        mask: DataSetFieldContentMask
        if datavalue:
            if message_status:
                message_mask |= UadpDataSetMessageContentMask.Status
            if message_timestamp:  # Default to no timestamp for datavalue
                message_mask |= UadpDataSetMessageContentMask.Timestamp
            mask = (
                DataSetFieldContentMask.ServerTimestamp
                | DataSetFieldContentMask.StatusCode
                | DataSetFieldContentMask.SourceTimestamp
            )
        else:
            if message_status is None or message_status:  # Default to status for variant/raw
                message_mask |= UadpDataSetMessageContentMask.Status
            if message_timestamp is None or message_timestamp:  # Default to timestamp for variant/raw
                message_mask |= UadpDataSetMessageContentMask.Timestamp
            if raw:
                mask = DataSetFieldContentMask.RawData
            else:  # Variant encoding
                mask = DataSetFieldContentMask(0)
        message_settings = UadpDataSetWriterMessageDataType(DataSetMessageContentMask=message_mask)
        dsw_cfg = DataSetWriterDataType(
            Name=name,
            Enabled=bool(enabled),
            DataSetWriterId=dataset_writer_id,
            DataSetName=dataset_name,
            KeyFrameCount=UInt32(1),
            MessageSettings=message_settings,
            DataSetFieldContentMask=mask,
        )
        return cls(dsw_cfg)

    def warn_once(self, key: str, message: str, *args: object) -> None:
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(message, *args)

    def generate_promoted_fields(self, pds: PublishedDataSet, message: UadpDataSetMessage) -> list[Variant]:
        """The values of the fields flagged as promoted, in the order of the metadata (OPC 10000-14 v1.05, 6.2.3.2.5)"""
        data = getattr(message, "Data", None)
        if not isinstance(data, list):
            return []
        promoted: list[Variant] = []
        for meta, value in zip(pds.dataset.get_config().Fields, data, strict=False):
            if DataSetFieldFlags.PromotedField in meta.FieldFlags:
                promoted.append(value.Value if isinstance(value, DataValue) else value)
        return promoted

    def check_configuration(self) -> None:
        if self._cfg.KeyFrameCount and self._cfg.KeyFrameCount > 1:
            self.warn_once(
                "KeyFrameCount",
                "DataSetWriter %s: KeyFrameCount %s needs delta frames, which aren't implemented; sending key frames",
                self._cfg.Name,
                self._cfg.KeyFrameCount,
            )

    def _take_sequence_number(self) -> UInt16:
        number = UInt16(self._seq_no)
        self._seq_no = (self._seq_no + 1) & 0xFFFF
        return number

    def generate_keep_alive(self) -> UadpDataSetMessage:
        """A keep-alive DataSetMessage; its sequence number is the next one the writer will use (7.2.4.5.8)"""
        header = UadpDataSetMessageHeader(Valid=True)
        msg_cfg = self._cfg.MessageSettings
        if isinstance(msg_cfg, UadpDataSetWriterMessageDataType):
            if UadpDataSetMessageContentMask.SequenceNumber in msg_cfg.DataSetMessageContentMask:
                header.SequenceNo = UInt16(self._seq_no)
        return UadpDataSetKeepAlive(header)

    def keep_alive_due(self, now: float, keep_alive_time: float) -> bool:
        return (
            keep_alive_time > 0
            and self._last_message_time is not None
            and now - self._last_message_time >= keep_alive_time
        )

    def mark_message_sent(self, now: float) -> None:
        self._last_message_time = now

    async def generate_uadp_dataset(self, pds: PublishedDataSet) -> UadpDataSetMessage:
        msg_cfg = self._cfg.MessageSettings
        if not isinstance(msg_cfg, UadpDataSetWriterMessageDataType):
            msg_cfg = UadpDataSetWriterMessageDataType()
        mask = msg_cfg.DataSetMessageContentMask
        field_mask = self._cfg.DataSetFieldContentMask
        meta = pds.dataset.get_config()
        header = UadpDataSetMessageHeader(Valid=True)
        if UadpDataSetMessageContentMask.MajorVersion in mask:
            header.CfgMajorVersion = meta.ConfigurationVersion.MajorVersion
        if UadpDataSetMessageContentMask.MinorVersion in mask:
            header.CfgMinorVersion = meta.ConfigurationVersion.MinorVersion
        if UadpDataSetMessageContentMask.Timestamp in mask and UadpDataSetMessageContentMask.PicoSeconds in mask:
            header.PicoSeconds = UInt16(0)
        if UadpDataSetMessageContentMask.SequenceNumber in mask:
            header.SequenceNo = UInt16(self._seq_no)
        source = pds.get_source()
        ds: UadpDataSetMessage
        if DataSetFieldContentMask.RawData in field_mask:
            problems = [error for error in (raw_layout_error(f) for f in meta.Fields) if error is not None]
            if problems:
                self.warn_once(
                    "raw", "DataSetWriter %s can't send its fields as RawData: %s", self._cfg.Name, problems[0]
                )
                header.Valid = False
                ds = UadpDataSetRaw(header, b"")
                status = StatusCode(UInt32(StatusCodes.BadConfigurationError))
                dt = DateTime.now(UTC)
            else:
                data, status, dt = await source.get_raw(meta.Fields)
                ds = UadpDataSetRaw(header, b"".join(data))
        elif field_mask == DataSetFieldContentMask(0):
            variants, status, dt = await source.get_variant()
            ds = UadpDataSetVariant(header, variants)
        else:
            values = await source.on_get_value()
            status = worst_status(values)
            ds = UadpDataSetDataValue(header, select_value_parts(values, field_mask))
            dt = DateTime.now(UTC)
        self._seq_no = (self._seq_no + 1) & 0xFFFF
        if UadpDataSetMessageContentMask.Status in mask:
            ds.Header.Status = UInt16((status.value >> 16) & 0xFFFF)
        if UadpDataSetMessageContentMask.Timestamp in mask:
            ds.Header.Timestamp = dt
        return ds

    async def _init_information_model(self, parent: Node, server: Server, pubsub: IPubSub | None) -> None:
        dsw_type = server.get_node(NodeId(Int32(ObjectIds.DataSetWriterType), Int16(0)))
        objs = await instantiate_util.instantiate(
            parent,
            dsw_type,
            idx=1,
            bname=self._cfg.Name,
            instantiate_optional=False,
            dname=LocalizedText(self._cfg.Name, ""),
        )
        dsw_obj = objs[0]
        self._node = dsw_obj
        await self._init_node(dsw_obj, server)
        await parent.add_reference(dsw_obj, NodeId(Int32(ObjectIds.HasDataSetWriter)))
        await parent.delete_reference(dsw_obj, ObjectIds.HasComponent)
        # Add Reference to Dataset
        if pubsub:
            ds = pubsub.get_published_dataset(self._cfg.DataSetName)
            if ds is not None:
                if ds._node is None:
                    raise RuntimeError(f"DataSet node for '{self._cfg.DataSetName}' is not initialized")
                await ds._node.add_reference(dsw_obj, NodeId(Int32(ObjectIds.DataSetToWriter)))
        await self.set_node_value("0:DataSetFieldContentMask", self._cfg.DataSetFieldContentMask)

        await self._node.add_variable(NodeId(NamespaceIndex=Int16(1)), "0:KeyFrameCount", self._cfg.KeyFrameCount)

        await self.set_node_value(
            "0:DataSetWriterProperties",
            Variant(
                self._cfg.DataSetWriterProperties,
                is_array=True,
                VariantType=VariantType.ExtensionObject,
            ),
        )
        # @TODO await self.set_node_value("0:TransportSettings")
        #      await self.set_node_value("0:Enabled", self._cfg.Enabled)
        # UadpDataSetWriterMessageType

        msg_cfg: UadpDataSetWriterMessageDataType | None = self._cfg.MessageSettings
        if isinstance(msg_cfg, UadpDataSetWriterMessageDataType):
            object_type_id = NodeId(Int32(ObjectIds.UadpDataSetWriterMessageType), Int16(0))
            nodes = await instantiate_util.instantiate(
                dsw_obj,
                server.get_node(object_type_id),
                idx=1,
                bname="0:MessageSettings",
                dname=LocalizedText("MessageSettings"),
            )
            msg_settings = nodes[0]
            n = await msg_settings.get_child("0:ConfiguredSize")
            await n.set_data_value(DataValue(Variant(msg_cfg.ConfiguredSize, VariantType.UInt16)))
            n = await msg_settings.get_child("0:DataSetMessageContentMask")
            await n.set_data_value(
                DataValue(Variant(msg_cfg.DataSetMessageContentMask, VariantType.UInt32))
            )  # FIXME: subtype
            n = await msg_settings.get_child("0:DataSetOffset")
            await n.set_data_value(DataValue(Variant(msg_cfg.DataSetOffset, VariantType.UInt16)))
            n = await msg_settings.get_child("0:NetworkMessageNumber")
            await n.set_data_value(DataValue(Variant(msg_cfg.NetworkMessageNumber, VariantType.UInt16)))


class WriterGroup(PubSubInformationModel):
    """
    Configures a group of datasets writer
    """

    _app: Server | None = None

    uadp = True  # Currently only uadp is supported

    def __init__(self, cfg: WriterGroupDataType | None) -> None:
        super().__init__()
        if cfg is not None:
            self._cfg = cfg
            self._writer = [DataSetWriter(writer) for writer in self._cfg.DataSetWriters]
        else:
            self._cfg = WriterGroupDataType()
            self._writer = []
        self._status = PubSubState.Disabled
        self._ps = None
        self._sequence_number = 0  # UInt16, the next one to send
        self._destination: tuple[Any, ...] | None = None
        self._prepared = False
        self.counters: Counter[str] = Counter()
        self._log = RateLimitedLog(logger)
        self._warned: set[str] = set()

    @classmethod
    def new_uadp(
        cls,
        name: String,
        writer_group_id: UInt16,
        group_version: VersionTime = VersionTime(0),
        enabled: bool | None = True,
        publishing_interval: Duration | None = Duration(1000),
        keep_alive_time: Duration | None = Duration(5000),
        max_network_message_size: UInt32 | None = UInt32(1500),
        writer: list[DataSetWriter] | None = None,
        *,
        payload_header: bool | None = True,
        priority: int = 0,
        address: str | None = None,
    ) -> Self:
        """
        Create a WriterGroup for UADP with sane defaults
        name: Name of the WriterGroup
        writer_group_id: Id for the subscriber to identify the writer_group
        enabled: if not enabled no msg are generated
        publishing_interval: time between each publish
        payload_header: add the count and list of DataSetWriterIds to the UADP header
        priority: Priority of the group, 0 to 255; higher groups start first
        address: destination URL (opc.udp://host:port) of a unicast group; None sends to the connection's address
        """
        mask = (
            UadpNetworkMessageContentMask.PublisherId
            | UadpNetworkMessageContentMask.GroupHeader
            | UadpNetworkMessageContentMask.WriterGroupId
            | UadpNetworkMessageContentMask.GroupVersion
            | UadpNetworkMessageContentMask.NetworkMessageNumber
            | UadpNetworkMessageContentMask.SequenceNumber
        )
        if payload_header:
            mask |= UadpNetworkMessageContentMask.PayloadHeader
        message_settings = UadpWriterGroupMessageDataType(
            GroupVersion=group_version,
            NetworkMessageContentMask=mask,
            DataSetOrdering=DataSetOrderingType.AscendingWriterId,
        )
        cfg = WriterGroupDataType(
            Name=name,
            Enabled=bool(enabled),
            WriterGroupId=writer_group_id,
            PublishingInterval=publishing_interval or Duration(0),
            KeepAliveTime=keep_alive_time or Duration(0),
            MaxNetworkMessageSize=max_network_message_size or UInt32(0),
            MessageSettings=message_settings,
            Priority=priority,
        )
        if address is not None:
            cfg.TransportSettings = DatagramWriterGroupTransport2DataType(
                Address=NetworkAddressUrlDataType(NetworkInterface="", Url=address)
            )
        o = cls(cfg)
        if writer:
            for wr in writer:
                o._writer.append(wr)
                o._cfg.DataSetWriters.append(wr._cfg)
        return o

    async def add_writer(self, writer: DataSetWriter) -> None:
        self._writer.append(writer)
        self._cfg.DataSetWriters.append(writer._cfg)
        if self.model_is_init():
            await writer._init_information_model(self._node, self._server, self._app)

    def get_writer(self, name: String) -> DataSetWriter | None:
        return next((c for c in self._writer if c._cfg.Name == name), None)

    def get_destination_url(self) -> str | None:
        """The Address of the datagram transport settings (OPC 10000-14 v1.05, 6.4.1.3.4), if one is configured"""
        settings = self._cfg.TransportSettings
        address = getattr(settings, "Address", None)
        url = getattr(address, "Url", None)
        return str(url) if url else None

    def check_configuration(self) -> None:
        """Raises a UaError for a configuration the group can't run with"""
        interval = self._cfg.PublishingInterval
        if not isinstance(interval, int | float) or math.isnan(interval) or interval <= 0:
            raise UaError(
                f"WriterGroup {self._cfg.Name}: PublishingInterval {interval} isn't supported, it must be above 0"
            )
        msg_cfg = self.get_msg_cfg()
        if not isinstance(msg_cfg, UadpWriterGroupMessageDataType):
            raise UaError("Only the UADP message mapping is implemented")
        if UadpNetworkMessageContentMask.PromotedFields in msg_cfg.NetworkMessageContentMask:
            enabled = [w for w in self._writer if w._cfg.Enabled]
            if len(enabled) > 1 and msg_cfg.DataSetOrdering != DataSetOrderingType.AscendingWriterIdSingle:
                raise UaError(
                    f"WriterGroup {self._cfg.Name}: PromotedFields need one DataSetMessage per NetworkMessage"
                )
        for w in self._writer:
            w.check_configuration()

    async def prepare(self, sender: PubSubSender) -> None:
        """Checks the configuration and resolves the destination; raises a UaError if the group can't run"""
        self.check_configuration()
        url = self.get_destination_url()
        self._destination = await sender.resolve_destination(url) if url is not None else None
        self._prepared = True

    def _warn_once(self, key: str, message: str, *args: object) -> None:
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(message, *args)

    def _init_msg(
        self,
        sender: PubSubSender,
        msg_cfg: UadpWriterGroupMessageDataType,
        msg_no: int,
        class_id: Any,
    ) -> tuple[UadpNetworkMessage, bool, bool]:
        msg = UadpNetworkMessage()
        payload_header = False
        promoted_fields = False
        mask = msg_cfg.NetworkMessageContentMask
        if UadpNetworkMessageContentMask.PublisherId in mask:
            msg.Header.PublisherId = sender.get_publisher_id()
        if UadpNetworkMessageContentMask.GroupHeader in mask:
            msg.GroupHeader = UadpGroupHeader()
            if UadpNetworkMessageContentMask.GroupVersion in mask:
                msg.GroupHeader.GroupVersion = msg_cfg.GroupVersion
            if UadpNetworkMessageContentMask.WriterGroupId in mask:
                msg.GroupHeader.WriterGroupId = self._cfg.WriterGroupId
            if UadpNetworkMessageContentMask.NetworkMessageNumber in mask:
                msg.GroupHeader.NetworkMessageNo = UInt16(msg_no)
            if UadpNetworkMessageContentMask.SequenceNumber in mask:
                msg.GroupHeader.SequenceNo = UInt16(self._sequence_number)
                self._sequence_number = (self._sequence_number + 1) & 0xFFFF
        if UadpNetworkMessageContentMask.PayloadHeader in mask:
            payload_header = True
        if UadpNetworkMessageContentMask.Timestamp in mask:
            msg.Timestamp = DateTime.now(UTC)
            if UadpNetworkMessageContentMask.PicoSeconds in mask:
                msg.PicoSeconds = UInt16(0)
        if UadpNetworkMessageContentMask.DataSetClassId in mask and class_id is not None:
            msg.Header.DataSetClassId = class_id
        if UadpNetworkMessageContentMask.PromotedFields in mask:
            promoted_fields = True
        msg.Payload = []
        return msg, promoted_fields, payload_header

    def _writer_batches(self, msg_cfg: UadpWriterGroupMessageDataType) -> list[list[DataSetWriter]]:
        writers = [w for w in self._writer if w._cfg.Enabled]
        if msg_cfg.DataSetOrdering == DataSetOrderingType.AscendingWriterId:
            return [sorted(writers, key=lambda w: w.get_id())] if writers else []
        if msg_cfg.DataSetOrdering == DataSetOrderingType.AscendingWriterIdSingle:
            return [[x] for x in sorted(writers, key=lambda w: w.get_id())]
        if msg_cfg.DataSetOrdering == DataSetOrderingType.Undefined:
            return [writers] if writers else []
        raise UaError(f"Unknown DataSetOrderingType: {msg_cfg.DataSetOrdering}")

    async def _dataset_message(
        self, w: DataSetWriter, ps: IPubSub, now: float, keep_alive_time: float
    ) -> tuple[PublishedDataSet, UadpDataSetMessage] | None:
        pds = ps.get_published_dataset(w._cfg.DataSetName)
        if pds is None:
            w.warn_once("pds", "DataSetWriter %s: PublishedDataSet %s not found", w._cfg.Name, w._cfg.DataSetName)
            return None
        try:
            message = await w.generate_uadp_dataset(pds)
        except Exception as e:
            self.counters["source_errors"] += 1
            self._log.warning("source-" + str(w._cfg.Name), "DataSetWriter %s: no DataSetMessage, %r", w._cfg.Name, e)
            if w.keep_alive_due(now, keep_alive_time):
                w.mark_message_sent(now)
                return pds, w.generate_keep_alive()
            return None
        w.mark_message_sent(now)
        return pds, message

    async def _publish_round(self, sender: PubSubSender, ps: IPubSub, now: float) -> None:
        msg_cfg = self.get_msg_cfg()
        if not isinstance(msg_cfg, UadpWriterGroupMessageDataType):
            raise UaError("Only the UADP message mapping is implemented")
        keep_alive_time = float(self._cfg.KeepAliveTime or 0) / 1000
        msgs: list[UadpNetworkMessage] = []
        for batch in self._writer_batches(msg_cfg):
            produced = []
            for w in batch:
                result = await self._dataset_message(w, ps, now, keep_alive_time)
                if result is not None:
                    produced.append((w, *result))
            if not produced:
                continue
            class_ids = {pds.dataset.get_config().DataSetClassId for _, pds, _ in produced}
            class_id = class_ids.pop() if len(class_ids) == 1 else None
            if class_id is not None and not class_id.int:
                class_id = None
            msg, promoted_fields, payload_header = self._init_msg(sender, msg_cfg, len(msgs) + 1, class_id)
            assert isinstance(msg.Payload, list)
            for w, pds, message in produced:
                if payload_header:
                    msg.DataSetPayloadHeader.append(w.get_id())
                msg.Payload.append(message)
                if promoted_fields:
                    msg.PromotedFields = w.generate_promoted_fields(pds, message)
            msgs.append(msg)
        if not msgs:
            return
        oversize = sender.send_uadp(msgs, self._destination, int(self._cfg.MaxNetworkMessageSize or 0))
        self.counters["published"] += len(msgs) - len(oversize)
        self.counters["oversize"] += len(oversize)
        if oversize:
            self._warn_once(
                "oversize",
                "WriterGroup %s: a NetworkMessage of %d bytes is larger than MaxNetworkMessageSize %d and isn't sent",
                self._cfg.Name,
                oversize[0],
                self._cfg.MaxNetworkMessageSize,
            )

    async def run(self, sender: PubSubSender, ps: IPubSub) -> None:
        """Publishes at the PublishingInterval on a fixed schedule until cancelled (OPC 10000-14 v1.05, 6.2.6.2)"""
        if not self._cfg.Enabled:
            await self._set_state(PubSubState.Disabled)
            return
        if not self._prepared:
            await self.prepare(sender)
        loop = asyncio.get_running_loop()
        interval = float(self._cfg.PublishingInterval) / 1000
        logger.info("WriterGroup %s running with %s ms", self._cfg.Name, self._cfg.PublishingInterval)
        await self._set_state(PubSubState.Operational)
        failed = False
        next_time = loop.time()
        try:
            while True:
                try:
                    await self._publish_round(sender, ps, loop.time())
                    if failed:
                        failed = False
                        await self._set_state(PubSubState.Operational)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.counters["errors"] += 1
                    self._log.warning("publish", "WriterGroup %s failed to publish: %r", self._cfg.Name, e)
                    if not failed:
                        failed = True
                        await self._set_state(PubSubState.Error)
                next_time += interval
                now = loop.time()
                if next_time <= now:
                    missed = int((now - next_time) // interval) + 1
                    next_time += missed * interval
                    self.counters["missed_rounds"] += missed
                await asyncio.sleep(max(next_time - loop.time(), 0))
        finally:
            await self._set_state(PubSubState.Disabled)

    def get_msg_cfg(self) -> UadpWriterGroupMessageDataType | JsonWriterGroupMessageDataType:
        if isinstance(self._cfg.MessageSettings, UadpWriterGroupMessageDataType):
            return self._cfg.MessageSettings
        if isinstance(self._cfg.MessageSettings, JsonWriterGroupMessageDataType):
            return self._cfg.MessageSettings
        raise UaError(f"WriterGroup {self._cfg.Name} has no usable message settings")

    async def _init_information_model(self, parent: Node, server: Server, pubsub: IPubSub) -> None:
        writer_grp_type = server.get_node(NodeId(Int32(ObjectIds.WriterGroupType)))
        self._ps = pubsub
        nodes = await instantiate_util.instantiate(
            parent,
            writer_grp_type,
            idx=1,
            bname=self._cfg.Name,
            instantiate_optional=False,
            dname=LocalizedText(self._cfg.Name, ""),
        )
        writer_gp_obj = nodes[0]
        self._node = writer_gp_obj
        await parent.add_reference(writer_gp_obj, NodeId(Int32(ObjectIds.HasWriterGroup)))
        await parent.delete_reference(writer_gp_obj, ObjectIds.HasComponent)
        await self._init_node(writer_gp_obj, server)
        await self.set_node_value("0:SecurityMode", self._cfg.SecurityMode)
        await self.set_node_value(
            "0:MaxNetworkMessageSize",
            Variant(self._cfg.MaxNetworkMessageSize, VariantType.UInt32),
        )
        await self.set_node_value(
            "0:GroupProperties",
            Variant(
                self._cfg.GroupProperties,
                VariantType=VariantType.ExtensionObject,
                is_array=True,
            ),
        )
        if self._node is None:
            raise UaError("Writer node is not initialized")
        await self._node.add_variable(
            NodeId(NamespaceIndex=1),
            "0:SecurityGroupId",
            self._cfg.SecurityGroupId,
            datatype=NodeId(ObjectIds.String),
        )
        await self._node.add_variable(
            NodeId(NamespaceIndex=Int16(1)),
            "0:SecurityKeyServices",
            Variant(
                self._cfg.SecurityKeyServices,
                VariantType=VariantType.ExtensionObject,
                is_array=True,
            ),
            datatype=ObjectIds.EndpointDescription,
        )
        await self.set_node_value("0:WriterGroupId", Variant(self._cfg.WriterGroupId, VariantType.UInt16))
        await self.set_node_value("0:PublishingInterval", self._cfg.PublishingInterval)
        await self.set_node_value("0:KeepAliveTime", self._cfg.KeepAliveTime)
        await self.set_node_value("0:Priority", Variant(self._cfg.Priority, VariantType.Byte))
        await self.set_node_value(
            "0:LocaleIds",
            Variant(self._cfg.LocaleIds, VariantType.String, is_array=True),
        )
        if self._cfg.HeaderLayoutUri is None:
            self._cfg.HeaderLayoutUri = ""
        await self.set_node_value("0:HeaderLayoutUri", self._cfg.HeaderLayoutUri)
        # UadpWriterGroupMessageType
        object_type_id = NodeId(Int32(ObjectIds.UadpWriterGroupMessageType))
        nodes = await instantiate_util.instantiate(
            writer_gp_obj,
            server.get_node(object_type_id),
            idx=1,
            bname="0:MessageSettings",
            dname=LocalizedText("MessageSettings"),
        )
        msg_settings = nodes[0]
        msg_cfg = self.get_msg_cfg()
        group_version = await msg_settings.get_child("0:GroupVersion")
        await write_typed(group_version, msg_cfg.GroupVersion)
        ordering = await msg_settings.get_child("0:DataSetOrdering")
        await write_typed(ordering, msg_cfg.DataSetOrdering)
        mask = await msg_settings.get_child("0:NetworkMessageContentMask")
        await write_typed(mask, msg_cfg.NetworkMessageContentMask)
        sampling_offset = await msg_settings.get_child("0:SamplingOffset")
        await write_typed(sampling_offset, msg_cfg.SamplingOffset)
        publishing_offset = await msg_settings.get_child("0:PublishingOffset")
        await publishing_offset.set_data_value(
            DataValue(Variant(msg_cfg.PublishingOffset, VariantType.Double, is_array=True))
        )

        for writer in self._writer:
            await writer._init_information_model(self._node, server, pubsub)
        # @TODO add transport settings  DatagramWriterGroupTransportType
        # transport_settings = await wgrp.get_child("0:TransportSettings")
        # a = await wgrp.get_child("0:MessageSettings")
        # @TODO fill methods
        # add_w = await self._node.get_child("0:AddDataSetWriter")
        # remove_w = await self._node.get_child("0:RemoveDataSetWriter")

"""
Subscriber side of PubSub (OPC 10000-14 v1.05, 6.2.8, 6.2.9, 7.2.3). Not implemented: metadata updates through
discovery, fixed layouts without a payload header, chunk reassembly, delta frames of RawData.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import Counter
from typing import TYPE_CHECKING

from ..common import instantiate_util
from ..common.node import Node
from ..common.utils import Buffer
from ..ua.object_ids import ObjectIds
from ..ua.uaerrors import UaError, UaStatusCodeError
from ..ua.uaprotocol_auto import (
    DataSetReaderDataType,
    PubSubState,
    ReaderGroupDataType,
    SubscribedDataSetMirrorDataType,
    TargetVariablesDataType,
)
from ..ua.uatypes import (
    DataValue,
    Int16,
    Int32,
    LocalizedText,
    NodeId,
    StatusCode,
    String,
    UInt16,
    UInt32,
    Variant,
    VariantType,
)
from .dataset import DataSetMeta, DataSetValue
from .information_model import PubSubInformationModel
from .protocols import SubscribedDataSet
from .subscribed_dataset import (
    SubscribedDataSetMirror,
    SubScribedTargetVariables,
)
from .uadp import (
    UadpDataSetDataValue,
    UadpDataSetDeltaDataValue,
    UadpDataSetDeltaVariant,
    UadpDataSetEvent,
    UadpDataSetHeartbeat,
    UadpDataSetKeepAlive,
    UadpDataSetMessage,
    UadpDataSetMessageHeader,
    UadpDataSetRaw,
    UadpDataSetSkipped,
    UadpDataSetVariant,
    UadpNetworkMessage,
    publisher_id_matches,
    raw_fields_from_binary,
)

if TYPE_CHECKING:
    from ..server.server import Server

logger = logging.getLogger(__name__)


def status_to_status_code(status: UInt16 | None) -> StatusCode:
    """Upgrade the header status to a full StatusCode."""
    return StatusCode(UInt32(((status or 0) & 0xFFFF) << 16))


def datavalue_from_variant(v: Variant, header: UadpDataSetMessageHeader, built_in_type: int = 0) -> DataValue:
    """Upgrade a Variant-encoded field of a Data Key Frame to DataValue for our callback. A Variant holding a
    StatusCode is a Bad field, one holding a DataValue is an Uncertain field (OPC 10000-14 v1.05, 7.2.4.5.4); a field that is
    declared as a StatusCode or a DataValue itself is left alone."""
    if v.VariantType == VariantType.StatusCode and built_in_type != VariantType.StatusCode.value:
        return DataValue(
            Variant(),
            v.Value,
            SourceTimestamp=None,
            ServerTimestamp=header.Timestamp,
            SourcePicoseconds=None,
            ServerPicoseconds=header.PicoSeconds,
        )
    if v.VariantType == VariantType.DataValue and built_in_type != VariantType.DataValue.value:
        return v.Value
    return DataValue(
        v,
        StatusCode(UInt32(0)),
        SourceTimestamp=None,
        ServerTimestamp=header.Timestamp,
        SourcePicoseconds=None,
        ServerPicoseconds=header.PicoSeconds,
    )


class _Dropped(Exception):
    """A DataSetMessage that a reader can't use; the reason is counted"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_NEWER_BELOW = 1 << 14
_OLDER_ABOVE = (1 << 16) - (1 << 14)
_SEQUENCE_MODULUS = 1 << 16


class DataSetReader(PubSubInformationModel):
    """
    Reads a Pubsub Message
    """

    __reader_cnt = 0

    def __init__(
        self,
        cfg: DataSetReaderDataType | None = None,
        subscribed: SubscribedDataSet | None = None,
    ) -> None:
        super().__init__()
        if cfg is None:
            self._cfg = DataSetReaderDataType()
        else:
            self._cfg = cfg
        self._meta = DataSetMeta(self._cfg.DataSetMetaData)
        self._subscribed = None
        if subscribed is not None:
            self._subscribed = subscribed
            get_subscribed_dataset = getattr(self._subscribed, "get_subscribed_dataset", None)
            if callable(get_subscribed_dataset):
                self._cfg.SubscribedDataSet = self._subscribed.get_subscribed_dataset()
        self._task: asyncio.Task[None] | None = None
        self._state = PubSubState.Disabled
        self._seen = asyncio.Event()
        self._last_sequence: int | None = None
        self._last_message_time: float | None = None
        self._bound_server: Server | None = None
        self.counters: Counter[str] = Counter()

    @classmethod
    def new(
        cls,
        publisherId: Variant,
        writer_group_id: UInt16,
        dataset_writer_id: UInt16,
        meta: DataSetMeta | None = None,
        name: str | None = None,
        enabled: bool | None = False,
        subscribed: SubscribedDataSet | None = None,
    ):
        if name is None:
            name = f"Reader{cls.__reader_cnt}"
            cls.__reader_cnt += 1
        cfg = DataSetReaderDataType(
            Name=String(name),
            PublisherId=publisherId,
            Enabled=bool(enabled),
            WriterGroupId=writer_group_id,
            DataSetWriterId=dataset_writer_id,
        )
        o = cls(cfg, subscribed)
        if meta is not None:
            o._meta = meta
            o._cfg.DataSetMetaData = meta._meta
        return o

    def set_subscribed(self, subscribed: SubscribedDataSet) -> None:
        self._subscribed = subscribed

    def bind_server(self, server: Server | None) -> None:
        """Gives a reader that was built from a configuration the sink its SubscribedDataSet describes"""
        self._bound_server = server
        if self._subscribed is None and server is not None:
            if isinstance(self._cfg.SubscribedDataSet, TargetVariablesDataType):
                self._subscribed = SubScribedTargetVariables(server, self._cfg.SubscribedDataSet)

    async def set_meta_data(self, meta: DataSetMeta) -> None:
        self._meta = meta
        self._cfg.DataSetMetaData = meta._meta

    def get_reader_state(self) -> PubSubState:
        return self._state

    async def _enter(self, state: PubSubState) -> None:
        if state == self._state:
            return
        self._state = state
        await self._set_state(state)
        if self._subscribed:
            try:
                await self._subscribed.on_state_change(self._meta, state)
            except Exception:
                logger.exception("%s: the SubscribedDataSet failed to handle the state %s", self._cfg.Name, state.name)

    def _is_new(self, header: UadpDataSetMessageHeader) -> bool:
        """OPC 10000-14 v1.05, 7.2.3: newer than the last processed message, by the modular difference"""
        timeout = float(self._cfg.MessageReceiveTimeout or 0) / 1000
        now = time.monotonic()
        if timeout > 0 and self._last_message_time is not None and now - self._last_message_time > 2 * timeout:
            self._last_sequence = None
        if header.SequenceNo is None or self._last_sequence is None:
            return True
        return (int(header.SequenceNo) - 1 - self._last_sequence) % _SEQUENCE_MODULUS < _NEWER_BELOW

    def _check_versions(self, header: UadpDataSetMessageHeader) -> bool:
        """True if the message has more fields than the metadata because of a newer minor version"""
        version = self._meta.get_config().ConfigurationVersion
        if header.CfgMajorVersion is not None and header.CfgMajorVersion != version.MajorVersion:
            raise _Dropped("configuration version")
        return header.CfgMinorVersion is not None and header.CfgMinorVersion != version.MinorVersion

    def _fields_of(self, ds: UadpDataSetMessage, newer_minor: bool) -> list[DataSetValue]:
        meta_fields = self._meta._fields
        header = ds.Header  # type: ignore[attr-defined]
        if isinstance(ds, UadpDataSetDeltaVariant | UadpDataSetDeltaDataValue):
            fields = []
            for d in ds.Data:
                if d.No >= len(meta_fields):
                    raise _Dropped("field index")
                field = meta_fields[d.No]
                value = d.Value
                if isinstance(ds, UadpDataSetDeltaVariant):
                    value = datavalue_from_variant(value, header, int(field.BuiltInType))
                fields.append(DataSetValue(field.Name, value, field))
            return fields
        if isinstance(ds, UadpDataSetRaw):
            try:
                variants = raw_fields_from_binary(Buffer(ds.Data), [f._meta for f in meta_fields])
            except UaError as e:
                raise _Dropped("raw data") from e
            status = status_to_status_code(header.Status)
            values = [
                DataValue(v, status, ServerTimestamp=header.Timestamp, ServerPicoseconds=header.PicoSeconds)
                for v in variants
            ]
        elif isinstance(ds, UadpDataSetDataValue):
            values = list(ds.Data)
        elif isinstance(ds, UadpDataSetVariant | UadpDataSetEvent):
            values = [
                datavalue_from_variant(v, header, int(f.BuiltInType))
                for v, f in zip(ds.Data, meta_fields, strict=False)
            ] + [datavalue_from_variant(v, header) for v in ds.Data[len(meta_fields) :]]
        else:
            raise _Dropped("message type")
        if len(values) < len(meta_fields) or (len(values) > len(meta_fields) and not newer_minor):
            raise _Dropped("field count")
        return [DataSetValue(m.Name, d, m) for d, m in zip(values, meta_fields, strict=False)]

    async def _message_received(self, key_frame: bool) -> None:
        self._last_message_time = time.monotonic()
        self._seen.set()
        if key_frame and self._state != PubSubState.Operational:
            await self._enter(PubSubState.Operational)

    async def handle_dataset(self, ds: UadpDataSetMessage) -> None:
        if isinstance(ds, UadpDataSetSkipped):
            self.counters["ignored: skipped DataSetMessage"] += 1
            return
        header: UadpDataSetMessageHeader = ds.Header  # type: ignore[attr-defined]
        if not header.Valid:
            self.counters["ignored: not valid"] += 1
            return
        if isinstance(ds, UadpDataSetKeepAlive):
            await self._message_received(key_frame=False)
            return
        if not self._is_new(header):
            self.counters["ignored: duplicate or older"] += 1
            return
        try:
            if isinstance(ds, UadpDataSetHeartbeat):
                fields: list[DataSetValue] = []
            else:
                fields = self._fields_of(ds, self._check_versions(header))
        except _Dropped as dropped:
            self.counters[f"dropped: {dropped.reason}"] += 1
            logger.debug("%s: dropped a DataSetMessage: %s", self._cfg.Name, dropped.reason)
            return
        if header.SequenceNo is not None:
            self._last_sequence = int(header.SequenceNo)
        is_delta = isinstance(ds, UadpDataSetDeltaVariant | UadpDataSetDeltaDataValue)
        await self._message_received(key_frame=not is_delta)
        if isinstance(ds, UadpDataSetHeartbeat):
            return
        if self._subscribed:
            await self._subscribed.on_dataset_received(self._meta, fields)
        else:
            logger.warning("DataSet %s: got Message without a SubscribedDataSet Handler", self._cfg.Name)

    def _datavalues_from_raw(self, data: UadpDataSetRaw, header: UadpDataSetMessageHeader) -> list[DataValue]:
        """Converts Raw dataset to DataValue"""
        variants = raw_fields_from_binary(Buffer(data.Data), [f._meta for f in self._meta._fields])
        status = status_to_status_code(header.Status)
        return [
            DataValue(
                v,
                status,
                SourceTimestamp=None,
                ServerTimestamp=header.Timestamp,
                SourcePicoseconds=None,
                ServerPicoseconds=header.PicoSeconds,
            )
            for v in variants
        ]

    async def _timeout_task(self) -> None:
        while True:
            timeout = float(self._cfg.MessageReceiveTimeout or 0) / 1000
            try:
                if timeout > 0 and self._state != PubSubState.Error:
                    await asyncio.wait_for(self._seen.wait(), timeout)
                else:
                    await self._seen.wait()
            except TimeoutError:
                logger.warning("%s: Timed out", self._cfg.Name)
                await self._enter(PubSubState.Error)
                continue
            self._seen.clear()

    async def start(self) -> None:
        if not self._cfg.Enabled:
            return
        self._seen = asyncio.Event()
        self._last_sequence = None
        self._last_message_time = None
        await self._enter(PubSubState.PreOperational)
        self._task = asyncio.create_task(self._timeout_task())

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self._enter(PubSubState.Disabled)

    async def _init_information_model(self, parent: Node, server: Server) -> None:
        """
        Inits the information model
        """
        reader_grp_type = server.get_node(NodeId(Int32(ObjectIds.DataSetReaderType)))
        nodes = await instantiate_util.instantiate(
            parent,
            reader_grp_type,
            idx=1,
            bname=self._cfg.Name,
            instantiate_optional=False,
            dname=LocalizedText(self._cfg.Name, ""),
        )
        reader_obj = nodes[0]
        await self._init_node(reader_obj, server)
        await parent.add_reference(reader_obj, NodeId(Int32(ObjectIds.HasDataSetReader)))
        await parent.delete_reference(reader_obj, ObjectIds.HasComponent)
        # @FIXME currently the datatype is wrong in the AddressSpace! Need to change schema generator
        await self.set_node_value("0:PublisherId", Variant(str(self._cfg.PublisherId)))
        await self.set_node_value("0:WriterGroupId", self._cfg.WriterGroupId)
        await self.set_node_value("0:DataSetMetaData", self._cfg.DataSetMetaData)
        await self.set_node_value("0:DataSetFieldContentMask", self._cfg.DataSetFieldContentMask)
        await self.set_node_value("0:MessageReceiveTimeout", self._cfg.MessageReceiveTimeout)
        await self.set_node_value("0:KeyFrameCount", Variant(self._cfg.KeyFrameCount, VariantType.UInt32))
        if self._cfg.HeaderLayoutUri is None:
            self._cfg.HeaderLayoutUri = ""
        await self.set_node_value("0:HeaderLayoutUri", self._cfg.HeaderLayoutUri)
        # await self.set_node_value("0:SecurityMode", self._cfg.SecurityMode)
        # await self.set_node_value("0:SecurityGroupId", self._cfg.SecurityGroupId)
        # await self.set_node_value("0:SecurityKeyServices", self._cfg.SecurityKeyServices)
        await self.set_node_value(
            "0:DataSetReaderProperties",
            Variant(
                self._cfg.DataSetReaderProperties,
                VariantType.ExtensionObject,
                is_array=True,
            ),
        )
        """ @TODO
        # "0:Enabled" ignore for now
        TransportSettings
        MessageSettings
        """
        if self._subscribed is None:
            if isinstance(self._cfg.SubscribedDataSet, SubscribedDataSetMirrorDataType):
                self._subscribed = SubscribedDataSetMirror(self._cfg.SubscribedDataSet, self._node)
            elif isinstance(self._cfg.SubscribedDataSet, TargetVariablesDataType):
                self._subscribed = SubScribedTargetVariables(self._server, self._cfg.SubscribedDataSet)
        if self._subscribed is not None:
            if self._node is not None:
                try:
                    await (await self._node.get_child("0:SubscribedDataSet")).delete(recursive=True)
                except UaStatusCodeError:
                    pass
            if isinstance(self._subscribed, SubScribedTargetVariables):
                nodes = await instantiate_util.instantiate(
                    self._node,
                    server.get_node(NodeId(ObjectIds.TargetVariablesType)),
                    bname="0:SubscribedDataSet",
                    dname=LocalizedText("SubscribedDataSet"),
                    idx=1,
                    instantiate_optional=False,
                )
                await self.set_node_value(
                    ["0:SubscribedDataSet", "0:TargetVariables"],
                    self._subscribed._cfg.TargetVariables,
                )
            elif isinstance(self._subscribed, SubscribedDataSetMirror):
                nodes = await instantiate_util.instantiate(
                    self._node,
                    server.get_node(NodeId(ObjectIds.SubscribedDataSetMirrorType)),
                    bname="0:SubscribedDataSet",
                    dname=LocalizedText("SubscribedDataSet"),
                    idx=1,
                    instantiate_optional=False,
                )
        # @TODO fill methods
        # add_r = await self._node.get_child("0:CreateTargetVariables")
        # remove_r = await self._node.get_child("0:CreateDataSetMirror")


class ReaderGroup(PubSubInformationModel):
    """
    Manages different reader
    """

    __reader_cnt = 0

    def __init__(self, cfg: ReaderGroupDataType) -> None:
        super().__init__()
        self._cfg = cfg
        self._reader = [DataSetReader(r) for r in cfg.DataSetReaders]
        self._tasks = None
        self.counters: Counter[str] = Counter()

    @classmethod
    def new(
        cls,
        name: str | None = None,
        reader: list[DataSetReader] | None = None,
        enable=False,
    ):
        obj = cls(ReaderGroupDataType())
        obj._reader = reader if reader is not None else []
        obj._cfg.DataSetReaders = [r._cfg for r in obj._reader]
        if name is not None:
            obj._cfg.Name = name
        else:
            obj._cfg.Name = "Reader" + str(cls.__reader_cnt)
            cls.__reader_cnt += 1
        obj._cfg.Enabled = enable
        return obj

    def get_name(self) -> String:
        return self._cfg.Name

    async def set_name(self, name: String) -> None:
        self._cfg.Name = name

    def bind_server(self, server: Server | None) -> None:
        for reader in self._reader:
            reader.bind_server(server)

    async def add_dataset_reader(self, reader: DataSetReader) -> None:
        self._reader.append(reader)
        self._cfg.DataSetReaders.append(reader._cfg)
        if self.model_is_init():
            await reader._init_information_model(self._node, self._server)

    def _matching(self, reader: DataSetReader, msg: UadpNetworkMessage) -> list[int]:
        """The positions of the DataSetMessages of the NetworkMessage that pass the reader's filters (6.2.9.1 to
        6.2.9.3)"""
        cfg = reader._cfg
        if not cfg.Enabled or not publisher_id_matches(cfg.PublisherId, msg.Header.PublisherId):
            return []
        writer_group_id = msg.GroupHeader.WriterGroupId if msg.GroupHeader is not None else None
        if cfg.WriterGroupId and cfg.WriterGroupId != writer_group_id:
            return []
        assert isinstance(msg.Payload, list)
        if msg.DataSetPayloadHeader:
            writer_ids = list(msg.DataSetPayloadHeader)
        else:
            writer_ids = [UInt16(0)] * len(msg.Payload)
        if not cfg.DataSetWriterId:
            return list(range(len(msg.Payload)))
        return [i for i, writer_id in enumerate(writer_ids) if writer_id == cfg.DataSetWriterId]

    async def handle_msg(self, msg: UadpNetworkMessage) -> None:
        if not self._cfg.Enabled:
            self.counters["ignored: group not enabled"] += 1
            return
        if not isinstance(msg.Payload, list):
            self.counters["ignored: not a DataSetMessage"] += 1
            return
        found_reader = False
        for reader in self._reader:
            for index in self._matching(reader, msg):
                found_reader = True
                try:
                    await reader.handle_dataset(msg.Payload[index])
                except Exception:
                    reader.counters["errors"] += 1
                    logger.exception("%s: failed to handle a DataSetMessage", reader._cfg.Name)
        if not found_reader:
            self.counters["ignored: no matching reader"] += 1
            logger.debug("Got Message with no matching reader: %s", msg.Header.PublisherId)

    async def start(self):
        await self._set_state(PubSubState.Operational)
        try:
            for reader in self._reader:
                await reader.start()
        except Exception:
            await self._set_state(PubSubState.Error)
            raise

    async def stop(self):
        await self._set_state(PubSubState.Disabled)
        for reader in self._reader:
            await reader.stop()

    async def _init_information_model(self, parent: Node, server: Server) -> None:
        """
        Inits the information model
        """
        reader_grp_type = server.get_node(NodeId(Int32(ObjectIds.ReaderGroupType)))
        nodes = await instantiate_util.instantiate(
            parent,
            reader_grp_type,
            idx=1,
            bname=self._cfg.Name,
            instantiate_optional=False,
            dname=LocalizedText(self._cfg.Name, ""),
        )
        reader_gp_obj = nodes[0]
        await self._init_node(reader_gp_obj, server)
        await parent.add_reference(reader_gp_obj, NodeId(Int32(ObjectIds.HasReaderGroup)))
        await parent.delete_reference(reader_gp_obj, ObjectIds.HasComponent)
        await self.set_node_value("0:SecurityMode", self._cfg.SecurityMode)
        await self.set_node_value(
            "0:MaxNetworkMessageSize",
            Variant(self._cfg.MaxNetworkMessageSize, VariantType.UInt32),
        )
        if self._node is not None:
            await self._node.add_variable(
                NodeId(NamespaceIndex=Int16(1)),
                "0:SecurityGroupId",
                self._cfg.SecurityGroupId,
                datatype=NodeId(Int32(ObjectIds.String)),
            )
        else:
            logger.warning("self._node is None, cannot add variable")
        await self.set_node_value(
            "0:GroupProperties",
            Variant(self._cfg.GroupProperties, VariantType.ExtensionObject, is_array=True),
        )
        # await self._node.add_variable(NodeId(NamespaceIndex=1), "0:SecurityKeyServices", Variant(self._cfg.SecurityKeyServices, VariantType.ExtensionObject, is_array=True), VariantType.ExtensionObject)
        # @TODO fill methods
        # add_r = await self._node.get_child("0:AddDataSetReader")
        # remove_r = await self._node.get_child("0:RemoveDataSetReader")

        for reader in self._reader:
            await reader._init_information_model(self._node, self._server)

"""
Connection which sends/generates and receives/handles pubsub message
over the network
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ..common.instantiate_util import instantiate
from ..common.methods import uamethod
from ..pubsub.information_model import PubSubInformationModel
from ..ua import (
    Byte,
    Int32,
    LocalizedText,
    MessageSecurityMode,
    NodeId,
    ObjectIds,
    PubSubConnectionDataType,
    PubSubState,
    String,
    UInt16,
    UInt32,
    UInt64,
    Variant,
    VariantType,
)
from ..ua.status_codes import StatusCodes
from ..ua.uaerrors import UaError, UaStatusCodeError
from ..ua.uaprotocol_auto import ReaderGroupDataType, WriterGroupDataType
from .protocols import IPubSub, PubSubReceiver
from .reader import ReaderGroup
from .uadp import UadpNetworkMessage
from .udp import OpcUdp, UdpSettings
from .writer import WriterGroup

if TYPE_CHECKING:
    from ..server.server import Server


logger = logging.getLogger(__name__)


SECURED_MODES = (MessageSecurityMode.Sign, MessageSecurityMode.SignAndEncrypt)
UDP_UADP_PROFILE = String("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp")


class PubSubConnection(PubSubInformationModel):
    def __init__(self, cfg: PubSubConnectionDataType) -> None:
        """
        Inits a PubSubConnection from opcua PubSubConnectionDataType
        """
        super().__init__()
        self._cfg = cfg
        if self._cfg.PublisherId.VariantType not in [
            VariantType.Byte,
            VariantType.UInt16,
            VariantType.UInt32,
            VariantType.UInt64,
            VariantType.String,
        ]:
            raise UaError(f"No valid publisher_id: {self._cfg.PublisherId}")
        if self._cfg.TransportProfileUri != UDP_UADP_PROFILE:
            raise UaError(f"Not supported PubSub Profile: {self._cfg.TransportProfileUri}")
        udp_cfg = UdpSettings.from_cfg(self._cfg)
        self._network_factory = OpcUdp
        self._network_settings = udp_cfg
        self._writer_groups = [WriterGroup(cfg) for cfg in self._cfg.WriterGroups]
        self._reader_groups = [ReaderGroup(cfg) for cfg in self._cfg.ReaderGroups]
        self._receiver = self
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: OpcUdp | None = None
        self._writer_tasks: dict[WriterGroup, asyncio.Task[None]] = {}
        self._nodes = {}
        self._bound_server: Server | None = None
        self._app: IPubSub | None = None
        self._invalid_groups: list[WriterGroup] = []

    @classmethod
    def udp_uadp(
        cls,
        name: str,
        publisher_id: Byte | UInt16 | UInt32 | UInt64 | String | Variant,
        network_cfg: UdpSettings,
        reader_groups: list[ReaderGroup] | None = None,
        writer_groups: list[WriterGroup] | None = None,
    ):
        """
        Creates UDP UADP Connection
        """
        if isinstance(publisher_id, Byte):
            pubid = Variant(publisher_id, VariantType.Byte)
        elif isinstance(publisher_id, UInt16):
            pubid = Variant(publisher_id, VariantType.UInt16)
        elif isinstance(publisher_id, UInt32):
            pubid = Variant(publisher_id, VariantType.UInt32)
        elif isinstance(publisher_id, UInt64):
            pubid = Variant(publisher_id, VariantType.UInt64)
        elif isinstance(publisher_id, int):
            pubid = Variant(publisher_id, VariantType.UInt32)
        elif isinstance(publisher_id, str) or isinstance(publisher_id, String):
            pubid = Variant(publisher_id, VariantType.String)
        elif isinstance(publisher_id, Variant):
            pubid = publisher_id
        else:
            raise UaError(f"No valid publisher_id: {publisher_id}")
        address = network_cfg.get_address()
        properties = network_cfg.get_key_value()
        cfg = PubSubConnectionDataType(
            Name=String(name),
            Enabled=True,
            PublisherId=pubid,
            TransportProfileUri=UDP_UADP_PROFILE,
            Address=address,  # this assignment is valid
            ConnectionProperties=properties,
        )
        o = cls(cfg)
        if writer_groups is not None:
            o._writer_groups = writer_groups
            cfg.WriterGroups = [g._cfg for g in writer_groups]
        if reader_groups is not None:
            o._reader_groups = reader_groups
            cfg.ReaderGroups = [g._cfg for g in reader_groups]
        return o

    async def get_name(self) -> String:
        """
        the name of the connection
        """
        if self.model_is_init():
            return await self._get_node_name()
        return self._cfg.Name

    async def add_writer_group(self, writer_group: WriterGroup) -> None:
        """
        Adds a writer group
        """
        if writer_group._cfg not in self._cfg.WriterGroups:
            self._cfg.WriterGroups.append(writer_group._cfg)
        self._writer_groups.append(writer_group)
        if self.model_is_init():
            await writer_group._init_information_model(self._node, self._server, self._app)

    async def add_reader_group(self, reader: ReaderGroup) -> None:
        """
        Adds a reader group
        """
        if reader._cfg not in self._cfg.ReaderGroups:
            self._cfg.ReaderGroups.append(reader._cfg)
        self._reader_groups.append(reader)
        reader.bind_server(self._bound_server)
        if self.model_is_init():
            await reader._init_information_model(self._node, self._server)

    def get_config(self) -> PubSubConnectionDataType:
        """
        Returns the PubSubConnection configuration.
        """
        return self._cfg

    def get_writer_group(self, name: String) -> WriterGroup | None:
        """
        Returns a writer group via name, if found.
        """
        return next((w for w in self._writer_groups if w._cfg.Name == name), None)

    def get_reader_group(self, name: String) -> ReaderGroup | None:
        """
        Returns a reader group via name, if found.
        """
        return next((r for r in self._reader_groups if r.get_name() == name), None)

    async def remove_reader_group(self, name: String) -> None:
        """
        Removes a reader group from the connection: stops it, deletes its node and forgets it
        """
        r = self.get_reader_group(name)
        if r is None:
            raise ValueError(f"Unknown ReaderGroup {name}")
        await r.stop()
        if r._node is not None:
            await r._node.delete(recursive=True)
        self._reader_groups.remove(r)
        if r._cfg in self._cfg.ReaderGroups:
            self._cfg.ReaderGroups.remove(r._cfg)

    async def remove_writer_group(self, name: String) -> None:
        """
        Removes a writer group from the connection: stops it, deletes its node and forgets it
        """
        w = self.get_writer_group(name)
        if w is None:
            raise ValueError(f"Unknown WriterGroup {name}")
        task = self._writer_tasks.pop(w, None)
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await w._set_state(PubSubState.Disabled)
        if w._node is not None:
            await w._node.delete(recursive=True)
        self._writer_groups.remove(w)
        if w._cfg in self._cfg.WriterGroups:
            self._cfg.WriterGroups.remove(w._cfg)

    def _check_startable(self) -> None:
        secured = self._groups_with_message_security()
        if secured:
            raise UaError(f"PubSub message security is not supported, refusing to start {', '.join(secured)}")
        if self._writer_groups and self._app is None:
            raise UaError(
                f"Connection {self._cfg.Name} has writer groups but no PubSub: add it with PubSub.add_connection()"
            )

    def _groups_to_run(self) -> list[WriterGroup]:
        """The enabled writer groups in order of their priority, highest first; a group with an Address on a
        multicast connection is in the Error state (Part 14, 7.3.2.2)"""
        groups = []
        for group in sorted(self._writer_groups, key=lambda w: int(w._cfg.Priority or 0), reverse=True):
            if self._network_settings.is_multicast() and group.get_destination_url() is not None:
                logger.error(
                    "WriterGroup %s has an Address, but the multicast connection %s sends to its own address",
                    group._cfg.Name,
                    self._cfg.Name,
                )
                self._invalid_groups.append(group)
                continue
            groups.append(group)
        return groups

    async def start(self) -> None:
        """
        Starts the connection, which listens to incoming messages
        and sends messages from writers. If it can't start, it is cleaned up and the error is raised.
        """
        logger.info("Starting Connection %s", await self.get_name())
        if not self._cfg.Enabled:
            await self._set_state(PubSubState.Disabled)
            return
        try:
            self._check_startable()
            self._invalid_groups = []
            groups = self._groups_to_run()
            loop = asyncio.get_running_loop()
            sock, _, _ = self._network_settings.create_socket(
                receive=bool(self._reader_groups) or self._receiver is not self
            )
            types = self._bound_server.types if self._bound_server is not None else None
            self._transport, self._protocol = await loop.create_datagram_endpoint(
                lambda: self._network_factory(self._network_settings, self._receiver, self._cfg.PublisherId, types),
                sock=sock,
            )
            for group in self._writer_groups:
                group._ps = self._app
            for group in groups:
                await group.prepare(self._protocol)
            for reader in self._reader_groups:
                await reader.start()
            self._protocol.set_receiver(self._receiver)
            for group in self._invalid_groups:
                await group._set_state(PubSubState.Error)
            for group in groups:
                if group._cfg.Enabled:
                    self._writer_tasks[group] = loop.create_task(group.run(self._protocol, self._app))
            await self._set_state(PubSubState.Operational)
        except BaseException:
            await self._cleanup()
            await self._set_state(PubSubState.Error)
            raise

    def _groups_with_message_security(self) -> list[str]:
        secured = [str(group._cfg.Name) for group in self._writer_groups if group._cfg.SecurityMode in SECURED_MODES]
        secured += [str(group._cfg.Name) for group in self._reader_groups if group._cfg.SecurityMode in SECURED_MODES]
        secured += [
            str(reader._cfg.Name)
            for group in self._reader_groups
            for reader in group._reader
            if reader._cfg.SecurityMode in SECURED_MODES
        ]
        return secured

    async def _cleanup(self) -> None:
        tasks = list(self._writer_tasks.values())
        self._writer_tasks = {}
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*[reader.stop() for reader in self._reader_groups], return_exceptions=True)
        protocol, self._protocol = self._protocol, None
        if protocol is not None:
            await protocol.close()
        transport, self._transport = self._transport, None
        if transport is not None:
            transport.close()

    async def stop(self) -> None:
        """Stops all activity of a connection; safe to call again"""
        logger.info("Stopping Connection %s", await self.get_name())
        await self._cleanup()
        await self._set_state(PubSubState.Disabled)

    async def send_uadp_msg(self, msg: UadpNetworkMessage) -> None:
        """Send a pubsub message in uadp format"""
        if self._network_factory != OpcUdp:
            await self._set_state(PubSubState.Error)
            raise UaError("Sending a Uadp Encoded Message is not supported with this connection")
        if self._protocol is not None:
            self._protocol.send_uadp([msg])
        else:
            logger.error("Cannot send UADP message: protocol is None")
            raise UaError("Cannot send UADP message: protocol is None")

    def set_if(self, ps: IPubSub) -> None:
        """
        Registers an IPubSub for the connection
        """
        self._app = ps

    def bind_server(self, server: Server | None) -> None:
        """Gives the readers of the connection their sinks, see `DataSetReader.bind_server`"""
        self._bound_server = server
        for group in self._reader_groups:
            group.bind_server(server)

    def set_receiver(self, receiver: PubSubReceiver) -> None:
        """
        Sets a PubSubReceiver which receives pubsub events
        """
        if self._protocol is not None:
            self._protocol.set_receiver(receiver)
        self._receiver = receiver

    async def got_uadp(self, msg: UadpNetworkMessage) -> None:
        """Handels a Uadp Message"""
        for r in self._reader_groups:
            await r.handle_msg(msg)

    @uamethod
    async def _add_reader_group(self, parent: NodeId, rg: ReaderGroupDataType) -> NodeId:
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)

    @uamethod
    async def _add_writer_group(self, parent: NodeId, wg: WriterGroupDataType) -> NodeId:
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)

    @uamethod
    async def _remove_group(self, parent: NodeId, nid: NodeId) -> None:
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)

    async def _init_information_model(self, server: Server) -> None:
        """
        Inits the information model
        """
        parent_pubsub = server.get_node(NodeId(Int32(ObjectIds.PublishSubscribe)))
        con_type = server.get_node(NodeId(Int32(ObjectIds.PubSubConnectionType)))
        objs = await instantiate(
            parent_pubsub,
            con_type,
            idx=1,
            bname=self._cfg.Name,
            instantiate_optional=False,
            dname=LocalizedText(self._cfg.Name, ""),
        )
        con_var = objs[0]
        await parent_pubsub.add_reference(con_var, NodeId(Int32(ObjectIds.HasPubSubConnection)))
        await parent_pubsub.delete_reference(con_var, ObjectIds.HasComponent)
        await self._init_node(con_var, server)
        # @FIXME currently the datatype is wrong in the AddressSpace! Need to change schema generator
        await self.set_node_value("0:PublisherId", Variant(str(self._cfg.PublisherId)))
        await self.set_node_value("0:TransportProfileUri", self._cfg.TransportProfileUri)
        await self.set_node_value(
            "0:ConnectionProperties",
            Variant(Value=self._cfg.ConnectionProperties, VariantType=VariantType.ExtensionObject),
        )
        if self._node is not None:
            addr = await self._node.get_child("0:Address")
            await addr.delete()
        object_type_id = NodeId(Int32(ObjectIds.NetworkAddressUrlType))
        await instantiate(
            con_var,
            server.get_node(object_type_id),
            idx=1,
            bname="0:Address",
            dname=LocalizedText("Address"),
        )
        con_addr = self._network_settings.get_address()
        await self.set_node_value(["0:Address", "0:NetworkInterface"], con_addr.NetworkInterface)
        await self.set_node_value(["0:Address", "0:Url"], con_addr.Url)
        meth = await instantiate(
            con_var,
            server.get_node(NodeId(Int32(ObjectIds.PubSubConnectionType_AddReaderGroup))),
            idx=1,
            bname="0:AddReaderGroup",
            dname=LocalizedText("AddReaderGroup"),
        )
        server.link_method(meth[0], self._add_reader_group)
        meth = await instantiate(
            con_var,
            server.get_node(NodeId(Int32(ObjectIds.PubSubConnectionType_AddWriterGroup))),
            idx=1,
            bname="0:AddWriterGroup",
            dname=LocalizedText("AddWriterGroup"),
        )
        server.link_method(meth[0], self._add_writer_group)
        meth = await instantiate(
            con_var,
            server.get_node(NodeId(Int32(ObjectIds.PubSubConnectionType_RemoveGroup))),
            idx=1,
            bname="0:RemoveGroup",
            dname=LocalizedText("RemoveGroup"),
        )
        server.link_method(meth[0], self._remove_group)
        for wg in self._writer_groups:
            await wg._init_information_model(self._node, self._server, self._app)
        for rg in self._reader_groups:
            await rg._init_information_model(self._node, self._server)

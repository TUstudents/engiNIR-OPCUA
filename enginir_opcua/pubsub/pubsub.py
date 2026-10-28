"""
top level of PubSub, similar to the Client/Server
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import anyio

from ..common.node import Node
from ..common.utils import Buffer
from ..ua import PubSubConfigurationDataType, String
from ..ua.object_ids import ObjectIds
from ..ua.status_codes import StatusCodes
from ..ua.ua_binary import extensionobject_from_binary, extensionobject_to_binary
from ..ua.uaerrors import UaError, UaStatusCodeError
from ..ua.uaprotocol_auto import PublishedDataItemsDataType, PublishedDataSetDataType, PubSubState, UABinaryFileDataType
from ..ua.uatypes import NodeId, Variant
from .connection import PubSubConnection
from .dataset import PublishedDataItems, PublishedDataSet
from .information_model import PubSubInformationModel

if TYPE_CHECKING:
    from ..server.server import Server

logger = logging.getLogger(__name__)


class PubSub(PubSubInformationModel):
    """
    Top Level PubSub Entry. Manages DataSets and Connections.
    """

    def __init__(self, cfg: PubSubConfigurationDataType = None, server: Server = None) -> None:
        super().__init__()
        self._running = False
        self._pds: list[PublishedDataSet] = []
        self._con: list[PubSubConnection] = []
        self._enabled = False
        self._server = server
        self._node = None
        self._datasets_node: Node | None = None
        if cfg is not None:
            self._pds = [self._new_published_dataset(pds) for pds in cfg.PublishedDataSets]
            self._con = [PubSubConnection(c) for c in cfg.Connections]
            for con in self._con:
                self._register(con)

    def _register(self, con: PubSubConnection) -> None:
        con.set_if(self)
        con.bind_server(self._server)

    def _new_published_dataset(self, cfg: PublishedDataSetDataType) -> PublishedDataSet:
        if self._server is not None and isinstance(cfg.DataSetSource, PublishedDataItemsDataType):
            return PublishedDataItems(cfg, self._server)
        return PublishedDataSet(cfg)

    @classmethod
    def new(
        cls,
        connections: list[PubSubConnection] | None = None,
        datasets: list[PublishedDataSet] | None = None,
    ):
        o = cls()
        if connections is not None:
            o._con = connections
            for con in connections:
                o._register(con)
        if datasets is not None:
            o._pds = datasets
        return o

    async def init_information_model(self) -> None:
        """
        Inits the Information Model: each dataset and each connection appears once, however many there are
        """
        if self._server is None:
            raise RuntimeError("Server is not initialized")
        if self._node is None:
            self._node = self._server.get_node(NodeId(ObjectIds.PublishSubscribe))
            await self._init_node(self._node, self._server)
        node: Node = self._node
        datasets_node = await node.get_child("0:PublishedDataSets")
        self._datasets_node = datasets_node
        for pds in self._pds:
            if not pds.model_is_init():
                await pds._init_information_model(datasets_node, self._server)
        for con in self._con:
            if not con.model_is_init():
                await con._init_information_model(self._server)

    def get_config(self) -> PubSubConfigurationDataType:
        """
        Returns the PubSub Configuration.
        """
        return PubSubConfigurationDataType(
            [pds.get_config() for pds in self._pds],
            [c.get_config() for c in self._con],
            self._enabled,
        )

    async def add_published_dataset(self, pds: PublishedDataSet) -> None:
        self._pds.append(pds)
        if self._node is not None and self._datasets_node is not None:
            await pds._init_information_model(self._datasets_node, self._server)

    async def add_connection(self, con: PubSubConnection) -> None:
        self._register(con)
        self._con.append(con)
        if self._node is not None:
            await con._init_information_model(self._server)

    def get_connection(self, name: String) -> PubSubConnection | None:
        return next((c for c in self._con if c._cfg.Name == name), None)

    def get_published_dataset(self, name: String) -> PublishedDataSet | None:
        return next((pds for pds in self._pds if pds.get_name() == name), None)

    async def remove_published_dataset(self, name: String) -> None:
        elm = self.get_published_dataset(name)
        if elm is None:
            raise ValueError(f"Unknown Published Dataset {name}")
        if elm._node is not None:
            await elm._node.delete(recursive=True)
        self._pds.remove(elm)

    async def remove_connection(self, name: String) -> None:
        elm = self.get_connection(name)
        if elm is None:
            raise ValueError(f"Unknown Connection {name}")
        await elm.stop()
        if elm._node is not None:
            await elm._node.delete(recursive=True)
        self._con.remove(elm)

    def _connections_by_priority(self) -> list[PubSubConnection]:
        def highest(con: PubSubConnection) -> int:
            return max((int(g._cfg.Priority or 0) for g in con._writer_groups), default=0)

        return sorted(self._con, key=highest, reverse=True)

    async def start(self) -> None:
        """
        Starts the pubsub applications. All writer and reader will publish and subscribe message from now on.
        If a connection can't start, everything that was started is stopped again and the first error is raised.
        """
        if self._running:
            return
        try:
            async with asyncio.TaskGroup() as group:
                for con in self._connections_by_priority():
                    group.create_task(con.start())
        except BaseExceptionGroup as errors:
            await self._stop_connections()
            await self._set_state(PubSubState.Error)
            raise errors.exceptions[0] from None
        self._enabled = True
        self._running = True
        await self._set_state(PubSubState.Operational)

    async def _stop_connections(self) -> None:
        results = await asyncio.gather(*[c.stop() for c in self._con], return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.warning("A connection failed to stop: %r", result)

    async def stop(self) -> None:
        """
        Stops the pubsub application.
        """
        if self._running:
            self._enabled = False
            await self._stop_connections()
            await self._set_state(PubSubState.Disabled)
            self._running = False

    async def __aenter__(self) -> PubSub:
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def load_binary_file(self, file: str | Path) -> None:
        """Replaces the configuration with the one in the file; if the file can't be used, nothing changes"""
        async with await anyio.open_file(file, mode="rb") as f:
            buf = Buffer(await f.read())
        try:
            ex_obj = extensionobject_from_binary(buf)
        except UaError as e:
            logger.error("Can't read %s as a PubSub configuration file: %s", file, e)
            raise UaStatusCodeError(StatusCodes.BadInvalidArgument) from e
        body = ex_obj.Body.Value if isinstance(ex_obj, UABinaryFileDataType) and ex_obj.Body is not None else None
        if not isinstance(body, PubSubConfigurationDataType):
            logger.error("File has ExtensionObject of type: %s instead of a PubSub configuration", ex_obj)
            raise UaStatusCodeError(StatusCodes.BadInvalidArgument)
        cfg: PubSubConfigurationDataType = body
        datasets = [self._new_published_dataset(ds) for ds in cfg.PublishedDataSets]
        connections = [PubSubConnection(con) for con in cfg.Connections]
        for old_con in list(self._con):
            await self.remove_connection(old_con._cfg.Name)
        for old_pds in list(self._pds):
            await self.remove_published_dataset(old_pds.get_name())
        self._enabled = cfg.Enabled
        for pds in datasets:
            await self.add_published_dataset(pds)
        for con in connections:
            await self.add_connection(con)

    async def save_binary_file(self, file: str | Path) -> None:  # @TODO save structs and enums, namespaces
        cfg = PubSubConfigurationDataType(
            [pds._data for pds in self._pds], [con._cfg for con in self._con], self._enabled
        )
        data = extensionobject_to_binary(UABinaryFileDataType(Body=Variant(cfg)))
        async with await anyio.open_file(file, mode="wb") as f:
            await f.write(data)

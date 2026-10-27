from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.node import Node
from enginir_opcua.server.history import HistoryDict, HistoryStorageInterface
from enginir_opcua.server.history_sql import HistorySQLite
from enginir_opcua.server.user_managers import PermissiveUserManager

from .access_rig import free_port

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


@dataclass
class HistoryRig:
    server: Server
    admin: Client
    user: Client
    storage: HistoryStorageInterface
    kind: str
    ns: int

    async def history_variable(self, name: str, values: list[tuple[float, Any]], **kwargs: Any) -> Node:
        node = await self.server.nodes.objects.add_variable(ua.NodeId(name, self.ns), f"{self.ns}:{name}", 0)
        await self.server.historize_node_data_change(node, period=kwargs.pop("period", None), **kwargs)
        for seconds, value in values:
            await self.save(node, seconds, value)
        return node

    async def save(self, node: Node, seconds: float | None, value: Any, **kwargs: Any) -> None:
        stamp = at(seconds) if seconds is not None else None
        dv = ua.DataValue(ua.Variant(value), SourceTimestamp=stamp, ServerTimestamp=stamp, **kwargs)
        await self.storage.save_node_value(node.nodeid, dv)

    async def read(
        self,
        node: Node,
        start: float | None,
        end: float | None,
        count: int = 0,
        *,
        bounds: bool = False,
        client: Client | None = None,
        timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both,
        token: bytes | None = None,
        index_range: str | None = None,
    ) -> ua.HistoryReadResult:
        details = ua.ReadRawModifiedDetails(
            IsReadModified=False,
            StartTime=at(start) if start is not None else ua.get_win_epoch(),
            EndTime=at(end) if end is not None else ua.get_win_epoch(),
            NumValuesPerNode=count,
            ReturnBounds=bounds,
        )
        return (await self.request(details, node, client, timestamps, token, index_range))[0]

    async def request(
        self,
        details: Any,
        node: Node | ua.NodeId,
        client: Client | None = None,
        timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both,
        token: bytes | None = None,
        index_range: str | None = None,
        release: bool = False,
    ) -> list[ua.HistoryReadResult]:
        nodeid = node.nodeid if isinstance(node, Node) else node
        item = ua.HistoryReadValueId(NodeId=nodeid, IndexRange=index_range, ContinuationPoint=token)
        params = ua.HistoryReadParameters(
            HistoryReadDetails=details,
            TimestampsToReturn=timestamps,
            ReleaseContinuationPoints=release,
            NodesToRead=[item],
        )
        return await (client or self.user).uaclient.history_read(params)


def numbers(result: ua.HistoryReadResult) -> list[Any]:
    return [dv.Value.Value if dv.Value is not None else None for dv in result.HistoryData.DataValues]


@pytest.fixture(params=["dict", "sqlite"], name="history_rig")
async def make_history_rig(request: pytest.FixtureRequest) -> AsyncIterator[HistoryRig]:
    port = free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    storage: HistoryStorageInterface = HistoryDict() if request.param == "dict" else HistorySQLite(":memory:")
    server.iserver.history_manager.set_storage(storage)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    ns = await server.register_namespace("http://test.example/history")
    await server.start()
    admin = Client(f"opc.tcp://admin@127.0.0.1:{port}", timeout=10)
    user = Client(f"opc.tcp://someone@127.0.0.1:{port}", timeout=10)
    await admin.connect()
    await user.connect()
    yield HistoryRig(server, admin, user, storage, request.param, ns)
    await user.disconnect()
    await admin.disconnect()
    await server.stop()

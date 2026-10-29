from collections.abc import AsyncIterator
from itertools import count

import pytest

from enginir_opcua import Client, Server
from enginir_opcua.server.history import HistoryDict, HistoryStorageInterface
from enginir_opcua.server.history_sql import HistorySQLite
from enginir_opcua.server.user_managers import PermissiveUserManager
from tests.access_rig import free_port
from tests.history_rig import HistoryRig

_namespace_numbers = count(1)


@pytest.fixture(scope="module", params=["dict", "sqlite"], name="history_cluster")
async def make_history_cluster(request: pytest.FixtureRequest) -> AsyncIterator[HistoryRig]:
    port = free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    storage: HistoryStorageInterface = HistoryDict() if request.param == "dict" else HistorySQLite(":memory:")
    server.iserver.history_manager.set_storage(storage)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await server.start()
    admin = Client(f"opc.tcp://admin@127.0.0.1:{port}", timeout=10)
    user = Client(f"opc.tcp://someone@127.0.0.1:{port}", timeout=10)
    await admin.connect()
    await user.connect()
    yield HistoryRig(server, admin, user, storage, request.param, 0)
    await user.disconnect()
    await admin.disconnect()
    await server.stop()


@pytest.fixture(name="history_rig")
async def make_history_rig(history_cluster: HistoryRig) -> AsyncIterator[HistoryRig]:
    server = history_cluster.server
    limits = (server.iserver.max_history_continuation_points, server.iserver.max_history_data_response_size)
    ns = await server.register_namespace(f"http://test.example/history/{next(_namespace_numbers)}")
    yield HistoryRig(
        server, history_cluster.admin, history_cluster.user, history_cluster.storage, history_cluster.kind, ns
    )
    server.iserver.max_history_continuation_points, server.iserver.max_history_data_response_size = limits

import asyncio
import operator
import socket
import subprocess
from asyncio import get_event_loop_policy, sleep
from collections import namedtuple
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from multiprocessing import Condition, Event, Process
from pathlib import Path
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ha.ha_client import HaClient, HaConfig, HaMode
from enginir_opcua.client.ua_client import UASocketState
from enginir_opcua.server.history import HistoryDict, TimeDomain
from enginir_opcua.server.history_sql import HistorySQLite
from enginir_opcua.server.uaprocessor import UaProcessor
from enginir_opcua.server.user_managers import PermissiveUserManager
from tests.harness import (
    PKI,
    TWO_SESSION_USERS,
    RawPeer,
    RawServer,
    ResponseTampering,
    TwoSessions,
    TwoUserManager,
    start_discovery_server,
)
from tests.model.methods_rig import add_server_methods
from tests.util_enum_struct import add_server_custom_enum_struct
from tests.waiting import wait_until

RETRY = 20
SLEEP = 0.4
PORTS_USED = set()
Opc = namedtuple("Opc", ["opc", "server"])


@pytest.fixture
def restore_ua_registry() -> Iterator[None]:
    saved_registry = ua.default_types.snapshot()
    ua_attributes = dict(vars(ua))
    yield
    ua.default_types.restore(saved_registry)
    for name in set(vars(ua)) - set(ua_attributes):
        delattr(ua, name)
    for name, value in ua_attributes.items():
        if vars(ua).get(name) is not value:
            setattr(ua, name, value)


def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = s.getsockname()[1]
        if port not in PORTS_USED:
            PORTS_USED.add(port)
            return port
        return find_free_port()


port_num = find_free_port()
port_num1 = find_free_port()
port_discovery = find_free_port()


def pytest_addoption(parser):
    parser.addoption(
        "--changed-since",
        metavar="REF",
        default=None,
        help="deselect tests marked slow unless git diff REF touches their source paths, their test file or conftest.py",
    )


def _changed_files(rootpath: Path, ref: str) -> set[str]:
    def git(*args: str) -> list[str]:
        result = subprocess.run(["git", *args], cwd=rootpath, capture_output=True, text=True)
        if result.returncode != 0:
            raise pytest.UsageError(f"--changed-since {ref}: {result.stderr.strip()}")
        return result.stdout.split()

    return set(git("diff", "--name-only", ref)) | set(git("ls-files", "--others", "--exclude-standard"))


def _touches(changed: set[str], paths: list[str]) -> bool:
    prefixes = [path.rstrip("/") for path in paths]
    return any(file == prefix or file.startswith(f"{prefix}/") for file in changed for prefix in prefixes)


def pytest_collection_modifyitems(config, items):
    ref = config.getoption("--changed-since")
    if ref is None:
        return
    changed = _changed_files(config.rootpath, ref)
    if _touches(changed, ["tests/conftest.py"]):
        return
    selected, deselected = [], []
    for item in items:
        mark = item.get_closest_marker("slow")
        paths = [*mark.args, item.path.relative_to(config.rootpath).as_posix()] if mark else []
        if mark is None or _touches(changed, paths):
            selected.append(item)
        else:
            deselected.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected


def pytest_generate_tests(metafunc):
    mark = metafunc.definition.get_closest_marker("parametrize")
    # override the opc parameters when explicilty provided
    if getattr(mark, "args", None) and "opc" in mark.args:
        pass
    elif "opc" in metafunc.fixturenames:
        metafunc.parametrize("opc", ["client", "server"], indirect=True)
    elif "history" in metafunc.fixturenames:
        metafunc.parametrize("history", ["dict", "sqlite"], indirect=True)
    elif "history_server" in metafunc.fixturenames:
        metafunc.parametrize("history_server", ["dict", "sqlite"], indirect=True)


@pytest.fixture(scope="module")
def event_loop(request):
    """Create an instance of the default event loop for each test case."""
    loop = get_event_loop_policy().new_event_loop()
    loop.set_debug(True)
    yield loop
    loop.close()


class ServerProcess(Process):
    def __init__(self):
        super().__init__()
        self.url = f"opc.tcp://127.0.0.1:{port_num}"
        self.cond = Condition()
        self.stop_ev = Event()

    async def run_server(self, url):
        srv = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
        srv.allow_plaintext_password = True
        srv.set_endpoint(url)
        await srv.init()
        namespace = await srv.register_namespace("http://test.example/tools")
        await add_server_methods(srv)
        await add_server_custom_enum_struct(srv)
        tools_node = await srv.nodes.objects.add_variable(
            ua.NodeId("ToolsReadWrite", namespace), f"{namespace}:ToolsReadWrite", "", ua.VariantType.String
        )
        await tools_node.set_writable()
        async with srv:
            await srv.historize_node_data_change(tools_node, period=None)
            with self.cond:
                self.cond.notify_all()
            while not self.stop_ev.is_set():
                await asyncio.sleep(1)
        await srv.stop()

    def stop(self):
        self.stop_ev.set()

    async def wait_for_start(self):
        with ThreadPoolExecutor() as pool:
            await asyncio.get_running_loop().run_in_executor(pool, self.wait_for_start_sync)

    def wait_for_start_sync(self):
        with self.cond:
            self.cond.wait()

    def run(self):
        loop = asyncio.new_event_loop()
        loop.run_until_complete(self.run_server(self.url))


@pytest.fixture(scope="module")
async def running_server(request):
    """
    Spawn a server in a separate process
    which can handle OPCUA requests
    """
    process = ServerProcess()
    process.start()
    await process.wait_for_start()
    yield process.url
    process.stop()
    process.join()


@pytest.fixture(scope="module")
async def server():
    # start our own server
    srv = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port_num}")
    await add_server_methods(srv)
    await add_server_custom_enum_struct(srv)
    await srv.start()
    yield srv
    # stop the server
    await srv.stop()


@pytest.fixture(scope="module")
async def discovery_server():
    srv = await start_discovery_server(port_discovery)
    yield srv
    await srv.stop()


@pytest.fixture(scope="module")
async def admin_client():
    # start admin client
    # long timeout since travis (automated testing) can be really slow
    clt = Client(f"opc.tcp://admin@127.0.0.1:{port_num}", timeout=10)
    await clt.connect()
    yield clt
    await clt.disconnect()


@pytest.fixture(scope="module")
async def client():
    # start anonymous client
    ro_clt = Client(f"opc.tcp://127.0.0.1:{port_num}")
    await ro_clt.connect()
    yield ro_clt
    await ro_clt.disconnect()


def declare_new_variables_writable(client: Client) -> None:
    """The variables a test client adds are declared writable, because the server refuses writes to read-only ones."""
    session = client.uaclient.session
    add_nodes = session.add_nodes
    writable = ua.AccessLevel.CurrentRead.mask | ua.AccessLevel.CurrentWrite.mask

    async def add_writable_variables(items: list[ua.AddNodesItem]) -> list[ua.AddNodesResult]:
        for item in items:
            if item.NodeClass == ua.NodeClass.Variable:
                item.NodeAttributes.AccessLevel = writable
                item.NodeAttributes.UserAccessLevel = writable
        return await add_nodes(items)

    session.add_nodes = add_writable_variables  # type: ignore[method-assign]


@pytest.fixture(scope="module")
async def opc(request):
    """
    Fixture for tests that should run for both `Server` and `Client`
    :param request:
    :return:
    """
    if request.param == "client":
        srv = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
        srv.allow_plaintext_password = True
        await srv.init()
        srv.set_endpoint(f"opc.tcp://127.0.0.1:{port_num}")
        await add_server_methods(srv)
        await srv.get_node(ua.NodeId(ua.ObjectIds.Server_NamespaceArray)).set_writable()
        await srv.start()
        # start client
        # long timeout since travis (automated testing) can be really slow
        clt = Client(f"opc.tcp://admin@127.0.0.1:{port_num}", timeout=10)
        await clt.connect()
        declare_new_variables_writable(clt)
        yield Opc(clt, srv)
        await clt.disconnect()
        await srv.stop()
    elif request.param == "server":
        # start our own server
        srv = Server(allow_no_security=True)
        await srv.init()
        srv.set_endpoint(f"opc.tcp://127.0.0.1:{port_num1}")
        await add_server_methods(srv)
        await srv.start()
        yield Opc(srv, srv)
        # stop the server
        await srv.stop()
    else:
        raise ValueError("invalid internal test config")


@pytest.fixture()
async def history(request):
    if request.param == "dict":
        h = HistoryDict()
        await h.init()
        yield h
        await h.stop()
    elif request.param == "sqlite":
        h = HistorySQLite(":memory:")
        await h.init()
        yield h
        await h.stop()


class HistoryServer:
    def __init__(self):
        self.srv = Server(allow_no_security=True)
        self.srv_node = None
        self.ev_values = None
        self.var = None
        self.values = None


async def _stored_values(history_server: HistoryServer, expected: int) -> bool:
    storage = history_server.srv.iserver.history_manager.storage
    page = await storage.read_node_history(history_server.var.nodeid, TimeDomain(None, None, expected + 1))
    return len(page.entries) >= expected


async def create_srv_events(history_server: HistoryServer):
    history_server.ev_values = [i for i in range(20)]
    srv_evgen = await history_server.srv.get_event_generator()
    history_server.srv_node = history_server.srv.get_node(ua.ObjectIds.Server)
    await history_server.srv.historize_node_event(history_server.srv_node, period=None)
    for i in history_server.ev_values:
        srv_evgen.event.Severity = history_server.ev_values[i]
        await srv_evgen.trigger(message="test message")
    await history_server.srv.iserver.history_manager._queue.join()


async def create_var(history_server: HistoryServer):
    o = history_server.srv.nodes.objects
    history_server.values = [i for i in range(21)]
    history_server.var = await o.add_variable(3, "history_var", 0)
    await history_server.srv.historize_node_data_change(history_server.var, period=None, count=0)
    for i in history_server.values[1:]:
        await history_server.var.write_value(i)
    await wait_until(lambda: _stored_values(history_server, len(history_server.values)))


async def create_history_server(sqlite=False) -> HistoryServer:
    history_server = HistoryServer()
    await history_server.srv.init()
    history_server.srv.set_endpoint(f"opc.tcp://127.0.0.1:{port_num if not sqlite else port_num1}")
    await history_server.srv.start()
    if sqlite:
        history = HistorySQLite(":memory:")
        await history.init()
        history_server.srv.iserver.history_manager.set_storage(history)
    await create_var(history_server)
    await create_srv_events(history_server)
    return history_server


@pytest.fixture(scope="module")
async def history_server(request):
    if request.param == "dict":
        srv = await create_history_server()
        yield srv
        await srv.srv.stop()
    elif request.param == "sqlite":
        srv = await create_history_server(sqlite=True)
        yield srv
        await srv.srv.stop()


@pytest.fixture(scope="session")
def client_key_and_cert(request):
    return PKI.peer1.key, PKI.peer1.certificate


@pytest.fixture(scope="session")
def server_key_and_cert(request):
    return PKI.server.key, PKI.server.certificate


@pytest.fixture(scope="function")
def ha_config():
    """
    Factory method to return a HaConfig
    """

    def _ha_config(srv_port1, srv_port2, ha_mode=HaMode.WARM):
        return HaConfig(
            ha_mode,
            keepalive_timer=1,
            manager_timer=1,
            reconciliator_timer=1,
            urls=[
                f"opc.tcp://127.0.0.1:{srv_port1}",
                f"opc.tcp://127.0.0.1:{srv_port2}",
            ],
            session_timeout=30,
        )

    return _ha_config


@pytest.fixture(scope="module")
async def ha_servers(server_key_and_cert):
    # start our own server
    srvs = []
    key, cert = server_key_and_cert

    async def create_srv(port, key, cert):
        srv = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
        srvs.append(srv)
        await srv.init()
        await srv.set_application_uri("urn:enginir:opcua:server")
        srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
        srv.set_security_policy(
            [
                ua.SecurityPolicyType.NoSecurity,
                ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ]
        )
        await srv.load_certificate(cert)
        await srv.load_private_key(key)
        srv.set_trust_store(PKI.trust_store())
        await srv.start()
        # default the service level to 255 once started
        slevel = srv.get_node(ua.NodeId(ua.ObjectIds.Server_ServiceLevel))
        await slevel.write_value(ua.Variant(255, ua.VariantType.Byte))
        redundancy = srv.get_node(ua.NodeId(ua.ObjectIds.Server_ServerRedundancy_RedundancySupport))
        await redundancy.write_value(ua.Variant(ua.RedundancySupport.Warm, ua.VariantType.Int32))
        return srv

    port_1 = find_free_port()
    port_2 = find_free_port()
    srv1 = await create_srv(port_1, key, cert)
    srv2 = await create_srv(port_2, key, cert)
    yield srv1, srv2
    # stop the servers
    for srv in srvs:
        await srv.stop()
    PORTS_USED.remove(port_1)
    PORTS_USED.remove(port_2)


@pytest.fixture(scope="module")
async def srv_variables(ha_servers):
    """
    This fixture returns client like ha_client
    server within the module scope.
    """
    clts = []
    # add the variables to the client
    node_to_var = {}
    for srv in ha_servers:
        for var in ("V1", "V2"):
            url = f"{srv.endpoint.scheme}://admin@{srv.endpoint.netloc}"
            c = Client(url, timeout=10)
            clts.append(c)
            await c.connect()
            values = [1, 2, 3]
            o = c.nodes.objects
            node = await o.add_variable(3, f"SubscriptionVariable{var}", values)
            node_to_var[node] = values
    yield node_to_var
    # disconnect admin@clients used to write the custom variables
    for c in clts:
        await c.disconnect()


@pytest.fixture(scope="function")
async def ha_client(ha_config, ha_servers):
    """
    This fixture returns everytime a new
    HaClient but configured with the same
    server within the module scope.
    """
    srv1, srv2 = ha_servers
    srv1_port = srv1.endpoint.port
    srv2_port = srv2.endpoint.port

    ha_config = ha_config(srv1_port, srv2_port)
    ha_client = HaClient(ha_config)
    yield ha_client
    if ha_client.is_running:
        await ha_client.stop()


async def wait_clients_socket(ha_client, state):
    for client in ha_client.get_clients():
        for _ in range(RETRY):
            if state == UASocketState.CLOSED and not client.uaclient.protocol:
                break
            if client.uaclient.protocol and client.uaclient.protocol.state == state:
                # for connection OPEN, also wait for the session to be established
                # otherwise we can encounter failure on disconnect
                if state == UASocketState.OPEN:
                    if client._renew_channel_task:
                        break
                else:
                    break
            await sleep(SLEEP)
        assert (
            not client.uaclient.protocol and state == UASocketState.CLOSED
        ) or client.uaclient.protocol.state == state


async def wait_sub_in_real_map(ha_client, sub, negation=False):
    reconciliator = ha_client.reconciliator
    oper = operator.not_ if negation else operator.truth
    for client in ha_client.get_clients():
        url = client.server_url.geturl()
        for _ in range(RETRY):
            if oper(reconciliator.real_map.get(url) and reconciliator.real_map[url].get(sub)):
                break
            await sleep(SLEEP)
        assert oper(reconciliator.real_map[url].get(sub))


async def wait_node_in_real_map(ha_client, sub, node_str, negation=False):
    oper = operator.not_ if negation else operator.truth
    reconciliator = ha_client.reconciliator
    for client in ha_client.get_clients():
        url = client.server_url.geturl()
        vs = None
        for _ in range(RETRY):
            # virtual subscription must already exist,
            if reconciliator.real_map.get(url):
                vs = reconciliator.real_map[url][sub]
                if oper(node_str in vs.nodes):
                    break
            await sleep(SLEEP)
        assert oper(node_str in vs.nodes)


async def wait_mode_in_real_map(ha_client, client, sub, mode, value):
    reconciliator = ha_client.reconciliator
    await wait_sub_in_real_map(ha_client, sub)
    url = client.server_url.geturl()
    vsub = reconciliator.real_map[url][sub]
    option = None
    for _ in range(RETRY):
        option = getattr(vsub, mode)
        if option == value:
            break
        await sleep(SLEEP)
    assert option == value


async def wait_for_status_change(ha_client, client, status):
    # wait for the KeepAlive task to update its client status
    srv_info = ha_client.clients[client]
    for _ in range(RETRY):
        if srv_info.status == status:
            break
        await sleep(SLEEP)
    assert srv_info.status == status


@pytest.fixture
async def raw_peer(server: Server) -> AsyncIterator[RawPeer]:
    peer = await RawPeer.connect(server.endpoint.hostname, server.endpoint.port)
    yield peer
    await peer.close()


@pytest.fixture
async def raw_server() -> AsyncIterator[RawServer]:
    raw = await RawServer.start()
    yield raw
    await raw.close()


@pytest.fixture
def tampered_responses(monkeypatch: pytest.MonkeyPatch) -> ResponseTampering:
    tampering = ResponseTampering()
    send_response = UaProcessor.send_response

    def send_tampered_response(
        processor: UaProcessor,
        requesthandle: Any,
        seqhdr: Any,
        response: Any,
        msgtype: bytes = ua.MessageType.SecureMessage,
    ) -> None:
        tampering.apply(response)
        send_response(processor, requesthandle, seqhdr, response, msgtype)

    monkeypatch.setattr(UaProcessor, "send_response", send_tampered_response)
    return tampering


@pytest.fixture(scope="module", name="_two_user_server")
async def start_two_user_server() -> AsyncIterator[tuple[Server, int]]:
    port = find_free_port()
    srv = Server(allow_no_security=True, user_manager=TwoUserManager())
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await srv.start()
    yield srv, port
    await srv.stop()


@pytest.fixture
async def two_sessions(_two_user_server: tuple[Server, int]) -> AsyncIterator[TwoSessions]:
    srv, port = _two_user_server
    alice = Client(f"opc.tcp://alice:{TWO_SESSION_USERS['alice']}@127.0.0.1:{port}")
    bob = Client(f"opc.tcp://bob:{TWO_SESSION_USERS['bob']}@127.0.0.1:{port}")
    await alice.connect()
    await bob.connect()
    yield TwoSessions(server=srv, alice=alice, bob=bob)
    await bob.disconnect()
    await alice.disconnect()
    srv.iserver.identity_guard.records.clear()


async def _start_signing_server() -> Server:
    srv = Server(allow_no_security=True, user_manager=TwoUserManager())
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_Sign])
    srv.set_identity_tokens([ua.UserNameIdentityToken])
    await srv.load_certificate(PKI.server.certificate)
    await srv.load_private_key(PKI.server.key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    return srv


@pytest.fixture
async def signing_server() -> AsyncIterator[Server]:
    srv = await _start_signing_server()
    yield srv
    await srv.stop()


@pytest.fixture(scope="module", name="_signing_server_for_module")
async def start_signing_server_for_module() -> AsyncIterator[Server]:
    srv = await _start_signing_server()
    yield srv
    await srv.stop()


@pytest.fixture
async def shared_signing_server(_signing_server_for_module: Server) -> AsyncIterator[Server]:
    guard = _signing_server_for_module.iserver.identity_guard
    original_sleep = guard.sleep
    yield _signing_server_for_module
    guard.sleep = original_sleep
    guard.records.clear()

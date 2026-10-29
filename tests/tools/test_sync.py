import asyncio
import gc
import inspect
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import warnings
from concurrent.futures import Future
from pathlib import Path

import pytest

from enginir_opcua import sync, ua, uamethod
from enginir_opcua.client import Client as AsyncClient
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.common.node import Node as AsyncNode
from enginir_opcua.common.subscription import Subscription as AsyncSubscription
from enginir_opcua.server import Server as AsyncServer
from enginir_opcua.server.user_managers import PermissiveUserManager
from enginir_opcua.sync import (
    Client,
    Server,
    SyncNode,
    ThreadLoop,
    ThreadLoopNotRunning,
    XmlExporter,
    call_method_full,
    new_enum,
    new_struct,
    new_struct_field,
    sync_async_client_method,
    sync_uaclient_method,
)
from tests.conftest import find_free_port

port_num = find_free_port()


@uamethod
def divide(parent, x, y):
    return x / y


@pytest.fixture(scope="module")
def tloop():
    with ThreadLoop() as tl:
        tl.loop.set_debug(True)
        yield tl


@pytest.fixture(scope="module")
def server(tloop):
    s = Server(allow_no_security=True, user_manager=PermissiveUserManager(), tloop=tloop)
    s.aio_obj.allow_plaintext_password = True
    s.disable_clock(True)
    s.set_endpoint(f"opc.tcp://0.0.0.0:{port_num}/enginir-opcua/server/")
    uri = "http://examples.freeopcua.github.io"
    ns_idx = s.register_namespace(uri)
    myobj = s.nodes.objects.add_object(ns_idx, "MyObject")
    myobj.add_variable(ns_idx, "MyVariable", 6.7)
    myobj.add_variable(ns_idx, "MySin", 0, ua.VariantType.Float)
    s.nodes.objects.add_method(
        ns_idx, "Divide", divide, [ua.VariantType.Float, ua.VariantType.Float], [ua.VariantType.Float]
    )
    s.get_node(ua.NodeId(ua.ObjectIds.Server_NamespaceArray)).set_writable()
    with s:
        yield s


@pytest.fixture
def client(tloop, server):
    c = Client(f"opc.tcp://admin@localhost:{port_num}/freeopcua/server", tloop=tloop)
    with c:
        yield c


@pytest.fixture
def client_no_tloop(server):
    with Client(f"opc.tcp://admin@localhost:{port_num}/freeopcua/server") as c:
        yield c


@pytest.fixture
def idx(client):
    uri = "http://examples.freeopcua.github.io"
    i = client.get_namespace_index(uri)
    return i


def test_sync_client(client, idx):
    client.load_type_definitions()
    myvar = client.nodes.root.get_child(["0:Objects", f"{idx}:MyObject", f"{idx}:MyVariable"])
    assert myvar.read_value() == 6.7


def test_sync_client_set_max_concurrent_requests(client):
    client.set_max_concurrent_requests(3)
    assert client.aio_obj.uaclient._max_concurrent_requests == 3


def test_sync_server_set_application_uri(tloop):
    """Sync Server must expose set_application_uri / get_application_uri (GH-1967)."""
    s = Server(allow_no_security=True, tloop=tloop)
    s.disable_clock(True)
    new_uri = "urn:enginir:opcua:server:sync_test_app_uri"
    s.set_application_uri(new_uri)
    assert s.get_application_uri() == new_uri
    # Namespace index 1 holds the application URI.
    namespaces = s.get_namespace_array()
    assert namespaces[1] == new_uri
    s.stop()


def test_sync_uaclient_method(client, idx):
    client.load_type_definitions()
    myvar = client.nodes.root.get_child(["0:Objects", f"{idx}:MyObject", f"{idx}:MyVariable"])
    read_attributes = sync_uaclient_method(UaClient.read_attributes)(client)
    results = read_attributes([myvar.nodeid], attr=ua.AttributeIds.Value)
    assert len(results) == 1
    assert results[0].Value.Value == 6.7


def test_sync_async_client_method(client, idx):
    client.load_type_definitions()
    myvar = client.nodes.root.get_child(["0:Objects", f"{idx}:MyObject", f"{idx}:MyVariable"])
    read_attributes = sync_async_client_method(AsyncClient.read_attributes)(client)
    results = read_attributes([myvar], attr=ua.AttributeIds.Value)
    assert len(results) == 1
    assert results[0].Value.Value == 6.7


def test_sync_delete_nodes(client):
    obj = client.nodes.objects
    var = obj.add_variable(2, "VarToDelete", 9.1)
    childs = obj.get_children()
    assert var in childs
    nodes, statuses = client.delete_nodes([var])
    assert len(nodes) == len(statuses) == 1
    assert isinstance(nodes[0], SyncNode)
    assert nodes[0] == var
    assert statuses[0].is_good()


async def test_sync_import_xml(client):
    nodes = client.import_xml("tests/model/custom_struct.xml")
    assert all([isinstance(node, ua.NodeId) for node in nodes])


def test_sync_read_attributes(client: Client, idx):
    client.load_type_definitions()
    myvar = client.nodes.root.get_child(["0:Objects", f"{idx}:MyObject", f"{idx}:MyVariable"])
    assert isinstance(myvar, SyncNode)
    results = client.read_attributes([myvar], attr=ua.AttributeIds.Value)
    assert len(results) == 1
    assert results[0].Value.Value == 6.7


def test_sync_read_values(client: Client, idx):
    client.load_type_definitions()
    myvar = client.nodes.root.get_child(["0:Objects", f"{idx}:MyObject", f"{idx}:MyVariable"])
    assert isinstance(myvar, SyncNode)
    results = client.read_values([myvar])
    assert len(results) == 1
    assert results[0] == 6.7


def test_sync_write_values(client: Client, server: Server):
    myvar = client.nodes.objects.add_variable(3, "a", 1)
    server.get_node(myvar.nodeid).set_writable()
    assert isinstance(myvar, SyncNode)
    rets = client.write_values([myvar], [4])
    assert rets == [ua.StatusCode(value=ua.StatusCodes.Good)]
    assert myvar.read_value() == 4


def test_sync_client_browse_nodes(client: Client, idx):
    nodes = [
        client.get_node("ns=0;i=2267"),
        client.get_node("ns=0;i=2259"),
    ]
    results = client.browse_nodes(nodes)
    assert len(results) == 2
    assert isinstance(results, list)
    assert results[0][0] == nodes[0]
    assert results[1][0] == nodes[1]
    assert isinstance(results[0][0], SyncNode)
    assert isinstance(results[1][0], SyncNode)
    assert isinstance(results[0][1], ua.BrowseResult)
    assert isinstance(results[1][1], ua.BrowseResult)


def test_sync_get_node(side, idx):
    _, node_source = side
    node = node_source.get_node(85)
    assert node == node_source.nodes.objects
    nodes = node.get_children()
    assert len(nodes) > 2
    assert node_source.nodes.server in nodes
    assert isinstance(nodes[0], SyncNode)

    results = node.get_children_by_path([[f"{idx}:MyObject", f"{idx}:MyVariable"]])
    assert len(results) == 1
    vars = results[0]
    assert len(vars) == 1
    assert vars[0].read_value() == 6.7


@pytest.mark.slow("enginir_opcua/sync.py", "enginir_opcua/server/internal_server.py")
async def test_sync_server_creating_shelf_files_works(tloop: ThreadLoop, tmp_path: Path) -> None:
    shelf_file_path: Path = tmp_path / "shelf_file"

    Server(allow_no_security=True, tloop=tloop, shelf_file=shelf_file_path)


class MySubHandler:
    def __init__(self):
        self.future = Future()

    def reset(self):
        self.future = Future()

    def datachange_notification(self, node, val, data):
        self.future.set_result((node, val))

    def event_notification(self, event):
        self.future.set_result(event)


def test_sync_tloop_sub(client_no_tloop, server):
    test_sync_sub(client_no_tloop, server)


def test_sync_sub(client, server):
    myhandler = MySubHandler()
    sub = client.create_subscription(1, myhandler)
    var = client.nodes.objects.add_variable(3, f"SubVar{uuid.uuid4().hex}", 0.1)
    server.get_node(var.nodeid).set_writable()
    sub.subscribe_data_change(var)
    n, v = myhandler.future.result()
    assert v == 0.1
    assert n == var
    myhandler.reset()
    var.write_value(0.123)
    n, v = myhandler.future.result()
    assert v == 0.123
    sub.delete()


def test_sync_meth(client, idx):
    res = client.nodes.objects.call_method(
        f"{idx}:Divide", ua.Variant(4, ua.VariantType.Float), ua.Variant(2, ua.VariantType.Float)
    )
    assert res == 2
    with pytest.raises(ua.UaError):
        res = client.nodes.objects.call_method(
            f"{idx}:Divide", ua.Variant(4, ua.VariantType.Float), ua.Variant(0, ua.VariantType.Float)
        )


def test_sync_client_no_tl(client_no_tloop, idx):
    test_sync_meth(client_no_tloop, idx)


def test_sync_call_meth(client, idx):
    methodid = client.nodes.objects.get_child(f"{idx}:Divide")
    res = call_method_full(
        client.tloop,
        client.nodes.objects,
        methodid,
        ua.Variant(4, ua.VariantType.Float),
        ua.Variant(2, ua.VariantType.Float),
    )
    assert res.OutputArguments[0] == 2


def test_sync_xml_export(server):
    exp = XmlExporter(server)
    exp.build_etree([server.nodes.objects])
    with tempfile.TemporaryDirectory() as tmpdir:
        exp.write_xml(Path(tmpdir) / "toto_test_export.xml")


@pytest.fixture(params=["server", "client"])
def side(request, server, client):
    return request.param, server if request.param == "server" else client


def test_create_enum_sync(side):
    kind, node_source = side
    idx = 4
    name = f"MyCustEnum_{kind}"
    new_enum(node_source, idx, name, ["titi", "toto", "tutu"])

    node_source.load_data_type_definitions()

    var = node_source.nodes.objects.add_variable(idx, f"my_enum_{kind}", getattr(ua, name).toto)
    assert var.read_value() == 1


def test_create_struct_sync(side):
    kind, node_source = side
    idx = 4
    name = f"MyMyStruct_{kind}"
    new_struct(
        node_source,
        idx,
        name,
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32", ua.VariantType.UInt32, array=True),
        ],
    )

    node_source.load_data_type_definitions()
    mystruct = getattr(ua, name)()
    mystruct.MyUInt32 = [78, 79]
    var = node_source.nodes.objects.add_variable(idx, f"my_struct_{kind}", mystruct)
    assert var.read_value().MyUInt32 == [78, 79]


def alive_thread_loops():
    return {t for t in list(sync._running_loops) if t.is_alive()}


def test_sync_server_init_failure_stops_own_tloop(monkeypatch):
    async def failing_init(self, shelf_file=None):
        raise RuntimeError("init failed")

    monkeypatch.setattr(AsyncServer, "init", failing_init)
    before = alive_thread_loops()
    with pytest.raises(RuntimeError, match="init failed"):
        Server(allow_no_security=True)
    assert alive_thread_loops() == before


def test_sync_server_stop_failure_stops_own_tloop(monkeypatch):
    s = Server(allow_no_security=True)

    async def failing_stop():
        raise RuntimeError("stop failed")

    monkeypatch.setattr(s.aio_obj, "stop", failing_stop)
    with pytest.raises(RuntimeError, match="stop failed"):
        s.stop()
    assert not s.tloop.is_alive()


def test_sync_client_init_failure_stops_own_tloop(monkeypatch):
    def failing_init(self, *args, **kwargs):
        raise ValueError("bad url")

    monkeypatch.setattr(AsyncClient, "__init__", failing_init)
    before = alive_thread_loops()
    with pytest.raises(ValueError, match="bad url"):
        Client("opc.tcp://localhost:4840")
    assert alive_thread_loops() == before


def run_with_deadline(function, seconds: float = 5.0) -> None:
    errors: list[BaseException] = []

    def target() -> None:
        try:
            function()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "the call did not return"
    if errors:
        raise errors[0]


def test_syn5_a_forgotten_threadloop_does_not_block_exit():
    """A program that never stops its ThreadLoop still exits."""
    code = "from enginir_opcua.sync import ThreadLoop\nThreadLoop().start()\n"
    result = subprocess.run([sys.executable, "-c", code], timeout=10, capture_output=True)
    assert result.returncode == 0


def test_syn1_a_sync_call_on_the_loop_thread_raises_instead_of_deadlocking():
    """Part 4 has no say here; a blocking call made on the loop thread could only wait for itself."""
    with ThreadLoop(timeout=3) as tloop:

        async def inner() -> int:
            return 1

        async def outer() -> int:
            return tloop.post(inner())

        with pytest.raises(RuntimeError, match="loop thread"):
            tloop.post(outer())


def test_syn2_a_timed_out_call_is_cancelled_before_post_raises():
    """Part 4, 5.7.5: a call that was reported as timed out must not run on."""
    state = {"cancelled": False, "finished": False}

    async def slow() -> None:
        try:
            await asyncio.sleep(5)
            state["finished"] = True
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    with ThreadLoop(timeout=0.2) as tloop:
        with pytest.raises(TimeoutError, match=r"0\.2 s"):
            tloop.post(slow())
        assert state == {"cancelled": True, "finished": False}


def test_syn2_a_call_may_carry_its_own_timeout():
    async def quick() -> int:
        await asyncio.sleep(0.3)
        return 7

    with ThreadLoop(timeout=0.1) as tloop:
        assert tloop.post(quick(), timeout=2) == 7
        assert tloop.post(quick(), timeout=None) == 7


def test_syn4_start_raises_when_the_thread_fails(monkeypatch):
    def broken_loop():
        raise OSError("no loop for you")

    monkeypatch.setattr(asyncio, "new_event_loop", broken_loop)
    tloop = ThreadLoop()
    with pytest.raises(OSError, match="no loop for you"):
        run_with_deadline(tloop.start)


def test_syn4_stop_cancels_pending_tasks():
    state = {"cancelled": False}

    async def forever() -> None:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    tloop = ThreadLoop()
    tloop.start()
    asyncio.run_coroutine_threadsafe(forever(), tloop.loop)
    time.sleep(0.2)
    tloop.stop()
    assert state["cancelled"]


def test_syn6_stop_is_idempotent_and_the_loop_restarts():
    async def answer() -> int:
        return 42

    tloop = ThreadLoop()
    tloop.start()
    tloop.stop()
    tloop.stop()
    tloop.start()
    assert tloop.post(answer()) == 42
    tloop.stop()


def test_syn6_post_on_a_stopped_loop_leaves_no_unawaited_coroutine():
    async def answer() -> int:
        return 1

    tloop = ThreadLoop()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(ThreadLoopNotRunning):
            tloop.post(answer())
        gc.collect()
    assert not [w for w in caught if issubclass(w.category, RuntimeWarning)]


def test_syn1_stop_from_the_loop_thread_raises():
    with ThreadLoop() as tloop:

        async def stopper() -> None:
            tloop.stop()

        with pytest.raises(RuntimeError, match="loop thread"):
            tloop.post(stopper())


EXCLUDED = {
    "Client": {"subscribe_state", "listen_reverse", "use_reverse_listener"},
    "Server": {
        "init",
        "get_pubsub",
        "add_reverse_connect",
        "remove_reverse_connect",
        "diagnostics",
        "model_change",
        "model_change_events",
        "create_condition",
        "delete_condition",
        "get_condition",
        "conditions",
        "refresh_required",
    },
    "SyncNode": {"new_node"},
    "Subscription": {"init", "publish_callback", "enqueue", "session_event", "close", "restore"},
}


PAIRS = [
    ("Client", AsyncClient, sync.Client),
    ("Server", AsyncServer, sync.Server),
    ("SyncNode", AsyncNode, sync.SyncNode),
    ("Subscription", AsyncSubscription, sync.Subscription),
]


def public_members(cls: type) -> dict[str, object]:
    return {name: member for name, member in inspect.getmembers(cls) if not name.startswith("_")}


def describe(function: object) -> list[tuple[str, object, object]]:
    return [(p.name, p.kind, p.default) for p in inspect.signature(function).parameters.values()]  # type: ignore[arg-type]


@pytest.mark.parametrize(("name", "aio_class", "sync_class"), PAIRS)
def test_syn10_every_public_async_member_has_a_sync_twin(name, aio_class, sync_class):
    """The sync classes follow the async ones, apart from a short list of members that serve the internals."""
    missing = sorted(set(public_members(aio_class)) - set(public_members(sync_class)) - EXCLUDED[name])
    assert not missing


@pytest.mark.parametrize(("name", "aio_class", "sync_class"), PAIRS)
def test_syn8_sync_signatures_match_the_async_ones(name, aio_class, sync_class):
    drift = []
    sync_members = public_members(sync_class)
    for member_name, member in public_members(aio_class).items():
        twin = sync_members.get(member_name)
        if not inspect.isfunction(member) or not inspect.isfunction(twin) or member_name in EXCLUDED[name]:
            continue
        if describe(member) != describe(twin):
            drift.append(member_name)
    assert not drift


def test_syn10_configuration_attributes_are_forwarded():
    for attribute in ("application_uri", "name", "product_uri", "session_state_path", "max_messagesize", "state"):
        assert isinstance(getattr(sync.Client, attribute), property)


def test_syn9_wrapped_methods_keep_name_and_doc():
    assert sync.Client.connect_sessionless.__name__ == "connect_sessionless"
    assert sync.SyncNode.read_value.__name__ == "read_value"
    assert list(inspect.signature(sync.Client.set_security).parameters)[1] == "policy"

import threading
import time

import pytest

from enginir_opcua.client.ua_client import UaClientState
from enginir_opcua.observer import Observer
from enginir_opcua.server.user_managers import PermissiveUserManager
from enginir_opcua.sync import Client, Server, SyncNode, ThreadLoop, _to_async, _to_sync
from tests.conftest import find_free_port
from tests.waiting import until_sync

PORT = find_free_port()
URL = f"opc.tcp://admin@127.0.0.1:{PORT}/enginir-opcua/server/"


@pytest.fixture(scope="module")
def server():
    s = Server(allow_no_security=True, user_manager=PermissiveUserManager())
    s.aio_obj.allow_plaintext_password = True
    s.disable_clock(True)
    s.set_endpoint(f"opc.tcp://127.0.0.1:{PORT}/enginir-opcua/server/")
    idx = s.register_namespace("urn:enginir:test:sync")
    holder = s.nodes.objects.add_object(idx, "Holder")
    variable = holder.add_variable(idx, "Value", 1.0)
    variable.set_writable()
    with s:
        yield s, variable


@pytest.fixture
def variable(server):
    return server[1]


@pytest.fixture
def client(server):
    c = Client(URL, sync_wrapper_timeout=10)
    with c:
        yield c


class Recorder:
    def __init__(self) -> None:
        self.values: list[float] = []
        self.threads: list[int] = []
        self.done = threading.Event()
        self.read_back: list[object] = []

    def datachange_notification(self, node, val, data) -> None:
        self.threads.append(threading.get_ident())
        self.values.append(val)
        self.done.set()


def test_syn1_a_sync_handler_may_call_the_sync_api(client, variable):
    """A handler that reads a node does not wait for its own call."""

    class Reader(Recorder):
        def datachange_notification(self, node, val, data) -> None:
            self.read_back.append(node.read_value())
            self.done.set()

    handler = Reader()
    sub = client.create_subscription(50, handler)
    sub.subscribe_data_change(client.get_node(variable.nodeid))
    assert handler.done.wait(5)
    assert handler.read_back
    sub.delete()


def test_syn1_handlers_run_in_order_on_one_thread(client, variable):
    handler = Recorder()
    sub = client.create_subscription(20, handler)
    sub.subscribe_data_change(client.get_node(variable.nodeid))
    handler.done.wait(5)
    for value in (11.0, 12.0, 13.0, 14.0):
        variable.write_value(value)
        until_sync(lambda value=value: handler.values[-1:] == [value])
    assert handler.values[-4:] == [11.0, 12.0, 13.0, 14.0]
    assert len(set(handler.threads)) == 1
    assert handler.threads[0] != threading.get_ident()
    sub.delete()


def test_syn1_a_slow_handler_does_not_stall_other_requests(client, variable):
    class Slow(Recorder):
        def datachange_notification(self, node, val, data) -> None:
            self.done.set()
            time.sleep(1.5)

    handler = Slow()
    sub = client.create_subscription(20, handler)
    sub.subscribe_data_change(client.get_node(variable.nodeid))
    assert handler.done.wait(5)
    started = time.monotonic()
    client.get_node(variable.nodeid).read_value()
    assert time.monotonic() - started < 1.0
    sub.delete()


def test_syn1_a_full_handler_queue_drops_the_oldest_and_reports_it(server, variable):
    """Dropping is reported like any other loss of messages (OBS-3)."""

    class Counting(Observer):
        def __init__(self) -> None:
            self.dropped = 0

        def on_messages_dropped(self, subscription_id, count) -> None:
            self.dropped += count

    observer = Counting()
    release = threading.Event()
    seen: list[float] = []

    class Blocked:
        def datachange_notification(self, node, val, data) -> None:
            release.wait(10)
            seen.append(val)

    with Client(URL, sync_wrapper_timeout=10, handler_queue_maxsize=2, observer=observer) as c:
        sub = c.create_subscription(20, Blocked())
        sub.subscribe_data_change(c.get_node(variable.nodeid))
        time.sleep(0.3)
        for value in (21.0, 22.0, 23.0, 24.0, 25.0):
            variable.write_value(value)
            time.sleep(0.15)
        assert c._handlers.dropped >= 1
        assert observer.dropped == c._handlers.dropped
        release.set()
        time.sleep(0.3)
        assert seen[-1] == 25.0


def test_syn3_connect_after_disconnect_works_and_old_nodes_stay_valid(server, variable):
    c = Client(URL, sync_wrapper_timeout=10)
    c.connect()
    node = c.get_node(variable.nodeid)
    root = c.nodes.root
    c.disconnect()
    c.connect()
    assert node.read_value() is not None
    assert root.read_browse_name().Name == "Root"
    c.disconnect()


def test_syn3_auto_reconnect_is_exposed_and_the_state_is_visible(server):
    c = Client(URL, sync_wrapper_timeout=10, auto_reconnect=True, reconnect_max_delay=2.0)
    assert c.aio_obj._auto_reconnect is True
    assert c.aio_obj._reconnect_max_delay == 2.0
    states: list[UaClientState] = []
    c.add_state_listener(states.append)
    with c:
        assert c.state is UaClientState.CONNECTED
        until_sync(lambda: UaClientState.CONNECTED in states)
    assert UaClientState.CONNECTED in states


def test_syn6_disconnect_twice_is_a_no_op(server):
    c = Client(URL, sync_wrapper_timeout=10)
    c.connect()
    c.disconnect()
    c.disconnect()


def test_syn4_keyword_and_nested_arguments_are_converted(client, variable):
    node = client.get_node(variable.nodeid)
    _args, kwargs = _to_async([], {"nodes": [node], "pair": (node, 1), "mapping": {"a": node}, "single": node})
    assert kwargs["nodes"][0] is node.aio_obj
    assert kwargs["pair"] == (node.aio_obj, 1)
    assert kwargs["mapping"]["a"] is node.aio_obj
    assert kwargs["single"] is node.aio_obj


def test_syn4_tuples_and_dicts_are_kept(client, variable):
    node = client.get_node(variable.nodeid)
    converted = _to_sync(client.tloop, (node.aio_obj, {"k": node.aio_obj}, [node.aio_obj]))
    assert isinstance(converted, tuple)
    assert isinstance(converted[0], SyncNode)
    assert isinstance(converted[1]["k"], SyncNode)
    assert isinstance(converted[2][0], SyncNode)
    browsed = client.browse_nodes([client.nodes.objects])
    assert isinstance(browsed[0], tuple)


def test_syn4_server_get_node_takes_a_sync_node(server, variable):
    assert server[0].get_node(variable).nodeid == variable.nodeid


def test_syn7_next_event_waits_for_its_own_timeout(client, variable):
    node = client.get_node(variable.nodeid)
    sub = client.create_subscription(50)
    sub.subscribe_data_change(node)
    assert sub.next_event(timeout=2) is not None
    client.tloop.timeout = 0.5
    started = time.monotonic()
    assert sub.next_event(timeout=1.5) is None
    assert time.monotonic() - started >= 1.4
    client.tloop.timeout = 10
    sub.delete()


def test_syn7_a_timed_out_post_does_not_swallow_the_next_event(client, variable):
    node = client.get_node(variable.nodeid)
    sub = client.create_subscription(50)
    sub.subscribe_data_change(node)
    assert sub.next_event(timeout=2) is not None
    client.tloop.timeout = 0.3
    with pytest.raises(TimeoutError):
        client.tloop.post(sub.aio_obj.next_event(timeout=5))
    client.tloop.timeout = 10
    variable.write_value(77.0)
    event = sub.next_event(timeout=3)
    assert event is not None and event.value == 77.0
    sub.delete()


def test_syn7_iteration_ends_on_delete(client, variable):
    sub = client.create_subscription(50)
    sub.subscribe_data_change(client.get_node(variable.nodeid))
    received = []

    def consume() -> None:
        for event in sub:
            received.append(event)

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    until_sync(lambda: bool(received))
    sub.delete()
    thread.join(5)
    assert not thread.is_alive()
    assert received


def test_syn11_client_nodes_use_the_session_of_get_node(client):
    assert type(client.nodes.root.aio_obj.session) is type(client.get_node("i=84").aio_obj.session)


def test_syn11_the_sync_client_has_no_user_manager_parameter():
    with pytest.raises(TypeError):
        Client(URL, user_manager=PermissiveUserManager())  # type: ignore[call-arg]


def test_syn11_a_handler_without_a_method_gets_the_async_layers_error(client, variable, caplog):
    class OnlyEvents:
        def event_notification(self, event) -> None: ...

    sub = client.create_subscription(50, OnlyEvents())
    with caplog.at_level("ERROR"):
        sub.subscribe_data_change(client.get_node(variable.nodeid))
        until_sync(lambda: "has no datachange_notification method" in caplog.text)
    assert "has no datachange_notification method" in caplog.text
    sub.delete()


def test_obs2_the_client_takes_an_observer(client):
    class Silent(Observer): ...

    observer = Silent()
    client.observer = observer
    assert client.aio_obj.uaclient.observer is observer
    assert client.observer is observer


def test_syn5_exit_hooks_disconnect_a_forgotten_client(server):
    code = f"from enginir_opcua.sync import Client\nc = Client({URL!r})\nc.connect()\nprint('connected')\n"
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-c", code], timeout=30, capture_output=True, text=True)
    assert result.returncode == 0
    assert "connected" in result.stdout


def test_syn3_a_shared_loop_is_never_stopped_by_a_client(server):
    with ThreadLoop() as tloop:
        c = Client(URL, tloop=tloop)
        c.connect()
        c.disconnect()
        assert tloop.is_running()

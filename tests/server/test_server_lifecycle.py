from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.server.internal_session import SessionManager
from enginir_opcua.server.user_managers import PermissiveUserManager
from tests.conftest import find_free_port
from tests.harness import give_identity, signing_client, start_discovery_server

"""Server start, restart and stop (Part 5, 12.6; Part 4, 5.5.5, 5.7.4)."""


def _renewal_tasks() -> list[asyncio.Task[Any]]:
    return [t for t in asyncio.all_tasks() if "_run_renewal_loop" in repr(t.get_coro()) and not t.done()]


@pytest.fixture
async def discovery() -> AsyncIterator[Server]:
    server = await start_discovery_server(find_free_port())
    yield server
    await server.stop()


async def test_srv10_restart_gives_the_same_endpoints_and_policy_factories(signing_server: Server) -> None:
    """Part 4, 5.5.4: a restarted server offers the endpoints of its first start, not a growing list."""
    first = [(e.EndpointUrl, e.SecurityPolicyUri, e.SecurityMode) for e in await signing_server.get_endpoints()]
    policies = len(signing_server._policies)
    for _ in range(2):
        await signing_server.stop()
        await signing_server.start()
        again = [(e.EndpointUrl, e.SecurityPolicyUri, e.SecurityMode) for e in await signing_server.get_endpoints()]
        assert again == first
        assert len(signing_server._policies) == policies
    client = await signing_client(signing_server)
    async with client:
        assert await client.nodes.root.read_browse_name() is not None


async def test_srv10_registering_twice_keeps_one_renewal_task_and_stop_cancels_it(discovery: Server) -> None:
    """Part 4, 5.5.5.1: one task renews every registration; stop() ends it."""
    server = Server(allow_no_security=True)
    await server.init()
    await give_identity(server, "urn:enginir:opcua:server", discovery)
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await server.start()
    await server.register_to_discovery(discovery.endpoint.geturl(), period=1)
    await server.register_to_discovery(discovery.endpoint.geturl(), period=1)
    assert len(_renewal_tasks()) == 1
    await server.stop()
    await asyncio.sleep(0)
    assert _renewal_tasks() == []


async def test_srv10_default_timeout_is_gone() -> None:
    """Server.default_timeout was never used."""
    assert not hasattr(Server(allow_no_security=True), "default_timeout")


async def test_srv34_unregistering_an_unknown_url_is_a_ua_error() -> None:
    """Part 4, 5.5.5: unregistering a discovery server that was never registered fails cleanly."""
    server = Server(allow_no_security=True)
    with pytest.raises(ua.UaError):
        await server.unregister_from_discovery("opc.tcp://127.0.0.1:1")


async def test_srv34_stop_sets_shutdown_before_it_closes_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Part 5, 12.6: ServerState is Shutdown while the server is going down."""
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await server.start()
    seen: list[int] = []
    close_all = SessionManager.close_all

    async def spy(manager: SessionManager) -> None:
        state = await server.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_State)).read_value()
        seen.append(int(state))
        await close_all(manager)

    monkeypatch.setattr(SessionManager, "close_all", spy)
    await server.stop()
    assert seen == [ua.ServerState.Shutdown]


async def test_srv34_stop_ends_sessions_subscriptions_and_background_tasks(discovery: Server) -> None:
    """Part 4, 5.7.4: after stop() nothing of the server is left running."""
    server = Server(allow_no_security=True)
    await server.init()
    await give_identity(server, "urn:enginir:opcua:server", discovery)
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await server.start()
    await server.register_to_discovery(discovery.endpoint.geturl(), period=1)
    client = Client(server.endpoint.geturl())
    await client.connect()
    sub = await client.create_subscription(100, None)
    await sub.subscribe_data_change(client.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime)))
    assert server.iserver.session_manager.sessions
    assert server.iserver.subscription_service.subscriptions
    await server.stop()
    assert server.iserver.session_manager.sessions == {}
    assert server.iserver.subscription_service.subscriptions == {}
    assert _renewal_tasks() == []
    client.disconnect_socket()


async def test_srv10_sync_method_callbacks_work_after_a_restart() -> None:
    """Part 4, 5.11.2: a synchronous method callback is still run after the server was stopped and started."""
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    idx = await server.register_namespace("urn:enginir:opcua:restart-method")

    def double(parent: ua.NodeId, value: ua.Variant) -> list[ua.Variant]:
        return [ua.Variant(int(value.Value) * 2, ua.VariantType.Int64)]

    method = await server.nodes.objects.add_method(
        ua.NodeId(1000, idx),
        ua.QualifiedName("double", idx),
        double,
        [ua.VariantType.Int64],
        [ua.VariantType.Int64],
    )
    await server.start()
    await server.stop()
    await server.start()
    try:
        client = Client(server.endpoint.geturl())
        async with client:
            assert await client.nodes.objects.call_method(method.nodeid, 21) == 42
    finally:
        await server.stop()


@pytest.mark.parametrize("field", ["StartTime", "CurrentTime"])
async def test_server_status_timestamps_match_components(opc: Any, field: str) -> None:
    status_node = opc.opc.get_node(ua.ObjectIds.Server_ServerStatus)
    component = await status_node.get_child(f"0:{field}")
    for _ in range(30):
        value = await status_node.read_data_value()
        assert value.StatusCode.is_good()
        assert value.Value is not None
        status = value.Value.Value
        assert value.SourceTimestamp >= status.CurrentTime
        component_value = await component.read_value()
        if getattr(status, field) == component_value:
            break
        await asyncio.sleep(0.1)
    assert getattr(status, field) == component_value


async def test_server_status_clock_updates_preserve_fields(server: Server) -> None:
    status_node = server.get_node(ua.ObjectIds.Server_ServerStatus)
    await server.set_build_info("urn:test", "Manufacturer", "Product", "2.0", "42", datetime.now(UTC))
    before = deepcopy(await status_node.read_value())
    for _ in range(30):
        current = await status_node.read_value()
        if current.CurrentTime > before.CurrentTime:
            break
        await asyncio.sleep(0.1)
    assert current.CurrentTime > before.CurrentTime
    assert current.StartTime == before.StartTime
    assert current.BuildInfo == before.BuildInfo
    assert current.State == before.State
    assert current.SecondsTillShutdown == before.SecondsTillShutdown
    assert current.ShutdownReason == before.ShutdownReason


@pytest.mark.parametrize("disabled_clock", [False, True])
async def test_server_status_start_time_and_clock_shutdown(disabled_clock: bool) -> None:
    server = Server(allow_no_security=True)
    await server.init()
    server.iserver.disabled_clock = disabled_clock
    before = datetime.now(UTC)
    await server.iserver.start()
    try:
        status = await server.get_node(ua.ObjectIds.Server_ServerStatus).read_value()
        start = await server.get_node(ua.ObjectIds.Server_ServerStatus_StartTime).read_value()
        assert before <= status.StartTime <= datetime.now(UTC)
        assert status.StartTime == start
        assert (server.iserver.time_task is None) == disabled_clock
    finally:
        await server.iserver.stop()
    if server.iserver.time_task is not None:
        assert server.iserver.time_task.done()


async def test_server_status_subscription_receives_clock_updates(opc: Any) -> None:
    values: asyncio.Queue[ua.ServerStatusDataType] = asyncio.Queue()

    class Handler:
        def datachange_notification(self, node: Any, value: ua.ServerStatusDataType, data: Any) -> None:
            values.put_nowait(deepcopy(value))

    subscription = await opc.opc.create_subscription(20, Handler())
    try:
        await subscription.subscribe_data_change(opc.opc.get_node(ua.ObjectIds.Server_ServerStatus))
        before = await asyncio.wait_for(values.get(), 3)
        after = await asyncio.wait_for(values.get(), 3)
        assert after.CurrentTime > before.CurrentTime
        assert after.StartTime == before.StartTime
        assert after.BuildInfo == before.BuildInfo
    finally:
        await subscription.delete()


"""Tests for server-side resource limits that guard against exhaustion."""


async def _start_server(port: int) -> Server:
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await srv.start()
    return srv


async def test_session_timeout_clamped_to_max() -> None:
    """A client requesting a huge session timeout gets the server's max instead."""
    port = find_free_port()
    srv = await _start_server(port)
    srv.iserver.max_session_timeout_ms = 60_000
    client = Client(f"opc.tcp://127.0.0.1:{port}")
    client.session_timeout = 24 * 60 * 60 * 1000
    await client.connect()
    try:
        assert client.session_timeout == pytest.approx(60_000)
    finally:
        await client.disconnect()
        await srv.stop()


async def test_session_timeout_clamped_to_min() -> None:
    """A client requesting a very short session timeout gets the server's floor."""
    port = find_free_port()
    srv = await _start_server(port)
    srv.iserver.min_session_timeout_ms = 5_000
    client = Client(f"opc.tcp://127.0.0.1:{port}")
    client.session_timeout = 100
    await client.connect()
    try:
        assert client.session_timeout == pytest.approx(5_000)
    finally:
        await client.disconnect()
        await srv.stop()


async def test_unacked_buffer_cap_propagated_from_iserver() -> None:
    """SubscriptionService threads max_unacked_messages_per_subscription into each InternalSubscription."""
    port = find_free_port()
    srv = await _start_server(port)
    srv.iserver.max_unacked_messages_per_subscription = 42
    client = Client(f"opc.tcp://127.0.0.1:{port}")
    await client.connect()
    try:
        sub = await client.create_subscription(50)
        assert sub.subscription_id is not None
        srv_sub = srv.iserver.isession.subscription_service.subscriptions[sub.subscription_id]
        assert srv_sub._no_acks_limit == 42
        await sub.delete()
    finally:
        await client.disconnect()
        await srv.stop()


async def test_monitored_item_queue_size_clamped() -> None:
    """RequestedQueueSize larger than max_monitored_item_queue_size is revised down."""
    port = find_free_port()
    srv = await _start_server(port)
    srv.iserver.max_monitored_item_queue_size = 100
    objects = srv.get_objects_node()
    variable = await objects.add_variable(2, "ClampVar", 0)

    client = Client(f"opc.tcp://127.0.0.1:{port}")
    await client.connect()
    try:
        sub = await client.create_subscription(50)
        request = ua.CreateMonitoredItemsParameters()
        request.SubscriptionId = sub.subscription_id
        request.TimestampsToReturn = ua.TimestampsToReturn.Both
        rv = ua.ReadValueId()
        rv.NodeId = variable.nodeid
        rv.AttributeId = ua.AttributeIds.Value
        mparams = ua.MonitoringParameters()
        mparams.ClientHandle = 9999
        mparams.SamplingInterval = 50
        mparams.QueueSize = 100_000
        mparams.DiscardOldest = True
        mir = ua.MonitoredItemCreateRequest()
        mir.ItemToMonitor = rv
        mir.MonitoringMode = ua.MonitoringMode.Reporting
        mir.RequestedParameters = mparams
        request.ItemsToCreate = [mir]
        results = await client.uaclient.create_monitored_items(request)
        assert results[0].StatusCode.is_good()
        assert results[0].RevisedQueueSize == 100
        await sub.delete()
    finally:
        await client.disconnect()
        await srv.stop()


async def test_srv13_zero_queue_size_of_a_data_item_is_revised_to_one() -> None:
    """Part 4, 7.21: a queue size of 0 or 1 gives a queue of one value for a data item."""
    port = find_free_port()
    srv = await _start_server(port)
    srv.iserver.max_monitored_item_queue_size = 250
    objects = srv.get_objects_node()
    variable = await objects.add_variable(2, "DefaultVar", 0)

    client = Client(f"opc.tcp://127.0.0.1:{port}")
    await client.connect()
    try:
        sub = await client.create_subscription(50)
        request = ua.CreateMonitoredItemsParameters()
        request.SubscriptionId = sub.subscription_id
        request.TimestampsToReturn = ua.TimestampsToReturn.Both
        rv = ua.ReadValueId()
        rv.NodeId = variable.nodeid
        rv.AttributeId = ua.AttributeIds.Value
        mparams = ua.MonitoringParameters()
        mparams.ClientHandle = 9998
        mparams.SamplingInterval = 50
        mparams.QueueSize = 0
        mparams.DiscardOldest = True
        mir = ua.MonitoredItemCreateRequest()
        mir.ItemToMonitor = rv
        mir.MonitoringMode = ua.MonitoringMode.Reporting
        mir.RequestedParameters = mparams
        request.ItemsToCreate = [mir]
        results = await client.uaclient.create_monitored_items(request)
        assert results[0].StatusCode.is_good()
        assert results[0].RevisedQueueSize == 1
        await sub.delete()
    finally:
        await client.disconnect()
        await srv.stop()

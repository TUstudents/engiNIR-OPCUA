"""Server start, restart and stop (Part 5, 12.6; Part 4, 5.5.5, 5.7.4)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.server.internal_session import SessionManager

from .conftest import find_free_port
from .harness import signing_client

pytestmark = pytest.mark.asyncio


def _renewal_tasks() -> list[asyncio.Task[Any]]:
    return [t for t in asyncio.all_tasks() if "_run_renewal_loop" in repr(t.get_coro()) and not t.done()]


@pytest.fixture
async def discovery() -> AsyncIterator[Server]:
    server = Server()
    await server.init()
    await server.set_application_uri("urn:enginir:opcua:lifecycle-discovery")
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    server.accept_server_registrations()
    await server.start()
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
    server = Server()
    await server.init()
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
    assert not hasattr(Server(), "default_timeout")


async def test_srv34_unregistering_an_unknown_url_is_a_ua_error() -> None:
    """Part 4, 5.5.5: unregistering a discovery server that was never registered fails cleanly."""
    server = Server()
    with pytest.raises(ua.UaError):
        await server.unregister_from_discovery("opc.tcp://127.0.0.1:1")


async def test_srv34_stop_sets_shutdown_before_it_closes_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Part 5, 12.6: ServerState is Shutdown while the server is going down."""
    server = Server()
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
    server = Server()
    await server.init()
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

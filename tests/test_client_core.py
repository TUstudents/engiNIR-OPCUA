import asyncio
import logging
from collections.abc import Iterator

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClientState
from enginir_opcua.client.ua_session import SessionState

from .harness import ResponseTampering, signing_client


@pytest.fixture
async def connected(server: Server) -> Iterator[Client]:
    client = Client(server.endpoint.geturl())
    await client.connect()
    yield client  # type: ignore[misc]
    await client.disconnect()


async def test_cli9_register_and_unregister_nodes_accept_generators(connected: Client) -> None:
    """Part 4, 5.9.5: every node of the request is registered and paired with its result."""
    nodes = [
        connected.get_node(ua.ObjectIds.Server_ServerStatus),
        connected.get_node(ua.ObjectIds.Server_NamespaceArray),
    ]
    registered = await connected.register_nodes(node for node in nodes)
    assert [node.basenodeid for node in registered] == [
        ua.NodeId(ua.ObjectIds.Server_ServerStatus),
        ua.NodeId(ua.ObjectIds.Server_NamespaceArray),
    ]
    await connected.unregister_nodes(node for node in registered)
    assert all(node.basenodeid is None for node in registered)


async def test_cli9_browse_nodes_accepts_a_generator(connected: Client) -> None:
    """Part 4, 5.8.2: every node of the request is browsed and paired with its result."""
    nodes = [connected.get_root_node(), connected.get_objects_node()]
    pairs = await connected.browse_nodes(node for node in nodes)
    assert [node.nodeid for node, _ in pairs] == [node.nodeid for node in nodes]


async def test_cli9_result_count_mismatch_is_an_error(connected: Client, tampered_responses: ResponseTampering) -> None:
    """Part 4, 5.3: a response has one result per request item; a different count is an error."""

    def drop_one(response: ua.ReadResponse) -> None:
        response.Results = response.Results[:-1]

    tampered_responses.on(ua.ReadResponse, drop_one)
    nodes = [
        connected.get_node(ua.ObjectIds.Server_NamespaceArray),
        connected.get_node(ua.ObjectIds.Server_ServerArray),
    ]
    with pytest.raises(ua.UaError, match="2"):
        await connected.read_attributes(nodes)


async def test_cli9_write_values_needs_equal_lengths(connected: Client) -> None:
    """Part 4, 5.10.4: one value per node."""
    nodes = [connected.get_node(ua.ObjectIds.Server_NamespaceArray)]
    with pytest.raises(ValueError):
        await connected.write_values(nodes, [1, 2])


async def test_cli2_register_server2_succeeds_without_the_fallback(server: Server) -> None:
    """Part 4, 5.5.6: RegisterServer2 is tried first; RegisterServer is not sent when it works."""
    client = Client(server.endpoint.geturl())
    calls: list[str] = []

    async def register_server2(params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        calls.append("2")
        return []

    async def register_server(registered: ua.RegisteredServer) -> None:
        calls.append("1")

    client.uaclient.register_server2 = register_server2  # type: ignore[method-assign]
    client.uaclient.register_server = register_server  # type: ignore[method-assign]
    await client.register_server(server)
    await client.register_server(server, [ua.MdnsDiscoveryConfiguration()])
    assert calls == ["2", "2"]


async def test_cli2_register_server_falls_back_only_when_register_server2_is_unsupported(server: Server) -> None:
    """Part 4, 5.5.5 and 5.5.6: RegisterServer is the fallback for Bad_ServiceUnsupported only."""
    client = Client(server.endpoint.geturl())
    calls: list[tuple[str, bool]] = []

    async def unsupported(params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        raise ua.uaerrors.BadServiceUnsupported

    async def refused(params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        raise ua.uaerrors.BadUserAccessDenied

    async def register_server(registered: ua.RegisteredServer) -> None:
        calls.append(("1", registered.IsOnline))

    client.uaclient.register_server = register_server  # type: ignore[method-assign]
    client.uaclient.unregister_server = register_server  # type: ignore[method-assign]
    client.uaclient.register_server2 = unsupported  # type: ignore[method-assign]
    client.uaclient.unregister_server2 = unsupported  # type: ignore[method-assign]
    await client.register_server(server)
    await client.unregister_server(server)
    assert calls == [("1", True), ("1", False)]
    client.uaclient.register_server2 = refused  # type: ignore[method-assign]
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await client.register_server(server)
    assert len(calls) == 2


async def test_cli25_failed_connect_leaves_no_session_on_the_server(
    signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.1: a client that rejects the CreateSession response closes the Session it created."""

    def shorten(response: ua.CreateSessionResponse) -> None:
        response.Parameters.ServerNonce = b"\x01" * 8

    tampered_responses.on(ua.CreateSessionResponse, shorten)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadNonceInvalid):
        await client.connect()
    await asyncio.sleep(0.3)
    assert signing_server.iserver.session_manager.sessions == {}
    assert client.state is UaClientState.DISCONNECTED
    assert client.uaclient.session.state is SessionState.CLOSED


async def test_cli37_second_connect_raises_and_keeps_the_first_session(server: Server) -> None:
    """Part 4, 5.7.2.1: one Session per client; a second connect does not open another one."""
    sessions = server.iserver.session_manager.sessions
    before = len(sessions)
    async with Client(server.endpoint.geturl()) as client:
        assert len(sessions) == before + 1
        with pytest.raises(ConnectionError, match="already connected"):
            await client.connect()
        assert len(sessions) == before + 1
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


async def test_cli36_url_without_a_port_uses_4840(monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 6, 7.1.3: opc.tcp has a registered default port."""
    client = Client("opc.tcp://example.invalid")
    connected: list[tuple[str, int]] = []

    async def connect_socket(host: str, port: int) -> None:
        connected.append((host, port))

    monkeypatch.setattr(client.uaclient, "connect_socket", connect_socket)
    await client.connect_socket()
    assert connected == [("example.invalid", 4840)]


@pytest.mark.parametrize("url", ["http://example.invalid:4840", "localhost:4840", "example.invalid"])
def test_cli36_other_schemes_are_a_configuration_error(url: str) -> None:
    """Only opc.tcp is implemented."""
    with pytest.raises(ua.uaerrors.ConfigurationError):
        Client(url)


async def test_cli24_session_timeout_warning_names_the_session_timeout(
    server: Server, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 4, 5.7.2.2: the log line gives the requested and the revised session timeout."""
    client = Client(server.endpoint.geturl())
    client.session_timeout = 1_234_567_890
    client.secure_channel_timeout = 3_600_000
    with caplog.at_level(logging.WARNING):
        async with client:
            pass
    messages = [r.getMessage() for r in caplog.records if "session timeout" in r.getMessage()]
    assert len(messages) == 1
    assert "1234567890ms" in messages[0]


async def test_cli27_reconnect_gate_survives_disconnect_and_connect(server: Server) -> None:
    """Part 4, 6.7: requests wait for the reconnect also on a client that was disconnected and connected again."""
    client = Client(server.endpoint.geturl(), reconnect_request_timeout=0.3)
    await client.connect()
    await client.disconnect()
    await client.connect()
    try:
        assert client.uaclient.pre_request_hook is not None
        client.uaclient.enter_reconnecting()
        with pytest.raises(ConnectionError):
            await client.nodes.server_state.read_value()
    finally:
        client.uaclient.mark_disconnected()
        await client.disconnect()


async def test_cli28_disconnect_closes_subscription_objects_and_ends_iterators(server: Server) -> None:
    """Part 4, 5.7.4.1: closing the Session ends its Subscriptions; the local objects end with them."""
    client = Client(server.endpoint.geturl())
    await client.connect()
    subscription = await client.create_subscription(100)
    events: list[object] = []

    async def consume() -> None:
        async for event in subscription:
            events.append(event)

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.1)
    await client.disconnect()
    await asyncio.wait_for(consumer, 2)
    assert subscription.is_deleted
    assert client._subscriptions == []


async def test_cli28_connect_after_disconnect_does_not_recreate_old_subscriptions(server: Server) -> None:
    """Part 4, 5.7.4.1: a Subscription of the closed Session does not come back with the next connect."""
    service = server.iserver.subscription_service
    before = len(service.subscriptions)
    client = Client(server.endpoint.geturl())
    client._stale_check_margin = 0
    client._stale_check_interval = 0.05
    await client.connect()
    await client.create_subscription(100)
    await client.disconnect()
    await client.connect()
    await asyncio.sleep(0.5)
    assert len(service.subscriptions) == before
    await client.disconnect()

import asyncio
from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import ReverseConnectListener, UaClientState
from tests.conftest import find_free_port
from tests.waiting import wait_until


async def start_server(application_uri: str = "urn:enginir:opcua:server") -> Server:
    server = Server(allow_no_security=True)
    await server.init()
    await server.set_application_uri(application_uri)
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}/reverse")
    await server.start()
    return server


@pytest.fixture
async def server() -> AsyncIterator[Server]:
    server = await start_server()
    yield server
    await server.stop()


async def test_cli61_listen_reverse_connects_after_the_server_dials(server: Server) -> None:
    """Part 6, 7.1.3: the server connects out, the client runs Hello, OpenSecureChannel and the session on it."""
    port = find_free_port()
    server.add_reverse_connect(f"opc.tcp://127.0.0.1:{port}", retry_interval=0.2)
    client = Client(server.endpoint.geturl(), timeout=3)
    client.listen_reverse(f"opc.tcp://127.0.0.1:{port}", server_uri="urn:enginir:opcua:server")
    async with client:
        assert await client.nodes.server.get_child("0:ServerStatus/0:State") is not None
        value = await client.get_node(ua.ObjectIds.Server_ServerStatus_State).read_value()
        assert value == ua.ServerState.Running


async def test_cli61_wrong_server_uri_is_refused_and_the_wait_times_out(server: Server) -> None:
    """Part 6, 7.1.2.6: a ReverseHello of another server is refused; connect gives up after accept_timeout."""
    port = find_free_port()
    server.add_reverse_connect(f"opc.tcp://127.0.0.1:{port}", retry_interval=0.2)
    client = Client(server.endpoint.geturl(), timeout=3)
    client.listen_reverse(f"opc.tcp://127.0.0.1:{port}", server_uri="urn:someone:else", accept_timeout=1.0)
    with pytest.raises(TimeoutError):
        await client.connect()
    await client.disconnect()


async def test_cli61_parked_socket_is_used_by_a_later_connect(server: Server) -> None:
    """Part 6, 7.1.3, Table 78: the client may save the socket for later."""
    async with ReverseConnectListener("opc.tcp://127.0.0.1:0") as listener:
        server.add_reverse_connect(f"opc.tcp://127.0.0.1:{listener.port}", retry_interval=0.2)
        client = Client(server.endpoint.geturl(), timeout=3)
        client.use_reverse_listener(listener, "urn:enginir:opcua:server")
        await wait_until(lambda: listener.parked_count() == 1)
        await client.connect()
        try:
            assert client.uaclient.state is UaClientState.CONNECTED or client.uaclient.has_session
        finally:
            await client.disconnect()


async def test_cli61_two_clients_share_one_listener(server: Server) -> None:
    """Part 6, 7.1.2.6: one listener serves several servers, told apart by their ServerUri."""
    other = await start_server("urn:enginir:opcua:other")
    try:
        async with ReverseConnectListener("opc.tcp://127.0.0.1:0") as listener:
            clients = []
            for srv in (server, other):
                srv.add_reverse_connect(f"opc.tcp://127.0.0.1:{listener.port}", retry_interval=0.2)
                client = Client(srv.endpoint.geturl(), timeout=3)
                client.use_reverse_listener(listener, srv.get_application_uri())
                clients.append(client)
            try:
                for client in clients:
                    await client.connect()
                names = [await client.get_node(ua.ObjectIds.Server_ServerArray).read_value() for client in clients]
                assert len(names) == 2
            finally:
                for client in clients:
                    await client.disconnect()
    finally:
        await other.stop()


async def test_cli61_connect_waits_at_most_accept_timeout() -> None:
    """Part 6, 7.1.3: with no server connecting, connect fails after the configured time."""
    client = Client("opc.tcp://127.0.0.1:4840/none", timeout=1)
    client.listen_reverse("opc.tcp://127.0.0.1:0", server_uri="urn:none", accept_timeout=0.3)
    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(TimeoutError):
        await client.connect()
    assert loop.time() - started < 2
    await client.disconnect()


async def test_cli61_certificate_host_is_the_name_of_the_url_not_the_peer_address(server: Server) -> None:
    """Part 4, 5.6.2.1: the host name check uses the endpoint URL, never the address of the accepted socket."""
    port = find_free_port()
    url = "opc.tcp://some.server.example:4840/reverse"
    server.add_reverse_connect(f"opc.tcp://127.0.0.1:{port}", endpoint_url=url, retry_interval=0.2)
    client = Client(url, timeout=3)
    client.listen_reverse(f"opc.tcp://127.0.0.1:{port}", server_uri="urn:enginir:opcua:server")
    await client.connect_socket()
    try:
        assert client.uaclient.validation_host_name == "some.server.example"
    finally:
        client.disconnect_socket()
        await client._close_private_reverse_listener()


async def test_cli62_reconnect_waits_for_the_next_reverse_hello_and_keeps_the_session(server: Server) -> None:
    """Part 4, 6.7: a reverse-connect client does not dial; it reconnects on the next socket of the server."""
    port = find_free_port()
    server.add_reverse_connect(f"opc.tcp://127.0.0.1:{port}", retry_interval=0.2)
    client = Client(server.endpoint.geturl(), timeout=2, watchdog_intervall=0.2)
    client.listen_reverse(f"opc.tcp://127.0.0.1:{port}", server_uri="urn:enginir:opcua:server")
    await client.connect(auto_reconnect=True, reconnect_max_delay=0.3, reconnect_request_timeout=10.0)
    try:
        token = client.uaclient.session.authentication_token
        async with client.subscribe_state() as states:
            protocol = client.uaclient.protocol
            assert protocol is not None and protocol.transport is not None
            protocol.transport.close()
            async with asyncio.timeout(15):
                while await states.next_change() is not UaClientState.RECONNECTING:
                    pass
                while await states.next_change() is not UaClientState.CONNECTED:
                    pass
        assert client.uaclient.session.authentication_token == token
        await client.get_node(ua.ObjectIds.Server_ServerStatus_State).read_value()
    finally:
        await client.disconnect()

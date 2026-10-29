import asyncio
from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.connection import error_message_to_binary
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import struct_from_binary
from tests.conftest import find_free_port
from tests.harness import RawPeer

HELLO = ua.Hello(ReceiveBufferSize=65536, SendBufferSize=65536)


class Listener:
    """A listening client that hands every connection of a reverse-connecting server to the test."""

    def __init__(self) -> None:
        self.peers: asyncio.Queue[RawPeer] = asyncio.Queue()
        self.accepted = 0
        self.port = 0
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            self.accepted += 1
            self.peers.put_nowait(RawPeer(reader, writer))

        self._server = await asyncio.start_server(accept, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    @property
    def url(self) -> str:
        return f"opc.tcp://127.0.0.1:{self.port}"

    async def next_peer(self, timeout: float = 5.0) -> RawPeer:
        return await asyncio.wait_for(self.peers.get(), timeout)

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()


@pytest.fixture
async def listener() -> AsyncIterator[Listener]:
    result = Listener()
    await result.start()
    yield result
    await result.stop()


@pytest.fixture
async def reverse_server() -> AsyncIterator[Server]:
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}/reverse")
    await server.start()
    yield server
    await server.stop()


async def receive_reverse_hello(peer: RawPeer) -> ua.ReverseHello:
    message_type, body = await peer.receive()
    assert message_type == b"RHE"
    return struct_from_binary(ua.ReverseHello, Buffer(body))


async def test_srv95_server_sends_reverse_hello_first_and_acknowledges_the_hello(
    reverse_server: Server, listener: Listener
) -> None:
    """Part 6, 7.1.2.6 and 7.1.3: ReverseHello first, then the client's Hello gets an Acknowledge."""
    reverse_server.add_reverse_connect(listener.url)
    peer = await listener.next_peer()
    hello = await receive_reverse_hello(peer)
    assert hello.ServerUri == "urn:enginir:opcua:server"
    assert hello.EndpointUrl == reverse_server.endpoint.geturl()
    await peer.send_hello(HELLO)
    assert (await peer.receive_acknowledge()).ProtocolVersion == 0
    await peer.close()


async def test_srv95_explicit_endpoint_url_is_announced_and_target_can_be_added_before_start(
    listener: Listener,
) -> None:
    """Part 6, 7.1.2.6: the EndpointUrl of the ReverseHello is the configured one."""
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}/x")
    server.add_reverse_connect(listener.url, endpoint_url="opc.tcp://elsewhere:4840/y")
    await server.start()
    try:
        peer = await listener.next_peer()
        assert (await receive_reverse_hello(peer)).EndpointUrl == "opc.tcp://elsewhere:4840/y"
        await peer.close()
    finally:
        await server.stop()


async def test_srv95_next_pending_socket_opens_when_the_hello_arrives(
    reverse_server: Server, listener: Listener
) -> None:
    """Part 6, 7.1.3, Table 78: a new socket exists as soon as the previous one is used."""
    reverse_server.add_reverse_connect(listener.url)
    first = await listener.next_peer()
    await receive_reverse_hello(first)
    assert listener.peers.empty()
    await first.send_hello(HELLO)
    await first.receive_acknowledge()
    second = await listener.next_peer()
    await receive_reverse_hello(second)
    await first.close()
    await second.close()


async def test_srv95_error_from_the_client_closes_the_socket_and_the_server_retries_later(
    reverse_server: Server, listener: Listener
) -> None:
    """Part 6, 7.1.3, Table 78: after an Error message the server closes, logs and reconnects after its delay."""
    reverse_server.add_reverse_connect(listener.url, retry_interval=0.3)
    peer = await listener.next_peer()
    await receive_reverse_hello(peer)
    loop = asyncio.get_running_loop()
    sent = loop.time()
    await peer.send(error_message_to_binary(ua.StatusCodes.BadServerTooBusy, "busy"))
    assert await peer.is_closed_by_peer()
    again = await listener.next_peer()
    assert loop.time() - sent >= 0.3
    await receive_reverse_hello(again)
    await again.close()


async def test_srv95_silent_close_reconnects(reverse_server: Server, listener: Listener) -> None:
    """Part 6, 7.1.3, Table 78: a socket closed without an Error is replaced by a new one."""
    reverse_server.add_reverse_connect(listener.url, retry_interval=0.2)
    peer = await listener.next_peer()
    await receive_reverse_hello(peer)
    await asyncio.sleep(1.1)
    await peer.close()
    again = await listener.next_peer()
    await receive_reverse_hello(again)
    await again.close()


async def test_srv95_pending_socket_has_no_hello_deadline(reverse_server: Server, listener: Listener) -> None:
    """Part 6, 7.1.3, Table 78: a client may keep the socket for later, so no Hello timeout runs on it."""
    reverse_server.iserver.hello_timeout_seconds = 0.2
    reverse_server.iserver.max_pending_activation_seconds = 0.2
    reverse_server.add_reverse_connect(listener.url)
    peer = await listener.next_peer()
    await receive_reverse_hello(peer)
    await asyncio.sleep(0.8)
    await peer.send_hello(HELLO)
    await peer.receive_acknowledge()
    await peer.close()


async def test_srv95_activation_watchdog_starts_at_the_hello(reverse_server: Server, listener: Listener) -> None:
    """Part 6, 7.1.3: once the Hello has arrived the connection is an ordinary one and idles out."""
    reverse_server.iserver.max_pending_activation_seconds = 0.3
    reverse_server.add_reverse_connect(listener.url)
    peer = await listener.next_peer()
    await receive_reverse_hello(peer)
    await peer.send_hello(HELLO)
    await peer.receive_acknowledge()
    assert await peer.is_closed_by_peer(timeout=3)


async def test_srv95_stop_closes_the_pending_socket_and_does_not_reconnect(listener: Listener) -> None:
    """Part 6, 7.1.3: stopping the server ends the reverse connection."""
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}/x")
    await server.start()
    server.add_reverse_connect(listener.url, retry_interval=0.1)
    peer = await listener.next_peer()
    await receive_reverse_hello(peer)
    await server.stop()
    assert await peer.is_closed_by_peer()
    await asyncio.sleep(0.4)
    assert listener.accepted == 1


async def test_srv95_remove_reverse_connect_closes_nothing_used_and_stops_retrying(
    reverse_server: Server, listener: Listener
) -> None:
    """Part 6, 7.1.3: a removed target is no longer served."""
    handle = reverse_server.add_reverse_connect(listener.url, retry_interval=0.1)
    peer = await listener.next_peer()
    await receive_reverse_hello(peer)
    reverse_server.remove_reverse_connect(handle)
    await peer.close()
    await asyncio.sleep(0.4)
    assert listener.accepted == 1


@pytest.mark.parametrize("what", ["uri", "endpoint"])
def test_srv95_strings_of_4096_bytes_are_refused_at_configuration(what: str) -> None:
    """Part 6, 7.1.2.6: both strings encode to fewer than 4096 bytes."""
    server = Server()
    if what == "uri":
        server._application_uri = "u" * 4096
        with pytest.raises(ValueError):
            server.add_reverse_connect("opc.tcp://127.0.0.1:1")
    else:
        with pytest.raises(ValueError):
            server.add_reverse_connect("opc.tcp://127.0.0.1:1", endpoint_url="e" * 4096)


def test_srv95_target_is_added_once_and_needs_an_opc_tcp_url() -> None:
    """Part 6, 7.1.3: one target per client; the URL is configuration."""
    server = Server()
    server.add_reverse_connect("opc.tcp://127.0.0.1:1")
    with pytest.raises(ValueError):
        server.add_reverse_connect("opc.tcp://127.0.0.1:1")
    with pytest.raises(ValueError):
        server.add_reverse_connect("http://127.0.0.1:1")

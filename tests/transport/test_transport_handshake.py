import asyncio
import struct
from collections.abc import AsyncIterator
from unittest.mock import Mock

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient, UASocketProtocol
from enginir_opcua.common.connection import TransportLimits, error_message_to_binary
from enginir_opcua.common.utils import Buffer
from enginir_opcua.server.binary_server_asyncio import OPCUAProtocol
from enginir_opcua.server.uaprocessor import UaProcessor
from enginir_opcua.ua.ua_binary import header_from_binary, struct_from_binary, struct_to_binary, uatcp_to_binary
from tests.conftest import find_free_port
from tests.harness import RawPeer, RawServer, connect_client

HELLO = ua.Hello(ReceiveBufferSize=65536, SendBufferSize=65536)


async def assert_error_and_close(raw_peer: RawPeer, status: int) -> None:
    error = await raw_peer.receive_error()
    assert error.Error.value == status
    assert await raw_peer.is_closed_by_peer()


@pytest.mark.parametrize("message_type", [b"RHE", b"XYZ", b"OPN", b"MSG", b"ACK", b"CLO"])
async def test_srv25_other_message_before_hello_gets_type_invalid(raw_peer: RawPeer, message_type: bytes) -> None:
    """Part 6, 7.1.3 and 7.1.5: Hello comes first; any other type, ReverseHello included, is refused."""
    await raw_peer.send_message(message_type, b"\x00" * 24)
    await assert_error_and_close(raw_peer, ua.StatusCodes.BadTcpMessageTypeInvalid)


@pytest.mark.parametrize("message_type", [b"RHE", b"XYZ", b"ACK", b"HEL"])
async def test_srv25_unusable_message_after_hello_gets_type_invalid(raw_peer: RawPeer, message_type: bytes) -> None:
    """Part 6, 7.1.2.6, 7.1.3 and 7.1.5: after Hello a second Hello, ACK, RHE or unknown type is refused."""
    await raw_peer.send_hello(HELLO)
    await raw_peer.receive_acknowledge()
    await raw_peer.send_message(message_type, b"\x00" * 24)
    await assert_error_and_close(raw_peer, ua.StatusCodes.BadTcpMessageTypeInvalid)


async def test_srv25_unknown_type_is_refused_when_three_bytes_arrived(raw_peer: RawPeer) -> None:
    """Part 6, 7.1.5: the message type is checked as soon as it is there, not when the message is complete."""
    await raw_peer.send(b"RHE")
    await assert_error_and_close(raw_peer, ua.StatusCodes.BadTcpMessageTypeInvalid)


def test_srv9_receive_buffer_is_extended_in_place() -> None:
    """Part 6, 7.1.2.2: a partial chunk is kept in one buffer that data_received only appends to."""
    iserver = Mock()
    iserver.max_pending_messages_per_connection = 500
    protocol = OPCUAProtocol(iserver, [], [], [], Mock())
    protocol.transport = Mock()
    protocol.processor = Mock()
    protocol.processor.hello_received = True
    protocol.processor.max_receive_chunk_size.return_value = 65535
    protocol.data_received(b"MSGF" + struct.pack("<I", 40000))
    buffer = protocol._reader.buffer
    for _ in range(10):
        protocol.data_received(bytes(100))
    assert protocol._reader.buffer is buffer
    assert isinstance(buffer, bytearray)
    assert len(buffer) == 1008


@pytest.mark.parametrize("field", ["ReceiveBufferSize", "SendBufferSize"])
@pytest.mark.parametrize("size", [0, 16, 8191])
async def test_com36_hello_below_8192_is_rejected(raw_peer: RawPeer, field: str, size: int) -> None:
    """Part 6, 7.1.2.3: buffers of at least 8192 bytes; the Error names the field."""
    hello = ua.Hello(ReceiveBufferSize=65535, SendBufferSize=65535)
    setattr(hello, field, size)
    await raw_peer.send_hello(hello)
    error = await raw_peer.receive_error()
    assert error.Error.value == ua.StatusCodes.BadInvalidArgument
    assert field in error.Reason
    assert await raw_peer.is_closed_by_peer()


async def test_com36_hello_with_8192_buffers_is_accepted(raw_peer: RawPeer) -> None:
    """Part 6, 7.1.2.3: 8192 is the smallest allowed buffer."""
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=8192, SendBufferSize=8192))
    acknowledge = await raw_peer.receive_acknowledge()
    assert (acknowledge.ReceiveBufferSize, acknowledge.SendBufferSize) == (8192, 8192)


async def test_srv8_endpoint_url_over_4096_is_rejected(raw_peer: RawPeer) -> None:
    """Part 6, 7.1.2.3: the EndpointUrl is limited to 4096 bytes."""
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=65535, SendBufferSize=65535, EndpointUrl="o" * 4097))
    await assert_error_and_close(raw_peer, ua.StatusCodes.BadTcpEndpointUrlInvalid)


async def test_srv8_endpoint_url_of_4096_bytes_is_accepted(raw_peer: RawPeer) -> None:
    """Part 6, 7.1.2.3: the EndpointUrl is limited to 4096 bytes."""
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=65535, SendBufferSize=65535, EndpointUrl="o" * 4096))
    await raw_peer.receive_acknowledge()


@pytest.mark.parametrize("version", [0, 1, 5, 2**32 - 1])
async def test_srv8_any_protocol_version_gets_zero(raw_peer: RawPeer, version: int) -> None:
    """Part 6, 7.1.2.3 and 7.1.2.4: a higher version than ours is accepted and answered with 0."""
    await raw_peer.send_hello(ua.Hello(ProtocolVersion=version, ReceiveBufferSize=65535, SendBufferSize=65535))
    assert (await raw_peer.receive_acknowledge()).ProtocolVersion == 0


@pytest.fixture
def short_hello_deadline(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server.iserver, "hello_timeout_seconds", 0.3)


@pytest.fixture
async def no_free_connection(server: Server, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[None]:
    async with Client(server.endpoint.geturl()):
        assert server.bserver is not None
        monkeypatch.setattr(server.iserver, "max_connections", len(server.bserver.clients))
        yield


async def test_srv26_no_hello_is_closed_with_timeout(short_hello_deadline: None, raw_peer: RawPeer) -> None:
    """Part 6, 7.1.3: a connection without a Hello is closed; Table 79 gives Bad_Timeout."""
    await assert_error_and_close(raw_peer, ua.StatusCodes.BadTimeout)


async def test_srv26_hello_stops_the_deadline(short_hello_deadline: None, raw_peer: RawPeer) -> None:
    """Part 6, 7.1.3: the deadline is for the Hello only."""
    await raw_peer.send_hello(HELLO)
    await raw_peer.receive_acknowledge()
    assert not await raw_peer.is_closed_by_peer(timeout=0.8)


async def test_srv26_connection_over_limit_gets_not_enough_resources(
    no_free_connection: None, raw_peer: RawPeer
) -> None:
    """Part 6, 7.1.2.3 and 7.1.5: a server that cannot take the connection says so before it closes."""
    await assert_error_and_close(raw_peer, ua.StatusCodes.BadTcpNotEnoughResources)


def hello_limits(hello_max_message_size: int, hello_max_chunk_count: int) -> ua.Hello:
    return ua.Hello(
        ReceiveBufferSize=65535,
        SendBufferSize=65535,
        MaxMessageSize=hello_max_message_size,
        MaxChunkCount=hello_max_chunk_count,
    )


def test_com60_ack_carries_request_limits_and_hello_limits_become_send_limits() -> None:
    """Part 6, 7.1.2.3 and 7.1.2.4: the Hello limits describe responses, the Acknowledge limits describe requests."""
    limits = TransportLimits(max_chunk_count=7, max_message_size=100_000)
    ack = limits.create_acknowledge_and_set_limits(hello_limits(500, 3))
    assert (ack.MaxMessageSize, ack.MaxChunkCount) == (100_000, 7)
    assert (limits.max_message_size, limits.max_chunk_count) == (100_000, 7)
    assert (limits.send_max_message_size, limits.send_max_chunk_count) == (500, 3)


def test_com60_zero_peer_limit_does_not_unbound_receive() -> None:
    """Part 6, 7.1.2.3: 0 from the peer means no limit on what we send, not on what we receive."""
    limits = TransportLimits(max_chunk_count=7, max_message_size=100_000)
    ack = limits.create_acknowledge_and_set_limits(hello_limits(0, 0))
    assert (ack.MaxMessageSize, ack.MaxChunkCount) == (100_000, 7)
    assert (limits.max_message_size, limits.max_chunk_count) == (100_000, 7)
    assert (limits.send_max_message_size, limits.send_max_chunk_count) == (0, 0)


def test_com60_configured_zero_is_replaced_by_the_defaults() -> None:
    """Part 6, 7.1.2.3: an own receive limit of 0 would let a peer send without bound."""
    limits = TransportLimits(max_chunk_count=0, max_message_size=0)
    assert (limits.max_message_size, limits.max_chunk_count) == (100 * 1024 * 1024, 1601)


def test_com60_client_checks_responses_against_its_own_limits() -> None:
    """Part 6, 7.1.2.4: the Acknowledge limits are the server's request limits, not ours for responses."""
    limits = TransportLimits(max_chunk_count=2, max_message_size=1000)
    limits.update_client_limits(ua.Acknowledge(ReceiveBufferSize=65535, SendBufferSize=65535, MaxMessageSize=10**6))
    assert (limits.max_message_size, limits.max_chunk_count) == (1000, 2)
    assert (limits.send_max_message_size, limits.send_max_chunk_count) == (10**6, 0)


async def test_com60_negotiation_does_not_touch_server_configuration() -> None:
    """Part 6, 7.1.2.4: the negotiated values belong to the connection."""
    configured = TransportLimits()
    processor = UaProcessor(Mock(), Mock(), configured)
    processor.accept_hello(Buffer(struct_to_binary(hello_limits(500, 3))))
    assert configured == TransportLimits()
    assert processor._limits.send_max_chunk_count == 3


def test_com38_create_hello_limits_carries_each_limit() -> None:
    """Part 6, 7.1.2.3: MaxMessageSize is a size, not the chunk count."""
    limits = TransportLimits(max_recv_buffer=9000, max_send_buffer=10000, max_chunk_count=7, max_message_size=123456)
    hello = limits.create_hello_limits(ua.Hello())
    assert (hello.ReceiveBufferSize, hello.SendBufferSize) == (9000, 10000)
    assert (hello.MaxMessageSize, hello.MaxChunkCount) == (123456, 7)


def test_com38_hello_defaults_are_the_library_limits() -> None:
    """Part 6, 7.1.2.3: not 2^31-1 placeholders."""
    hello = ua.Hello()
    assert (hello.ReceiveBufferSize, hello.SendBufferSize) == (65535, 65535)
    assert (hello.MaxMessageSize, hello.MaxChunkCount) == (100 * 1024 * 1024, 1601)


async def test_com38_client_hello_carries_its_own_limits(raw_server: RawServer) -> None:
    """Part 6, 7.1.2.3: the client tells the server what it can receive."""
    uaclient = UaClient(timeout=1)
    await uaclient.connect_socket(raw_server.host, raw_server.port)
    hello_task = asyncio.create_task(uaclient.send_hello(raw_server.url))
    peer = await raw_server.accept()
    hello = await peer.receive_hello()
    assert (hello.ReceiveBufferSize, hello.SendBufferSize) == (65535, 65535)
    assert (hello.MaxMessageSize, hello.MaxChunkCount) == (100 * 1024 * 1024, 1601)
    assert hello.EndpointUrl == raw_server.url
    await peer.send_acknowledge(ua.Acknowledge(ReceiveBufferSize=65535, SendBufferSize=65535))
    await hello_task
    uaclient.disconnect_socket()


@pytest.mark.parametrize(
    "acknowledge",
    [
        ua.Acknowledge(ProtocolVersion=1, ReceiveBufferSize=65535, SendBufferSize=65535),
        ua.Acknowledge(ReceiveBufferSize=65536, SendBufferSize=65535),
        ua.Acknowledge(ReceiveBufferSize=65535, SendBufferSize=65536),
        ua.Acknowledge(ReceiveBufferSize=100, SendBufferSize=65535),
        ua.Acknowledge(ReceiveBufferSize=65535, SendBufferSize=8191),
    ],
    ids=["version", "receive-too-large", "send-too-large", "receive-below-8192", "send-below-8192"],
)
async def test_com36_client_rejects_invalid_acknowledge(raw_server: RawServer, acknowledge: ua.Acknowledge) -> None:
    """Part 6, 7.1.2.4: the buffers do not exceed the Hello's and are at least 8192; the version is not higher."""
    uaclient = UaClient(timeout=1)
    await uaclient.connect_socket(raw_server.host, raw_server.port)
    hello_task = asyncio.create_task(uaclient.send_hello(raw_server.url))
    peer = await raw_server.accept()
    await peer.receive_hello()
    await peer.send_acknowledge(acknowledge)
    with pytest.raises(ua.UaStatusCodeError):
        await hello_task
    assert await peer.is_closed_by_peer()


async def test_cli18_client_rejects_oversized_header_before_buffering(raw_server: RawServer) -> None:
    """Part 6, 7.1.2.2 and 7.1.5: a size above the receive buffer ends the connection before the body is read."""
    uaclient, peer = await connect_client(raw_server)
    await peer.send(b"MSGF" + struct.pack("<I", 2**31) + struct.pack("<I", 1))
    await peer.send(bytes(10**6))
    await asyncio.sleep(0.3)
    assert uaclient.protocol is not None
    assert uaclient.protocol.is_closed
    assert len(uaclient.protocol._reader.buffer) == 0


async def test_cli18_client_buffer_is_extended_in_place() -> None:
    """Part 6, 7.1.2.2: a partial chunk is kept in one buffer that data_received only appends to."""
    protocol = UASocketProtocol()
    protocol.data_received(b"MSGF" + struct.pack("<I", 40000))
    buffer = protocol._reader.buffer
    for _ in range(10):
        protocol.data_received(bytes(100))
    assert protocol._reader.buffer is buffer
    assert len(buffer) == 1008


@pytest.mark.parametrize(
    ("data", "error"),
    [
        (b"RHEF" + struct.pack("<I", 8), ua.uaerrors.BadTcpMessageTypeInvalid),
        (b"MSGF" + struct.pack("<I", 4), ua.uaerrors.BadTcpMessageTypeInvalid),
        (b"MSGF" + struct.pack("<I", 2**31) + struct.pack("<I", 1), ua.uaerrors.BadTcpMessageTooLarge),
    ],
    ids=["reverse-hello", "size-below-header", "size-above-buffer"],
)
async def test_cli18_client_fails_pending_requests_on_a_bad_frame(
    raw_server: RawServer, data: bytes, error: type[ua.UaStatusCodeError]
) -> None:
    """Part 6, 7.1.2.2 and 7.1.5: an unusable message from the server fails the waiting requests and closes."""
    uaclient = UaClient(timeout=1)
    await uaclient.connect_socket(raw_server.host, raw_server.port)
    hello_task = asyncio.create_task(uaclient.send_hello(raw_server.url))
    peer = await raw_server.accept()
    await peer.receive_hello()
    await peer.send(data)
    with pytest.raises(error):
        await hello_task
    assert await peer.is_closed_by_peer()


def test_srv25_error_reason_is_cut_at_4096_bytes() -> None:
    """Part 6, 7.1.2.5: the Reason of an Error message is at most 4096 bytes."""
    data = error_message_to_binary(ua.StatusCodes.BadTimeout, "é" * 3000)
    header = header_from_binary(Buffer(data))
    error = struct_from_binary(ua.ErrorMessage, Buffer(data[header.header_size :]))
    assert error.Error.value == ua.StatusCodes.BadTimeout
    assert 0 < len(error.Reason.encode()) <= 4096


async def test_srv25_client_ignores_an_error_reason_over_4096_bytes(raw_server: RawServer) -> None:
    """Part 6, 7.1.2.5: a longer Reason is ignored; the StatusCode still fails the request."""
    uaclient = UaClient(timeout=1)
    await uaclient.connect_socket(raw_server.host, raw_server.port)
    hello_task = asyncio.create_task(uaclient.send_hello(raw_server.url))
    peer = await raw_server.accept()
    await peer.receive_hello()
    error = ua.ErrorMessage(ua.StatusCode(ua.StatusCodes.BadTimeout), "r" * 5000)
    await peer.send(uatcp_to_binary(ua.MessageType.Error, error))
    with pytest.raises(ua.uaerrors.BadTimeout):
        await hello_task


async def test_srv27_oldest_unused_channel_is_closed_at_the_limit() -> None:
    """Part 4, 5.6.2.1: at the limit the oldest channel without a session makes room for the new connection."""
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await server.start()
    server.iserver.max_connections = 2
    peers = []
    try:
        for _ in range(3):
            peer = await RawPeer.connect(server.endpoint.hostname, server.endpoint.port)
            peers.append(peer)
            await peer.send_hello(HELLO)
            await peer.receive_acknowledge()
        first, second, _ = peers
        assert await first.is_closed_by_peer()
        assert not await second.is_closed_by_peer(timeout=0.3)
    finally:
        for peer in peers:
            await peer.close()
        await server.stop()

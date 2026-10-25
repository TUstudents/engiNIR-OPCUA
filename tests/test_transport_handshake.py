import struct
from unittest.mock import Mock

import pytest

from enginir_opcua import ua
from enginir_opcua.server.binary_server_asyncio import OPCUAProtocol

from .harness import RawPeer

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

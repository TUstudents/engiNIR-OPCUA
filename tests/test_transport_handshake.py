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

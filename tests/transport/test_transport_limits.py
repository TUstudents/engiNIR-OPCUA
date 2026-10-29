import struct

import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import header_from_binary, struct_from_binary
from tests.harness import RawPeer


async def test_srv9_oversized_hello_is_rejected_before_buffering(raw_peer: RawPeer) -> None:
    """Part 6, 7.1.2.2 and 7.1.5: the MessageSize is checked against the receive buffer before the chunk is read."""
    await raw_peer.send(b"HELF" + struct.pack("<I", 2**31) + b"\x00" * 1024)
    message_type, body = await raw_peer.receive()
    assert message_type == ua.MessageType.Error
    error = struct_from_binary(ua.ErrorMessage, Buffer(body))
    assert error.Error.value == ua.StatusCodes.BadTcpMessageTooLarge
    assert await raw_peer.is_closed_by_peer()


async def test_srv9_chunk_above_negotiated_buffer_is_rejected(raw_peer: RawPeer) -> None:
    """Part 6, 7.1.2.2: after Hello the limit is the negotiated ReceiveBufferSize."""
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=65536, SendBufferSize=65536))
    acknowledge = await raw_peer.receive_acknowledge()
    await raw_peer.send(b"OPNF" + struct.pack("<I", acknowledge.ReceiveBufferSize + 1) + b"\x00" * 16)
    message_type, _ = await raw_peer.receive()
    assert message_type == ua.MessageType.Error
    assert await raw_peer.is_closed_by_peer()


@pytest.mark.parametrize(("message_type", "size"), [(b"HEL", 7), (b"HEL", 0), (b"MSG", 11), (b"OPN", 8)])
def test_srv9_header_from_binary_rejects_size_below_the_header(message_type: bytes, size: int) -> None:
    """Part 6, 7.1.2.2: MessageSize counts the header, so it cannot be smaller than the header."""
    data = struct.pack("<3scI", message_type, b"F", size) + b"\x00" * 4
    with pytest.raises(ua.uaerrors.BadTcpMessageTypeInvalid):
        header_from_binary(Buffer(data))


@pytest.mark.parametrize(("message_type", "size"), [(b"HEL", 7), (b"MSG", 11)])
async def test_srv9_size_below_header_is_rejected(raw_peer: RawPeer, message_type: bytes, size: int) -> None:
    """Part 6, 7.1.2.2 and 7.1.5: a malformed header gets an Error message before the close."""
    await raw_peer.send_message(message_type, b"\x00" * 4, size=size)
    error = await raw_peer.receive_error()
    assert error.Error.value == ua.StatusCodes.BadTcpMessageTypeInvalid
    assert await raw_peer.is_closed_by_peer()

import struct

import pytest

from enginir_opcua import ua
from enginir_opcua.common.connection import (
    AbortedMessage,
    MessageChunk,
    SecureChannel,
    TransportError,
    TransportLimits,
)
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto.security_policies import SecurityPolicyNone
from enginir_opcua.ua.ua_binary import (
    header_from_binary,
    struct_from_binary,
    struct_to_binary,
)
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


def _incoming_chunk(seq: int, body: bytes, chunk_type=ua.ChunkType.Intermediate) -> MessageChunk:
    chunk = MessageChunk(SecurityPolicyNone().symmetric_cryptography, body=body, chunk_type=chunk_type)
    chunk.MessageHeader.ChannelId = 1
    chunk.MessageHeader.packet_size = len(body) + 24
    chunk.SequenceHeader.RequestId = 1
    chunk.SequenceHeader.SequenceNumber = seq
    return chunk


def _channel(limits: TransportLimits) -> SecureChannel:
    connection = SecureChannel(SecurityPolicyNone(), limits)
    connection.security_token.ChannelId = 1
    return connection


def test_incomplete_message_is_capped_by_max_message_size():
    limits = TransportLimits(max_recv_buffer=1024, max_chunk_count=1000, max_message_size=4096)
    connection = _channel(limits)
    body = bytes(1000)

    for seq in range(1, 5):
        assert connection._receive(_incoming_chunk(seq, body)) is None

    with pytest.raises(TransportError):
        connection._receive(_incoming_chunk(5, body))
    assert connection._incoming_parts == []


def test_a_message_within_max_message_size_still_arrives():
    limits = TransportLimits(max_recv_buffer=1024, max_chunk_count=1000, max_message_size=4096)
    connection = _channel(limits)
    body = bytes(1000)

    for seq in range(1, 4):
        assert connection._receive(_incoming_chunk(seq, body)) is None
    message = connection._receive(_incoming_chunk(4, body, ua.ChunkType.Single))

    assert message is not None
    assert connection._incoming_parts == []


def test_a_configured_zero_message_size_means_the_default_not_unlimited() -> None:
    limits = TransportLimits(max_recv_buffer=1024, max_chunk_count=1000, max_message_size=0)
    connection = _channel(limits)

    assert limits.max_message_size == 100 * 1024 * 1024
    for seq in range(1, 51):
        assert connection._receive(_incoming_chunk(seq, bytes(1000))) is None

    assert len(connection._incoming_parts) == 50


def test_the_accumulated_size_resets_between_messages():
    limits = TransportLimits(max_recv_buffer=1024, max_chunk_count=1000, max_message_size=4096)
    connection = _channel(limits)
    body = bytes(1000)

    for seq in range(1, 4):
        connection._receive(_incoming_chunk(seq, body))
    connection._receive(_incoming_chunk(4, body, ua.ChunkType.Single))

    for seq in range(5, 8):
        assert connection._receive(_incoming_chunk(seq, body)) is None
    assert connection._receive(_incoming_chunk(8, body, ua.ChunkType.Single)) is not None


def test_an_aborted_message_frees_its_accumulated_size():
    limits = TransportLimits(max_recv_buffer=1024, max_chunk_count=1000, max_message_size=4096)
    connection = _channel(limits)
    body = bytes(1000)

    for seq in range(1, 4):
        connection._receive(_incoming_chunk(seq, body))
    abort = _incoming_chunk(4, struct_to_binary(ua.ErrorMessage()), ua.ChunkType.Abort)
    assert isinstance(connection._receive(abort), AbortedMessage)

    for seq in range(5, 8):
        assert connection._receive(_incoming_chunk(seq, body)) is None


def test_acknowledge_bounds_each_buffer_by_the_opposite_hello_buffer() -> None:
    limits = TransportLimits(max_recv_buffer=16384, max_send_buffer=65535)
    hello = ua.Hello(ReceiveBufferSize=8192, SendBufferSize=32768)

    ack = limits.create_acknowledge_and_set_limits(hello)

    assert (ack.ReceiveBufferSize, ack.SendBufferSize) == (16384, 8192)
    assert (limits.max_recv_buffer, limits.max_send_buffer) == (16384, 8192)


@pytest.mark.parametrize("initial", [(65535, 65535), (65535, 8192)])
def test_client_sends_what_the_server_receives_and_receives_what_it_sends(initial: tuple[int, int]) -> None:
    limits = TransportLimits(*initial, 0, 0)
    ack = ua.Acknowledge(ReceiveBufferSize=8192, SendBufferSize=65535)

    limits.update_client_limits(ack)

    assert (limits.max_recv_buffer, limits.max_send_buffer) == (65535, 8192)

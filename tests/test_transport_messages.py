import asyncio
import struct
from unittest.mock import patch

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.connection import (
    MessageAborted,
    MessageChunk,
    SecureChannel,
    TransportError,
    TransportLimits,
)
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto.security_policies import SecurityPolicyNone
from enginir_opcua.ua.ua_binary import header_from_binary, struct_from_binary, struct_to_binary

from .harness import RawPeer, RawServer, connect_client, secure_chunk, signing_client


def big_request(size: int) -> ua.WriteRequest:
    value = ua.DataValue(ua.Variant(b"a" * size, ua.VariantType.ByteString))
    write = ua.WriteValue(NodeId=ua.NodeId(1, 1), AttributeId=ua.AttributeIds.Value, Value=value)
    return ua.WriteRequest(Parameters=ua.WriteParameters(NodesToWrite=[write]))


@pytest.mark.parametrize(
    "acknowledge",
    [
        ua.Acknowledge(ReceiveBufferSize=65535, SendBufferSize=65535, MaxMessageSize=1000),
        ua.Acknowledge(ReceiveBufferSize=8192, SendBufferSize=65535, MaxChunkCount=2),
    ],
    ids=["message-size", "chunk-count"],
)
async def test_com61_request_over_send_limit_fails_locally(raw_server: RawServer, acknowledge: ua.Acknowledge) -> None:
    """Part 6, 7.1.2.4: a request above the server's MaxMessageSize or MaxChunkCount is not sent."""
    uaclient, peer = await connect_client(raw_server, acknowledge)
    assert uaclient.protocol is not None
    with pytest.raises(ua.uaerrors.BadRequestTooLarge):
        await uaclient.protocol.send_request(big_request(20000))
    with pytest.raises(TimeoutError):
        await peer.receive(timeout=0.3)
    assert not uaclient.protocol.is_closed


async def test_com61_request_within_send_limit_is_sent(raw_server: RawServer) -> None:
    """Part 6, 7.1.2.4: a request inside the limits is sent in chunks of at most the negotiated size."""
    acknowledge = ua.Acknowledge(ReceiveBufferSize=8192, SendBufferSize=65535, MaxMessageSize=30000, MaxChunkCount=3)
    uaclient, peer = await connect_client(raw_server, acknowledge)
    assert uaclient.protocol is not None
    request = asyncio.create_task(uaclient.protocol.send_request(big_request(20000), timeout=0.3))
    sizes = []
    for _ in range(3):
        header = await peer.receive()
        sizes.append(len(header[1]) + 8)
    assert max(sizes) <= 8192
    with pytest.raises(TimeoutError):
        await request


async def test_com61_response_over_limit_becomes_service_fault(server: Server) -> None:
    """Part 4, 5.3: a response above the client's MaxMessageSize is replaced by Bad_ResponseTooLarge."""
    big = await server.nodes.objects.add_variable(1, "ComSixtyOneBig", b"a" * 100_000)
    small = await server.nodes.objects.add_variable(1, "ComSixtyOneSmall", "small")
    client = Client(server.endpoint.geturl())
    client.max_messagesize = 60_000
    async with client:
        with pytest.raises(ua.uaerrors.BadResponseTooLarge):
            await client.get_node(big.nodeid).read_value()
        assert await client.get_node(small.nodeid).read_value() == "small"


def _channel(limits: TransportLimits) -> SecureChannel:
    connection = SecureChannel(SecurityPolicyNone(), limits)
    connection.security_token.ChannelId = 1
    return connection


def test_com36_capacity_is_positive_for_8192() -> None:
    """Part 6, 6.7.2: a Hello buffer of 8192 gives chunks that carry data."""
    connection = _channel(TransportLimits(max_send_buffer=8192))
    data = connection.message_to_binary(b"a" * 20000, request_id=1)
    assert len(data) > 20000
    assert len(data) // 3 <= 8192


def test_com36_chunk_size_without_capacity_is_an_error() -> None:
    """Part 6, 7.1.2.3: a buffer too small for any body is refused, not turned into zero chunks."""
    connection = _channel(TransportLimits(max_send_buffer=16))
    with pytest.raises(ua.UaError):
        connection.message_to_binary(b"a" * 500, request_id=1)


def chunks_of(data: bytes) -> list[tuple[ua.Header, bytes]]:
    buf = Buffer(data)
    chunks = []
    while buf:
        header = header_from_binary(buf)
        chunks.append((header, buf.read(header.body_size)))
    return chunks


def test_com61_abort_chunk_after_late_failure() -> None:
    """Part 6, 6.7.3: a Message that fails after its first chunk is closed with an Abort chunk."""
    connection = _channel(TransportLimits(max_send_buffer=8192))
    to_binary = MessageChunk.to_binary
    calls = []

    def fail_on_second(chunk: MessageChunk) -> bytes:
        calls.append(chunk)
        if len(calls) == 2:
            raise ua.UaError("late failure")
        return to_binary(chunk)

    with patch.object(MessageChunk, "to_binary", fail_on_second):
        with pytest.raises(MessageAborted) as aborted:
            connection.message_to_binary(b"a" * 20000, request_id=7)
    chunks = chunks_of(aborted.value.written)
    assert [header.ChunkType for header, _ in chunks] == [ua.ChunkType.Intermediate, ua.ChunkType.Abort]
    sequence_numbers = [struct.unpack("<II", body[4:12])[0] for _, body in chunks]
    assert sequence_numbers == [1, 2]
    error = struct_from_binary(ua.ErrorMessage, Buffer(chunks[1][1][12:]))
    assert error.Error.value != ua.StatusCodes.Good
    assert connection._sequence_number == 2


def _chunk(message_type: bytes, chunk_type: bytes, seq: int, request_id: int = 1) -> MessageChunk:
    chunk = MessageChunk(SecurityPolicyNone().symmetric_cryptography, b"x" * 10, message_type, chunk_type)
    chunk.MessageHeader.ChannelId = 1
    chunk.MessageHeader.packet_size = 34
    chunk.SequenceHeader.RequestId = request_id
    chunk.SequenceHeader.SequenceNumber = seq
    return chunk


@pytest.mark.parametrize("message_type", [ua.MessageType.SecureOpen, ua.MessageType.SecureClose])
@pytest.mark.parametrize("chunk_type", [ua.ChunkType.Intermediate, ua.ChunkType.Abort])
def test_com64_open_and_close_need_a_single_final_chunk(message_type: bytes, chunk_type: bytes) -> None:
    """Part 6, 6.7.2.2: OpenSecureChannel and CloseSecureChannel are one final chunk."""
    connection = _channel(TransportLimits())
    with pytest.raises(TransportError) as error:
        connection._receive(_chunk(message_type, chunk_type, 1))
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed
    assert connection._incoming_parts == []


def test_com64_mixed_message_types_are_rejected() -> None:
    """Part 6, 6.7.3: the chunks of one Message have the same message type."""
    connection = _channel(TransportLimits())
    assert connection._receive(_chunk(ua.MessageType.SecureMessage, ua.ChunkType.Intermediate, 1)) is None
    with pytest.raises(TransportError) as error:
        connection._receive(_chunk(ua.MessageType.SecureClose, ua.ChunkType.Single, 2))
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed
    assert connection._incoming_parts == []


def test_com64_a_different_request_id_inside_a_message_is_rejected() -> None:
    """Part 6, 6.7.3: chunks of different Messages are not interleaved."""
    connection = _channel(TransportLimits())
    connection._receive(_chunk(ua.MessageType.SecureMessage, ua.ChunkType.Intermediate, 1, request_id=1))
    with pytest.raises(TransportError) as error:
        connection._receive(_chunk(ua.MessageType.SecureMessage, ua.ChunkType.Single, 2, request_id=2))
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed


def test_com60_message_above_the_receive_limit_is_tcp_message_too_large() -> None:
    """Part 6, 7.1.2.3 and 7.1.5: a Message above the announced size ends the connection with Table 79's code."""
    connection = _channel(TransportLimits(max_chunk_count=2))
    connection._receive(_chunk(ua.MessageType.SecureMessage, ua.ChunkType.Intermediate, 1))
    connection._receive(_chunk(ua.MessageType.SecureMessage, ua.ChunkType.Intermediate, 2))
    with pytest.raises(TransportError) as error:
        connection._receive(_chunk(ua.MessageType.SecureMessage, ua.ChunkType.Intermediate, 3))
    assert error.value.status == ua.StatusCodes.BadTcpMessageTooLarge


@pytest.fixture
def five_chunks_per_message(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    assert server.bserver is not None
    monkeypatch.setattr(server.bserver.limits, "max_chunk_count", 5)


async def test_com60_server_answers_too_many_chunks_with_tcp_message_too_large(
    five_chunks_per_message: None, raw_peer: RawPeer
) -> None:
    """Part 6, 7.1.2.3 and 7.1.5: the Error for a Message with more chunks than announced."""
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=65535, SendBufferSize=65535))
    acknowledge = await raw_peer.receive_acknowledge()
    assert acknowledge.MaxChunkCount == 5
    await raw_peer.send(b"".join(secure_chunk(b"C", 1, seq, b"x") for seq in range(1, 7)))
    error = await raw_peer.receive_error()
    assert error.Error.value == ua.StatusCodes.BadTcpMessageTooLarge
    assert await raw_peer.is_closed_by_peer()


async def test_com60_client_fails_pending_requests_on_too_many_chunks(raw_server: RawServer) -> None:
    """Part 6, 7.1.2.3: a response with more chunks than the client announced fails the request."""
    uaclient, peer = await connect_client(raw_server)
    assert uaclient.protocol is not None
    uaclient.protocol._channel.limits.max_chunk_count = 2
    request = asyncio.create_task(uaclient.protocol.send_request(ua.ReadRequest(), timeout=2))
    await peer.receive()
    await peer.send(b"".join(secure_chunk(b"C", 1, seq, b"x") for seq in range(1, 4)))
    with pytest.raises(ua.uaerrors.BadResponseTooLarge):
        await request
    assert await peer.is_closed_by_peer()


async def test_cli19_abort_fails_the_request_at_once(raw_server: RawServer) -> None:
    """Part 6, 6.7.3: an Abort chunk fails the request it names with the Error StatusCode."""
    uaclient, peer = await connect_client(raw_server)
    assert uaclient.protocol is not None
    request = asyncio.create_task(uaclient.protocol.send_request(ua.ReadRequest(), timeout=2))
    _, body = await peer.receive()
    request_id = struct.unpack("<I", body[12:16])[0]
    error = ua.ErrorMessage(ua.StatusCode(ua.StatusCodes.BadEncodingLimitsExceeded), "no")
    await peer.send(secure_chunk(b"A", request_id, 1, struct_to_binary(error)))
    with pytest.raises(ua.uaerrors.BadEncodingLimitsExceeded):
        await asyncio.wait_for(request, 1)
    assert not uaclient.protocol.is_closed


async def test_cli19_abort_with_unreadable_body_fails_with_unexpected_error(raw_server: RawServer) -> None:
    """Part 6, 6.7.3: an Abort whose body cannot be read still discards the Message."""
    uaclient, peer = await connect_client(raw_server)
    assert uaclient.protocol is not None
    request = asyncio.create_task(uaclient.protocol.send_request(ua.ReadRequest(), timeout=2))
    _, body = await peer.receive()
    request_id = struct.unpack("<I", body[12:16])[0]
    await peer.send(secure_chunk(b"A", request_id, 1, b"\x01"))
    with pytest.raises(ua.uaerrors.BadUnexpectedError):
        await asyncio.wait_for(request, 1)


@pytest.mark.parametrize("opn_chunk_type", [b"C", b"A"])
async def test_srv25_open_with_intermediate_chunk_gets_security_checks_failed(
    raw_peer: RawPeer, opn_chunk_type: bytes
) -> None:
    """Part 6, 6.7.2.2 and 7.1.5: a protocol error on the channel is answered with an Error message and a close."""
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=65535, SendBufferSize=65535))
    await raw_peer.receive_acknowledge()
    await raw_peer.send(secure_chunk(opn_chunk_type, 1, 1, b"x", message_type=b"OPN"))
    error = await raw_peer.receive_error()
    assert error.Error.value == ua.StatusCodes.BadSecurityChecksFailed
    assert error.Reason == ""
    assert await raw_peer.is_closed_by_peer()


async def test_srv25_wrong_sequence_number_gets_security_checks_failed_and_closes(raw_peer: RawPeer) -> None:
    """Part 6, 6.7.2.4 and 6.7.7: a sequence number out of order closes the channel, and the peer is told."""
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=65535, SendBufferSize=65535))
    await raw_peer.receive_acknowledge()
    await raw_peer.send(secure_chunk(b"C", 1, 1, b"x"))
    await raw_peer.send(secure_chunk(b"C", 1, 9, b"x"))
    error = await raw_peer.receive_error()
    assert error.Error.value == ua.StatusCodes.BadSecurityChecksFailed
    assert await raw_peer.is_closed_by_peer()


async def test_srv25_bad_signature_sends_security_checks_failed_and_closes(
    signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 6, 6.7.7 and 7.1.5: a chunk that does not verify gets an Error message and closes the connection."""
    client = await signing_client(signing_server)
    async with client:
        assert client.uaclient.protocol is not None
        crypto = client.uaclient.protocol._channel.security_policy.symmetric_cryptography
        genuine = crypto.signature
        monkeypatch.setattr(crypto, "signature", lambda data: bytes(len(genuine(data))))
        with pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
            await client.get_node(ua.ObjectIds.Server_ServerStatus_State).read_value()
        monkeypatch.undo()

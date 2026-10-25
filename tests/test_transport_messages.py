import asyncio
import struct
from unittest.mock import patch

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.connection import MessageAborted, MessageChunk, SecureConnection, TransportLimits
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto.security_policies import SecurityPolicyNone
from enginir_opcua.ua.ua_binary import header_from_binary, struct_from_binary

from .harness import RawServer, connect_client


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


def _connection(limits: TransportLimits) -> SecureConnection:
    connection = SecureConnection(SecurityPolicyNone(), limits)
    connection.security_token.ChannelId = 1
    return connection


def test_com36_capacity_is_positive_for_8192() -> None:
    """Part 6, 6.7.2: a Hello buffer of 8192 gives chunks that carry data."""
    connection = _connection(TransportLimits(max_send_buffer=8192))
    data = connection.message_to_binary(b"a" * 20000, request_id=1)
    assert len(data) > 20000
    assert len(data) // 3 <= 8192


def test_com36_chunk_size_without_capacity_is_an_error() -> None:
    """Part 6, 7.1.2.3: a buffer too small for any body is refused, not turned into zero chunks."""
    connection = _connection(TransportLimits(max_send_buffer=16))
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
    connection = _connection(TransportLimits(max_send_buffer=8192))
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

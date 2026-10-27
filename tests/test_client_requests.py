import asyncio
import logging

import pytest

from enginir_opcua import ua
from enginir_opcua.client.ua_client import UaClient, UASocketProtocol
from enginir_opcua.common.connection import SecureChannel
from enginir_opcua.ua.ua_binary import struct_to_binary

from .harness import CONNECTION_PROTOCOL_HEADER, RawPeer, RawServer, _frames, connect_client, open_channel_as_server


async def handshaken(raw_server: RawServer, timeout: float = 0.3) -> tuple[UaClient, RawPeer, SecureChannel]:
    uaclient, peer = await connect_client(raw_server)
    channel = await open_channel_as_server(uaclient, peer)
    protocol = uaclient.protocol
    assert protocol is not None
    protocol.timeout = timeout
    return uaclient, peer, channel


async def receive_request_id(peer: RawPeer, channel: SecureChannel) -> int:
    message_type, body = await peer.receive()
    data = CONNECTION_PROTOCOL_HEADER.pack(message_type, b"F", CONNECTION_PROTOCOL_HEADER.size + len(body)) + body
    ((header, chunk_body),) = _frames(data)
    return channel.receive_from_header_and_body(header, chunk_body).request_id()


async def send_read_response(peer: RawPeer, channel: SecureChannel, request_id: int) -> None:
    response = ua.ReadResponse()
    response.Results = [ua.DataValue(ua.Variant(1, ua.VariantType.Int32))]
    await peer.send(channel.message_to_binary(struct_to_binary(response), request_id=request_id))


def read_request() -> ua.ReadRequest:
    request = ua.ReadRequest()
    request.Parameters.NodesToRead = [ua.ReadValueId(NodeId=ua.NodeId(2259), AttributeId=ua.AttributeIds.Value)]
    return request


async def timed_out_request(
    protocol: UASocketProtocol, peer: RawPeer, channel: SecureChannel, timeout: float = 0.2
) -> int:
    request_task = asyncio.create_task(protocol.send_request(read_request(), timeout))
    request_id = await receive_request_id(peer, channel)
    with pytest.raises(TimeoutError):
        await request_task
    return request_id


async def test_cli1_timed_out_request_leaves_no_table_entry(raw_server: RawServer) -> None:
    """Part 6, 6.7.7: a request that timed out is no longer pending."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    await timed_out_request(protocol, peer, channel)
    assert protocol._callbackmap == {}


async def test_cli1_cancelled_request_leaves_no_table_entry(raw_server: RawServer) -> None:
    """Part 6, 6.7.7: a request that the caller cancelled is no longer pending."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    request_task = asyncio.create_task(protocol.send_request(read_request(), 5))
    await receive_request_id(peer, channel)
    request_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request_task
    assert protocol._callbackmap == {}


async def test_cli1_late_response_is_dropped_silently(raw_server: RawServer, caplog: pytest.LogCaptureFixture) -> None:
    """Part 6, 6.7.7: the response of an abandoned request is discarded; the channel stays usable."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    request_id = await timed_out_request(protocol, peer, channel)
    with caplog.at_level(logging.DEBUG):
        await send_read_response(peer, channel, request_id)
        await asyncio.sleep(0.2)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert not protocol.is_closed
    second = asyncio.create_task(protocol.send_request(read_request(), 2))
    await send_read_response(peer, channel, await receive_request_id(peer, channel))
    await second


async def test_cli1_response_for_an_id_never_issued_closes_the_channel(raw_server: RawServer) -> None:
    """Part 6, 6.7.7: the client verifies the RequestId of a response; an id it never sent ends the connection."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    await send_read_response(peer, channel, 4711)
    assert await peer.is_closed_by_peer()
    assert protocol.is_closed

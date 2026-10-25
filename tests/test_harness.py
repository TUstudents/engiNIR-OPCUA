import pytest

from enginir_opcua import Client, Server, ua

from .harness import RawPeer, ResponseTampering, TwoSessions


async def test_raw_peer_gets_acknowledge_for_hello(raw_peer: RawPeer) -> None:
    await raw_peer.send_hello(ua.Hello(ReceiveBufferSize=65536, SendBufferSize=65536))
    acknowledge = await raw_peer.receive_acknowledge()
    assert acknowledge.ProtocolVersion == 0
    assert acknowledge.ReceiveBufferSize <= 65536


async def test_raw_peer_sees_error_and_close_after_second_hello(raw_peer: RawPeer) -> None:
    hello = ua.Hello(ReceiveBufferSize=65536, SendBufferSize=65536)
    await raw_peer.send_hello(hello)
    await raw_peer.receive_acknowledge()
    await raw_peer.send_hello(hello)
    message_type, _ = await raw_peer.receive()
    assert message_type == ua.MessageType.Error
    assert await raw_peer.is_closed_by_peer()


async def test_tampered_responses_rewrite_get_endpoints(server: Server, tampered_responses: ResponseTampering) -> None:
    def redirect_endpoints(response: ua.GetEndpointsResponse) -> None:
        for endpoint in response.Endpoints:
            endpoint.EndpointUrl = "opc.tcp://tampered.invalid:4840"

    tampered_responses.on(ua.GetEndpointsResponse, redirect_endpoints)
    async with Client(server.endpoint.geturl()) as client:
        endpoints = await client.get_endpoints()
    assert endpoints
    assert {endpoint.EndpointUrl for endpoint in endpoints} == {"opc.tcp://tampered.invalid:4840"}


async def test_two_sessions_are_both_activated(two_sessions: TwoSessions) -> None:
    for client in (two_sessions.alice, two_sessions.bob):
        state = await client.get_node(ua.ObjectIds.Server_ServerStatus_State).read_value()
        assert state == ua.ServerState.Running


async def test_two_sessions_server_rejects_unknown_user(two_sessions: TwoSessions) -> None:
    endpoint = two_sessions.server.endpoint
    with pytest.raises(ua.UaStatusCodeError):
        async with Client(f"opc.tcp://mallory:wrong@{endpoint.hostname}:{endpoint.port}"):
            pass

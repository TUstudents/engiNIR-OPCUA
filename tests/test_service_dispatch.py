"""One dispatch table for the service requests: checks, StatusCode mapping, concurrency (Part 4, 5.3, 7.34)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.crypto.permission_rules import User

from .conftest import find_free_port
from .harness import SessionProbe

pytestmark = pytest.mark.asyncio


class RolelessUserManager:
    def get_user(self, iserver: Any, username: Any = None, password: Any = None, certificate: Any = None) -> User:
        return User(role="Operator", name="someone")  # type: ignore[arg-type]


async def _server(user_manager: Any = None) -> Server:
    srv = Server(allow_no_security=True, user_manager=user_manager)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await srv.start()
    return srv


@pytest.fixture
async def srv() -> AsyncIterator[Server]:
    server = await _server()
    yield server
    await server.stop()


async def _activated(probe: SessionProbe) -> ua.NodeId:
    token = (await probe.create_session()).AuthenticationToken
    await probe.activate(token)
    return token


def _read_request(count: int) -> ua.ReadRequest:
    request = ua.ReadRequest()
    request.Parameters.NodesToRead = [
        ua.ReadValueId(NodeId=ua.NodeId(ua.ObjectIds.Server_ServerStatus_State), AttributeId=ua.AttributeIds.Value)
        for _ in range(count)
    ]
    return request


async def test_cry12_unknown_role_is_user_access_denied() -> None:
    """Part 4, 5.3: a user whose role no rule covers is refused, not answered with an internal error."""
    srv = await _server(RolelessUserManager())
    try:
        probe = await SessionProbe.open(srv.endpoint.geturl())
        token = await _activated(probe)
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await probe.send(token, _read_request(1), ua.ReadResponse)
        probe.close()
    finally:
        await srv.stop()


async def test_srv37_empty_read_is_nothing_to_do(srv: Server) -> None:
    """Part 4, 5.10.2.3: a Read without nodes fails with Bad_NothingToDo."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        with pytest.raises(ua.uaerrors.BadNothingToDo):
            await probe.send(token, _read_request(0), ua.ReadResponse)
    finally:
        probe.close()


async def test_srv37_more_nodes_than_the_limit_is_too_many_operations(srv: Server) -> None:
    """Part 4, 5.10.2.3: more operations than the OperationLimits allow fail with Bad_TooManyOperations."""
    srv.iserver.operation_limits.max_nodes_per_read = 3
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        assert len((await probe.send(token, _read_request(3), ua.ReadResponse)).Results) == 3
        with pytest.raises(ua.uaerrors.BadTooManyOperations):
            await probe.send(token, _read_request(4), ua.ReadResponse)
    finally:
        probe.close()


async def test_srv37_operation_limits_nodes_show_the_enforced_values(srv: Server) -> None:
    """Part 5, 6.3.2: the OperationLimits nodes say what the server enforces."""
    value = await srv.get_node(
        ua.NodeId(ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead)
    ).read_value()
    assert value == srv.iserver.operation_limits.max_nodes_per_read


async def test_srv38_truncated_body_is_decoding_error(srv: Server) -> None:
    """Part 4, 5.3: a request body that cannot be decoded fails with Bad_DecodingError."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        with pytest.raises(ua.uaerrors.BadDecodingError):
            await probe.send_edited(token, _read_request(2), ua.ReadResponse, lambda data: data[:-6])
        assert await probe.read_server_state(token) == ua.ServerState.Running
    finally:
        probe.close()


async def test_cry12_unknown_request_type_is_service_unsupported(srv: Server) -> None:
    """Part 4, 7.34: a request type the server does not implement is Bad_ServiceUnsupported."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        with pytest.raises(ua.uaerrors.BadServiceUnsupported):
            await probe.send(token, ua.QueryFirstRequest(), ua.QueryFirstResponse)
        unknown = ua.NodeId(bytes(32), 0, ua.NodeIdType.ByteString)
        with pytest.raises(ua.uaerrors.BadServiceUnsupported):
            await probe.send(unknown, ua.QueryFirstRequest(), ua.QueryFirstResponse)
    finally:
        probe.close()


@pytest.mark.parametrize("request_type", [ua.ReadRequest, ua.WriteRequest, ua.BrowseRequest, ua.CallRequest])
async def test_cry12_session_checks_run_before_the_body_is_decoded(srv: Server, request_type: type) -> None:
    """Part 4, 5.7.2.1: the Session checks come first, in one order, whatever the body holds."""
    url = srv.endpoint.geturl()
    probe, other = await SessionProbe.open(url), await SessionProbe.open(url)
    try:
        created = (await probe.create_session()).AuthenticationToken
        unknown = ua.NodeId(bytes(32), 0, ua.NodeIdType.ByteString)
        expected: list[tuple[SessionProbe, ua.NodeId, type[Exception]]] = [
            (probe, unknown, ua.uaerrors.BadSessionIdInvalid),
            (probe, created, ua.uaerrors.BadSessionNotActivated),
            (other, created, ua.uaerrors.BadSecureChannelIdInvalid),
        ]
        for sender, token, error in expected:
            with pytest.raises(error):
                await sender.send_edited(token, request_type(), ua.ReadResponse, lambda data: data[:-1])
    finally:
        probe.close()
        other.close()


async def _slow_method(srv: Server, seconds: float) -> ua.NodeId:
    async def slow(parent: ua.NodeId) -> list[Any]:
        await asyncio.sleep(seconds)
        return []

    method = await srv.nodes.objects.add_method(2, "Slow", slow, [], [])
    return method.nodeid


def _call_request(method_id: ua.NodeId) -> ua.CallRequest:
    request = ua.CallRequest()
    request.Parameters.MethodsToCall = [
        ua.CallMethodRequest(ObjectId=ua.NodeId(ua.ObjectIds.ObjectsFolder), MethodId=method_id)
    ]
    return request


async def test_srv41_read_is_answered_while_a_call_runs(srv: Server) -> None:
    """Part 4, 5.3: requests of one Session can run at the same time, a slow Call does not delay a Read."""
    method_id = await _slow_method(srv, 1.5)
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        call = asyncio.create_task(probe.send(token, _call_request(method_id), ua.CallResponse))
        await asyncio.sleep(0.2)
        started = time.monotonic()
        assert await probe.read_server_state(token) == ua.ServerState.Running
        assert time.monotonic() - started < 1.0
        await call
    finally:
        probe.close()


async def test_srv41_requests_above_the_in_flight_cap_get_server_too_busy(srv: Server) -> None:
    """Part 4, 5.3: a Session with too many requests in flight gets Bad_ServerTooBusy."""
    srv.iserver.session_manager.max_requests_in_flight_per_session = 2
    method_id = await _slow_method(srv, 1.0)
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        calls = [asyncio.create_task(probe.send(token, _call_request(method_id), ua.CallResponse)) for _ in range(3)]
        outcomes = await asyncio.gather(*calls, return_exceptions=True)
        busy = [o for o in outcomes if isinstance(o, ua.uaerrors.BadServerTooBusy)]
        assert len(busy) == 1
        assert await probe.read_server_state(token) == ua.ServerState.Running
    finally:
        probe.close()

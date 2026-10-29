from __future__ import annotations

import asyncio
import inspect
from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.session_interface import AbstractSession
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.server.internal_session import InternalSession
from tests.conftest import find_free_port
from tests.harness import SessionProbe
from tests.waiting import wait_until

"""Session model of the server: ids, binding, limits, nonce, close and loss (Part 4, 5.7)."""


async def _start_server() -> Server:
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await srv.start()
    return srv


@pytest.fixture
async def srv() -> AsyncIterator[Server]:
    server = await _start_server()
    yield server
    await server.stop()


async def _activated(probe: SessionProbe) -> ua.NodeId:
    token = (await probe.create_session()).AuthenticationToken
    await probe.activate(token)
    return token


async def test_srv2_two_servers_in_one_process_have_independent_session_ids() -> None:
    """Part 4, 5.7.2: the SessionId is per server; a second server does not continue the first one's numbering."""
    first, second = await _start_server(), await _start_server()
    try:
        probe_a = await SessionProbe.open(first.endpoint.geturl())
        probe_b = await SessionProbe.open(second.endpoint.geturl())
        id_a = (await probe_a.create_session()).SessionId
        id_b = (await probe_b.create_session()).SessionId
        probe_a.close()
        probe_b.close()
        assert id_a == id_b
    finally:
        await first.stop()
        await second.stop()


async def test_srv2_second_create_session_keeps_the_first_session(srv: Server) -> None:
    """Part 4, 5.7.2.1: a channel can carry several Sessions."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        first = await _activated(probe)
        second = await _activated(probe)
        assert first != second
        assert await probe.read_server_state(first) == ua.ServerState.Running
        assert await probe.read_server_state(second) == ua.ServerState.Running
    finally:
        probe.close()


async def test_srv8_unknown_token_is_session_id_invalid(srv: Server) -> None:
    """Part 4, 5.7.2.1, 7.35: a token the server never issued names no Session."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        with pytest.raises(ua.uaerrors.BadSessionIdInvalid):
            await probe.read_server_state(ua.NodeId(bytes(32), 0, ua.NodeIdType.ByteString))
    finally:
        probe.close()


async def test_srv8_created_session_gets_session_not_activated(srv: Server) -> None:
    """Part 4, 5.7.3: services other than ActivateSession need an activated Session."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = (await probe.create_session()).AuthenticationToken
        with pytest.raises(ua.uaerrors.BadSessionNotActivated):
            await probe.read_server_state(token)
    finally:
        probe.close()


async def test_srv1_first_activation_on_other_channel_is_rejected(srv: Server) -> None:
    """Part 4, 5.7.3.1: the first ActivateSession comes on the channel that created the Session."""
    url = srv.endpoint.geturl()
    creator, other = await SessionProbe.open(url), await SessionProbe.open(url)
    try:
        token = (await creator.create_session()).AuthenticationToken
        with pytest.raises(ua.uaerrors.BadSecureChannelIdInvalid):
            await other.activate(token)
        await creator.activate(token)
        assert await creator.read_server_state(token) == ua.ServerState.Running
    finally:
        creator.close()
        other.close()


async def test_srv28_oldest_unactivated_session_is_evicted_at_the_limit(srv: Server) -> None:
    """Part 4, 5.7.2.1: at the limit the server closes its oldest Session that was never activated."""
    srv.iserver.session_manager.max_sessions = 3
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        tokens = [(await probe.create_session()).AuthenticationToken for _ in range(4)]
        with pytest.raises(ua.uaerrors.BadSessionIdInvalid):
            await probe.activate(tokens[0])
        await probe.activate(tokens[1])
        await probe.activate(tokens[3])
    finally:
        probe.close()


async def test_srv28_too_many_sessions_when_all_are_activated(srv: Server) -> None:
    """Part 4, 5.7.2.1: with no unactivated Session to evict, CreateSession fails."""
    srv.iserver.session_manager.max_sessions = 2
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        await _activated(probe)
        await _activated(probe)
        with pytest.raises(ua.uaerrors.BadTooManySessions):
            await probe.create_session()
    finally:
        probe.close()


@pytest.mark.parametrize("nonce", [b"", b"x", bytes(31), bytes(129)], ids=["empty", "one", "31", "129"])
async def test_srv29_wrong_client_nonce_length_is_nonce_invalid(srv: Server, nonce: bytes) -> None:
    """Part 4, 5.7.2.2: the ClientNonce is 32 to 128 bytes."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        with pytest.raises(ua.uaerrors.BadNonceInvalid):
            await probe.create_session(client_nonce=nonce)
    finally:
        probe.close()


async def test_srv31_close_unknown_session_is_session_id_invalid(srv: Server) -> None:
    """Part 4, 5.7.4.2: CloseSession of a Session that does not exist fails."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        with pytest.raises(ua.uaerrors.BadSessionIdInvalid):
            await probe.close_session(ua.NodeId(bytes(32), 0, ua.NodeIdType.ByteString))
        token = await _activated(probe)
        await probe.close_session(token)
        with pytest.raises(ua.uaerrors.BadSessionIdInvalid):
            await probe.close_session(token)
    finally:
        probe.close()


async def test_srv35_max_request_message_size_matches_the_transport_limit(srv: Server) -> None:
    """Part 4, 5.7.2.2: MaxRequestMessageSize tells the client what the server accepts."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        result = await probe.create_session()
        assert result.MaxRequestMessageSize == srv.limits.max_message_size
    finally:
        probe.close()


async def test_srv42_activated_session_survives_channel_loss_until_timeout(srv: Server) -> None:
    """Part 4, 5.7.2.1 and Part 6, 6.7: after a channel is lost the client can reactivate its Session."""
    url = srv.endpoint.geturl()
    first = await SessionProbe.open(url)
    token = await _activated(first)
    first.close()
    await asyncio.sleep(0.3)
    second = await SessionProbe.open(url)
    try:
        await second.activate(token)
        assert await second.read_server_state(token) == ua.ServerState.Running
    finally:
        second.close()


async def _subscription_ids(srv: Server) -> set[int]:
    return set(srv.iserver.subscription_service.subscriptions)


async def _create_subscription(probe: SessionProbe, token: ua.NodeId) -> int:
    request = ua.CreateSubscriptionRequest()
    request.Parameters = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=1000, RequestedLifetimeCount=3000, RequestedMaxKeepAliveCount=100
    )
    response = await probe.send(token, request, ua.CreateSubscriptionResponse)
    return response.Parameters.SubscriptionId


async def test_srv42_session_timeout_keeps_its_subscriptions(srv: Server) -> None:
    """Part 4, 5.7.2.1: a Session the server ends leaves its Subscriptions to expire on their own."""
    srv.iserver.min_session_timeout_ms = 100
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = (await probe.create_session(timeout_ms=300)).AuthenticationToken
        await probe.activate(token)
        sub_id = await _create_subscription(probe, token)
        await wait_until(lambda: token not in srv.iserver.session_manager.sessions)
        with pytest.raises(ua.uaerrors.BadSessionIdInvalid):
            await probe.read_server_state(token)
        assert sub_id in await _subscription_ids(srv)
    finally:
        probe.close()


async def test_srv42_close_session_deletes_subscriptions_only_when_asked(srv: Server) -> None:
    """Part 4, 5.7.4.2: DeleteSubscriptions decides whether CloseSession deletes the Subscriptions."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        keep_token = await _activated(probe)
        keep_id = await _create_subscription(probe, keep_token)
        drop_token = await _activated(probe)
        drop_id = await _create_subscription(probe, drop_token)
        await probe.close_session(keep_token, delete_subscriptions=False)
        await probe.close_session(drop_token, delete_subscriptions=True)
        remaining = await _subscription_ids(srv)
        assert keep_id in remaining
        assert drop_id not in remaining
    finally:
        probe.close()


async def test_srv8_watchdog_rereads_the_revised_timeout(srv: Server) -> None:
    """Part 4, 5.7.2.2: the Session ends when it is idle for its revised timeout, as it stands now."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        session = srv.iserver.session_manager.sessions[token]
        session.revised_timeout_ms = 200
        await wait_until(lambda: token not in srv.iserver.session_manager.sessions)
        with pytest.raises(ua.uaerrors.BadSessionIdInvalid):
            await probe.read_server_state(token)
    finally:
        probe.close()


async def test_srv82_close_listener_gets_the_timeout_reason(srv: Server) -> None:
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        session = srv.iserver.session_manager.sessions[token]
        reasons: list[int] = []
        session.services.add_close_listener(lambda internal, reason: reasons.append(reason.value))
        session.revised_timeout_ms = 200
        await wait_until(lambda: reasons == [ua.StatusCodes.BadTimeout])
    finally:
        probe.close()


async def test_srv40_in_process_session_has_the_abstract_session_signatures() -> None:
    """The service set of the in-process session is that of AbstractSession."""
    for name in ("transfer_subscriptions", "create_subscription"):
        expected = list(inspect.signature(getattr(AbstractSession, name)).parameters)
        assert list(inspect.signature(getattr(InternalSession, name)).parameters)[: len(expected)] == expected
    assert list(inspect.signature(InternalSession.transfer_subscriptions).parameters) == list(
        inspect.signature(AbstractSession.transfer_subscriptions).parameters
    )


"""Publish requests and the retransmission queue belong to the Session (Part 4, 5.14.5, 5.14.1.1, 5.7)."""


async def _subscription(probe: SessionProbe, token: ua.NodeId, interval: float = 100) -> int:
    request = ua.CreateSubscriptionRequest()
    request.Parameters = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=interval,
        RequestedLifetimeCount=3000,
        RequestedMaxKeepAliveCount=100,
        PublishingEnabled=True,
    )
    return (await probe.send(token, request, ua.CreateSubscriptionResponse)).Parameters.SubscriptionId


def _publish(probe: SessionProbe, token: ua.NodeId) -> asyncio.Task[ua.PublishResponse]:
    return asyncio.create_task(probe.send(token, ua.PublishRequest(), ua.PublishResponse))


async def _wait_for(task: asyncio.Task[ua.PublishResponse]) -> Exception | ua.PublishResponse:
    try:
        return await asyncio.wait_for(task, 2)
    except TimeoutError:
        raise
    except Exception as error:
        return error


async def _queue_publish_requests(probe: SessionProbe, token: ua.NodeId, count: int) -> list[asyncio.Task]:
    first = _publish(probe, token)
    await first
    tasks = [_publish(probe, token) for _ in range(count)]
    await asyncio.sleep(0.3)
    return tasks


@pytest.mark.parametrize("limit", [None, 3])
async def test_srv30_publish_limit_is_per_session_and_configurable(srv: Server, limit: int | None) -> None:
    """Part 4, 5.14.5.1: the request over the limit is answered with Bad_TooManyPublishRequests for the oldest."""
    if limit is not None:
        srv.iserver.session_manager.max_publish_requests_per_session = limit
    queued = limit or 10
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        await _subscription(probe, token)
        tasks = await _queue_publish_requests(probe, token, queued + 1)
        done = [task for task in tasks if task.done()]
        assert len(done) == 1
        assert done[0] is tasks[0]
        with pytest.raises(ua.uaerrors.BadTooManyPublishRequests):
            done[0].result()
        for task in tasks[1:]:
            task.cancel()
    finally:
        probe.close()


async def test_srv30_close_session_answers_queued_publish_with_session_closed(srv: Server) -> None:
    """Part 4, 5.7.4.2: CloseSession answers the Publish requests that are still queued."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        await _subscription(probe, token)
        tasks = await _queue_publish_requests(probe, token, 2)
        await probe.close_session(token)
        for task in tasks:
            assert isinstance(await _wait_for(task), ua.uaerrors.BadSessionClosed)
    finally:
        probe.close()


async def test_srv30_deleting_the_last_subscription_flushes_publish_requests_with_no_subscription(srv: Server) -> None:
    """Part 4, 5.14.8.1: with no Subscription left, queued Publish requests get Bad_NoSubscription."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        sub_id = await _subscription(probe, token)
        tasks = await _queue_publish_requests(probe, token, 2)
        request = ua.DeleteSubscriptionsRequest()
        request.Parameters.SubscriptionIds = [sub_id]
        await probe.send(token, request, ua.DeleteSubscriptionsResponse)
        for task in tasks:
            assert isinstance(await _wait_for(task), ua.uaerrors.BadNoSubscription)
    finally:
        probe.close()


async def test_srv30_queued_publish_requests_get_secure_channel_closed_after_a_move(srv: Server) -> None:
    """Part 4, 5.7.3.1: Publish requests of the channel a Session leaves are answered, not left hanging."""
    url = srv.endpoint.geturl()
    old, new = await SessionProbe.open(url), await SessionProbe.open(url)
    try:
        token = await _activated(old)
        await _subscription(old, token)
        tasks = await _queue_publish_requests(old, token, 2)
        await new.activate(token)
        for task in tasks:
            assert isinstance(await _wait_for(task), ua.uaerrors.BadSecureChannelClosed)
    finally:
        old.close()
        new.close()


async def test_srv30_cancel_answers_queued_publish_with_cancelled_by_client(srv: Server) -> None:
    """Part 4, 5.7.5: Cancel answers the queued Publish request with that RequestHandle and counts it."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        await _subscription(probe, token)
        await _publish(probe, token)
        task = _publish(probe, token)
        await asyncio.sleep(0.2)
        protocol = probe.client.uaclient.protocol
        assert protocol is not None
        request = ua.CancelRequest()
        request.Parameters.RequestHandle = protocol._request_handle
        response = await probe.send(token, request, ua.CancelResponse)
        assert response.Parameters.CancelCount == 1
        assert isinstance(await _wait_for(task), ua.uaerrors.BadRequestCancelledByClient)
        request.Parameters.RequestHandle = 999_999
        assert (await probe.send(token, request, ua.CancelResponse)).Parameters.CancelCount == 0
    finally:
        probe.close()


async def _republish_has_data(probe: SessionProbe, token: ua.NodeId, sub_id: int, sequence_number: int) -> bool:
    request = ua.RepublishRequest()
    request.Parameters = ua.RepublishParameters(SubscriptionId=sub_id, RetransmitSequenceNumber=sequence_number)
    try:
        response = await probe.send(token, request, ua.RepublishResponse)
    except ua.uaerrors.BadMessageNotAvailable:
        return False
    return bool(response.NotificationMessage.NotificationData)


async def test_srv30_retransmission_queue_is_bounded_per_session(srv: Server) -> None:
    """Part 4, 5.14.1.1: a Session keeps a bounded number of unacknowledged messages, the oldest are dropped."""
    variable = await srv.nodes.objects.add_variable(2, "Counter", 0)
    await variable.set_writable()
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        sub_id = await _subscription(probe, token, interval=50)
        item = ua.MonitoredItemCreateRequest()
        item.ItemToMonitor.NodeId = variable.nodeid
        item.ItemToMonitor.AttributeId = ua.AttributeIds.Value
        item.MonitoringMode = ua.MonitoringMode.Reporting
        item.RequestedParameters.ClientHandle = 1
        item.RequestedParameters.SamplingInterval = 0
        item.RequestedParameters.QueueSize = 10
        item.RequestedParameters.DiscardOldest = True
        create = ua.CreateMonitoredItemsRequest()
        create.Parameters = ua.CreateMonitoredItemsParameters(
            SubscriptionId=sub_id, TimestampsToReturn=ua.TimestampsToReturn.Both, ItemsToCreate=[item]
        )
        await probe.send(token, create, ua.CreateMonitoredItemsResponse)
        numbers: list[int] = []
        for value in range(1, 31):
            await variable.write_value(value)
            response = await asyncio.wait_for(probe.send(token, ua.PublishRequest(), ua.PublishResponse), 3)
            if response.Parameters.NotificationMessage.NotificationData:
                numbers.append(response.Parameters.NotificationMessage.SequenceNumber)
        assert len(numbers) > 25
        assert not await _republish_has_data(probe, token, sub_id, numbers[0])
        assert await _republish_has_data(probe, token, sub_id, numbers[-1])
    finally:
        probe.close()


async def test_srv82_close_listeners_run_when_the_session_closes(srv: Server) -> None:
    """A listener registered on the services of a Session runs once when the Session closes."""
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        session = srv.iserver.session_manager.sessions[token]
        closed: list[ua.NodeId] = []
        reasons: list[int] = []

        async def listener(internal: InternalSession, reason: ua.StatusCode) -> None:
            closed.append(internal.session_id)
            reasons.append(reason.value)

        session.services.add_close_listener(listener)
        assert not closed
        await probe.close_session(token)
        await wait_until(lambda: closed == [session.id])
        assert reasons == [ua.StatusCodes.Good]
    finally:
        probe.close()


async def test_srv82_close_listener_error_does_not_stop_the_others(srv: Server) -> None:
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = await _activated(probe)
        session = srv.iserver.session_manager.sessions[token]
        calls: list[str] = []

        def failing(internal: InternalSession, reason: ua.StatusCode) -> None:
            calls.append("failing")
            raise RuntimeError("listener failure")

        session.services.add_close_listener(failing)
        session.services.add_close_listener(lambda internal, reason: calls.append("second"))
        await probe.close_session(token)
        await wait_until(lambda: calls == ["failing", "second"])
    finally:
        probe.close()


async def test_current_call_session_is_set_during_a_method_call() -> None:
    """The callback of a Method sees the Session, its user and the security mode of its channel."""
    from enginir_opcua import Client
    from enginir_opcua.server.internal_session import current_call_session
    from enginir_opcua.server.user_managers import PermissiveUserManager

    srv = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await srv.start()

    seen: list[tuple[object, ua.MessageSecurityMode, bool]] = []

    async def callback(parent: ua.NodeId) -> list[ua.Variant]:
        session = current_call_session.get()
        assert session is not None
        seen.append((session.user.role, session.channel_security_mode, session.external))
        return []

    method = await srv.nodes.objects.add_method(2, "WhoCalls", callback, [], [])
    try:
        async with Client(srv.endpoint.geturl().replace("opc.tcp://", "opc.tcp://admin@")) as client:
            await client.nodes.objects.call_method(method.nodeid)
    finally:
        await srv.stop()
    assert len(seen) == 1
    assert seen[0][0] == UserRole.Admin
    assert seen[0][1] == ua.MessageSecurityMode.None_
    assert seen[0][2] is True
    assert current_call_session.get() is None

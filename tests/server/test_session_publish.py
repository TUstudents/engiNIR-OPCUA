"""Publish requests and the retransmission queue belong to the Session (Part 4, 5.14.5, 5.14.1.1, 5.7)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Server, ua
from tests.conftest import find_free_port
from tests.harness import SessionProbe

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def srv() -> AsyncIterator[Server]:
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await server.start()
    yield server
    await server.stop()


async def _activated(probe: SessionProbe) -> ua.NodeId:
    token = (await probe.create_session()).AuthenticationToken
    await probe.activate(token)
    return token


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

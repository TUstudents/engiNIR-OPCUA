import contextlib
from collections import deque
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common import utils
from enginir_opcua.server.address_space import AddressSpace
from enginir_opcua.server.internal_server import InternalServer
from enginir_opcua.server.internal_subscription import (
    MAX_SEQUENCE_NUMBER,
    InternalSubscription,
    SubscriptionState,
)

SESSION = ua.NodeId(1, 1)


class Wire:
    """A Publish request queue and the responses sent through it, standing in for the Session."""

    def __init__(self) -> None:
        self.requests: deque[Any] = deque()
        self.sent: list[ua.PublishResult] = []
        self.expired: list[ua.PublishResult] = []

    def add_request(self, count: int = 1) -> None:
        self.requests.extend(object() for _ in range(count))

    def take(self, _subscription_id: int) -> Any:
        return self.requests.popleft() if self.requests else None

    async def send(self, result: ua.PublishResult, _request: Any = None) -> None:
        self.sent.append(result)

    def on_expired(self, _sub: InternalSubscription, notice: ua.PublishResult) -> None:
        self.expired.append(notice)


def make_sub(
    wire: Wire,
    keep_alive: int = 3,
    lifetime: int = 9,
    max_notifications: int = 10_000,
    enabled: bool = True,
    priority: int = 0,
) -> InternalSubscription:
    data = ua.CreateSubscriptionResult(
        SubscriptionId=78,
        RevisedPublishingInterval=50,
        RevisedLifetimeCount=lifetime,
        RevisedMaxKeepAliveCount=keep_alive,
    )
    return InternalSubscription(
        data,
        AddressSpace(),
        wire.send,
        SESSION,
        request_callback=wire.take,
        expire_callback=wire.on_expired,
        publishing_enabled=enabled,
        max_notifications_per_publish=max_notifications,
        priority=priority,
    )


async def add_change(sub: InternalSubscription, mid: int = 1, value: int = 1) -> None:
    item = ua.MonitoredItemNotification(ClientHandle=mid, Value=ua.DataValue(ua.Variant(value, ua.VariantType.Int32)))
    await sub.enqueue_datachange_event(mid, item, 0)


def is_keepalive(result: ua.PublishResult) -> bool:
    return not result.NotificationMessage.NotificationData


async def test_srv11_first_message_is_a_keepalive_with_sequence_number_1() -> None:
    """Part 4, 5.14.1.2: the first message is sent at the end of the first publishing cycle."""
    wire = Wire()
    sub = make_sub(wire)
    wire.add_request()
    await sub.timer_expired()
    assert len(wire.sent) == 1
    assert is_keepalive(wire.sent[0])
    assert wire.sent[0].NotificationMessage.SequenceNumber == 1
    assert wire.sent[0].AvailableSequenceNumbers == []


async def test_srv11_keepalive_does_not_consume_a_sequence_number() -> None:
    """Part 4, 5.14.1.1: a keep-alive carries the number the next NotificationMessage will use."""
    wire = Wire()
    sub = make_sub(wire, keep_alive=1)
    wire.add_request(3)
    await sub.timer_expired()
    await add_change(sub)
    await sub.timer_expired()
    await sub.timer_expired()
    first, data, keepalive = wire.sent
    assert first.NotificationMessage.SequenceNumber == 1
    assert data.NotificationMessage.SequenceNumber == 1
    assert data.AvailableSequenceNumbers == [1]
    assert keepalive.NotificationMessage.SequenceNumber == 2


@pytest.mark.parametrize("keep_alive", [1, 3])
async def test_srv11_keepalive_is_sent_after_max_keepalive_count_silent_cycles(keep_alive: int) -> None:
    """Part 4, 5.14.1.2: a keep-alive is sent when the keep-alive count expires without notifications."""
    wire = Wire()
    sub = make_sub(wire, keep_alive=keep_alive, lifetime=100)
    wire.add_request(10)
    await sub.timer_expired()
    wire.sent.clear()
    for _ in range(keep_alive - 1):
        await sub.timer_expired()
    assert wire.sent == []
    await sub.timer_expired()
    assert len(wire.sent) == 1
    assert is_keepalive(wire.sent[0])


async def test_srv11_late_subscription_answers_the_next_publish_at_once() -> None:
    """Part 4, 5.14.1.2: without a queued request the subscription goes LATE and uses the next request at once."""
    wire = Wire()
    sub = make_sub(wire)
    await add_change(sub)
    await sub.timer_expired()
    assert sub.state is SubscriptionState.LATE
    assert wire.sent == []
    assert await sub.publish_results(object()) is True
    assert sub.state is SubscriptionState.NORMAL
    assert wire.sent[0].NotificationMessage.SequenceNumber == 1
    assert len(wire.sent[0].NotificationMessage.NotificationData) == 1


async def test_srv11_publish_request_is_not_consumed_when_the_subscription_is_not_late() -> None:
    """Part 4, 5.14.1.2: a Publish request that arrives in the NORMAL state is queued, not used."""
    wire = Wire()
    sub = make_sub(wire)
    assert await sub.publish_results(object()) is False
    assert wire.sent == []


async def test_srv11_timer_runs_for_an_interval_that_was_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.14.2.2: the revised interval is always positive, so the publishing timer always runs."""
    server = InternalServer()
    server.min_publishing_interval_ms = 5
    params = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=0,
        RequestedLifetimeCount=30,
        RequestedMaxKeepAliveCount=10,
        PublishingEnabled=True,
    )
    wire = Wire()
    result = await server.subscription_service.create_subscription(params, wire.send, SESSION, wire.take)
    sub = server.subscription_service.subscriptions[result.SubscriptionId]
    assert sub._task is not None
    await sub.stop()


async def test_srv11_subscription_closes_after_lifetime_without_publish_requests() -> None:
    """Part 4, 5.14.1.2: the lifetime counter counts timer expirations without a Publish request."""
    wire = Wire()
    sub = make_sub(wire, keep_alive=1, lifetime=3)
    await sub.timer_expired()
    await sub.timer_expired()
    assert wire.expired == []
    await sub.timer_expired()
    assert len(wire.expired) == 1
    notice = wire.expired[0].NotificationMessage
    assert isinstance(notice.NotificationData[0], ua.StatusChangeNotification)
    assert notice.NotificationData[0].Status.value == ua.StatusCodes.BadTimeout
    assert notice.SequenceNumber == 1


async def test_srv11_a_taken_publish_request_resets_the_lifetime_counter() -> None:
    """Part 4, 5.14.1.2: taking a Publish request resets the lifetime counter."""
    wire = Wire()
    sub = make_sub(wire, keep_alive=1, lifetime=3)
    for _ in range(10):
        wire.add_request()
        await sub.timer_expired()
    assert wire.expired == []


async def call_service(server: InternalServer, operation: str, subscription_id: int) -> None:
    service = server.subscription_service
    if operation == "modify":
        service.modify_subscription(
            ua.ModifySubscriptionParameters(
                SubscriptionId=subscription_id,
                RequestedPublishingInterval=3_600_000,
                RequestedLifetimeCount=3,
                RequestedMaxKeepAliveCount=1,
            ),
            SESSION,
        )
    elif operation == "republish":
        service.republish(ua.RepublishParameters(SubscriptionId=subscription_id, RetransmitSequenceNumber=1), SESSION)
    else:
        await service.set_publishing_mode(
            ua.SetPublishingModeParameters(PublishingEnabled=True, SubscriptionIds=[subscription_id]), SESSION
        )


@pytest.mark.parametrize("operation", ["modify", "republish", "set_publishing_mode"])
async def test_srv33_service_calls_reset_the_lifetime_counter(operation: str) -> None:
    """Part 4, 5.14.1.1: every Subscription service call resets the lifetime counter."""
    server = InternalServer()
    wire = Wire()
    params = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=3_600_000,
        RequestedLifetimeCount=3,
        RequestedMaxKeepAliveCount=1,
        PublishingEnabled=True,
    )
    created = await server.subscription_service.create_subscription(params, wire.send, SESSION, wire.take)
    sub = server.subscription_service.subscriptions[created.SubscriptionId]
    await sub.timer_expired()
    await sub.timer_expired()
    with contextlib.suppress(utils.ServiceError):
        await call_service(server, operation, created.SubscriptionId)
    await sub.timer_expired()
    await sub.timer_expired()
    assert created.SubscriptionId in server.subscription_service.subscriptions
    await sub.timer_expired()
    assert created.SubscriptionId not in server.subscription_service.subscriptions


async def test_srv11_expired_subscription_leaves_its_notice_for_the_owners_next_publish() -> None:
    """Part 4, 5.14.1.1: the Bad_Timeout StatusChangeNotification is sent with the owner's next Publish."""
    server = InternalServer()
    wire = Wire()
    params = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=3_600_000,
        RequestedLifetimeCount=3,
        RequestedMaxKeepAliveCount=1,
        PublishingEnabled=True,
    )
    created = await server.subscription_service.create_subscription(params, wire.send, SESSION, wire.take)
    sub = server.subscription_service.subscriptions[created.SubscriptionId]
    for _ in range(3):
        await sub.timer_expired()
    assert created.SubscriptionId not in server.subscription_service.subscriptions
    assert wire.sent == []
    assert await server.subscription_service.on_publish_request(SESSION, object()) is True
    status = wire.sent[0].NotificationMessage.NotificationData[0]
    assert status.Status.value == ua.StatusCodes.BadTimeout
    assert await server.subscription_service.on_publish_request(SESSION, object()) is False


async def test_srv11_sequence_number_rolls_over_to_1() -> None:
    """Part 4, 5.14.1.1: sequence numbers continue at 1 after the largest UInt32."""
    wire = Wire()
    sub = make_sub(wire, keep_alive=1)
    sub._sequence = MAX_SEQUENCE_NUMBER
    wire.add_request(3)
    await add_change(sub)
    await sub.timer_expired()
    await add_change(sub)
    await sub.timer_expired()
    assert [r.NotificationMessage.SequenceNumber for r in wire.sent] == [MAX_SEQUENCE_NUMBER, 1]


async def test_srv11_max_notifications_per_publish_and_more_notifications() -> None:
    """Part 4, 5.14.2.2: a message carries at most MaxNotificationsPerPublish and says when more are ready."""
    wire = Wire()
    sub = make_sub(wire, max_notifications=2)
    for mid in range(1, 6):
        await add_change(sub, mid=mid)
    wire.add_request()
    await sub.timer_expired()
    assert len(wire.sent) == 1
    assert len(wire.sent[0].NotificationMessage.NotificationData[0].MonitoredItems) == 2
    assert wire.sent[0].MoreNotifications is True
    wire.add_request(2)
    assert await sub.publish_results(wire.requests.popleft()) is True
    assert sub.state is SubscriptionState.NORMAL
    sizes = [len(r.NotificationMessage.NotificationData[0].MonitoredItems) for r in wire.sent]
    assert sizes == [2, 2, 1]
    assert [r.MoreNotifications for r in wire.sent] == [True, True, False]


async def test_srv11_publishing_disabled_sends_keepalives_and_keeps_data() -> None:
    """Part 4, 5.14.4.2: disabled publishing stops notifications but not keep-alives."""
    wire = Wire()
    sub = make_sub(wire, keep_alive=1, enabled=False)
    await add_change(sub)
    wire.add_request(3)
    await sub.timer_expired()
    await sub.timer_expired()
    assert all(is_keepalive(r) for r in wire.sent)
    assert len(wire.sent) == 2
    await sub.set_publishing_mode(True)
    await sub.timer_expired()
    assert not is_keepalive(wire.sent[-1])


async def test_srv36_higher_priority_is_served_first() -> None:
    """Part 4, 5.14.2.2: the server gives the next Publish request to the subscription with the higher priority."""
    server = InternalServer()
    wire = Wire()
    subs = []
    for priority in (1, 200, 100):
        params = ua.CreateSubscriptionParameters(
            RequestedPublishingInterval=3_600_000,
            RequestedLifetimeCount=30,
            RequestedMaxKeepAliveCount=10,
            PublishingEnabled=True,
            Priority=priority,
        )
        created = await server.subscription_service.create_subscription(params, wire.send, SESSION, wire.take)
        sub = server.subscription_service.subscriptions[created.SubscriptionId]
        await sub.timer_expired()
        subs.append(sub)
    assert [s.state for s in subs] == [SubscriptionState.LATE] * 3
    for _ in range(3):
        assert await server.subscription_service.on_publish_request(SESSION, object()) is True
    assert [r.SubscriptionId for r in wire.sent] == [
        subs[1].data.SubscriptionId,
        subs[2].data.SubscriptionId,
        subs[0].data.SubscriptionId,
    ]

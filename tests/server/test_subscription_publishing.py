"""Delivery of notifications by the client Subscription: queues, handlers, lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common import utils
from enginir_opcua.common.node import Node
from enginir_opcua.common.subscription import (
    DataChangeEvent,
    StatusChangeEvent,
    Subscription,
    subscription_parameters,
)
from enginir_opcua.common.subscription import SubscriptionState as ClientSubscriptionState
from enginir_opcua.observer import Observer, SubscriptionEvent
from enginir_opcua.server.address_space import AddressSpace
from enginir_opcua.server.internal_server import InternalServer
from enginir_opcua.server.internal_subscription import (
    MAX_SEQUENCE_NUMBER,
    InternalSubscription,
    SubscriptionState,
)
from tests.subscription_rig import FakeSession, data_change, message, publish_result


async def make_subscription(session: FakeSession, handler: Any = None, **kwargs: Any) -> tuple[Subscription, int]:
    sub = Subscription(session, subscription_parameters(100), handler, **kwargs)  # type: ignore[arg-type]
    await sub.init()
    assert sub.subscription_id is not None
    await sub.subscribe_data_change(Node(session, ua.NodeId(1, 1)))  # type: ignore[arg-type]
    return sub, 201


async def collect(sub: Subscription, wait: float = 0.05) -> list[Any]:
    events = []
    try:
        while (event := await sub.next_event(wait)) is not None:
            events.append(event)
    except StopAsyncIteration:
        pass
    return events


async def test_com33_unread_iterator_does_not_stop_other_subscriptions() -> None:
    """Part 4, 5.14.5: one consumer that never reads cannot hold up the delivery for another Subscription."""
    session = FakeSession()
    unread, handle = await make_subscription(session, queue_maxsize=1)
    other_events: list[Any] = []

    class Handler:
        def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
            other_events.append(val)

    other, other_handle = await make_subscription(session, Handler())
    for number in range(1, 6):
        await asyncio.wait_for(
            unread.publish_callback(
                publish_result(unread.subscription_id or 0, message(number, data_change(handle, number)))
            ),
            1,
        )
    await asyncio.wait_for(
        other.publish_callback(publish_result(other.subscription_id or 0, message(1, data_change(other_handle, 42)))), 1
    )
    await asyncio.sleep(0.05)
    assert other_events == [42]


async def test_com33_slow_async_handler_does_not_stop_other_subscriptions() -> None:
    """Part 4, 5.14.5: a handler that waits delays only its own Subscription."""
    session = FakeSession()
    gate = asyncio.Event()

    class Slow:
        async def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
            await gate.wait()

    fast_values: list[Any] = []

    class Fast:
        def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
            fast_values.append(val)

    slow, slow_handle = await make_subscription(session, Slow())
    fast, fast_handle = await make_subscription(session, Fast())
    for number in (1, 2):
        await asyncio.wait_for(
            slow.publish_callback(
                publish_result(slow.subscription_id or 0, message(number, data_change(slow_handle, number)))
            ),
            1,
        )
    await asyncio.wait_for(
        fast.publish_callback(publish_result(fast.subscription_id or 0, message(1, data_change(fast_handle, 7)))), 1
    )
    await asyncio.sleep(0.05)
    assert fast_values == [7]
    gate.set()
    slow.close("test")


async def test_inbox_overflow_drops_oldest_and_counts(caplog: pytest.LogCaptureFixture) -> None:
    """Part 4, 5.14.5: a full inbox loses its oldest message, counts it and warns."""
    session = FakeSession()
    gate = asyncio.Event()
    seen: list[Any] = []

    class Slow:
        async def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
            seen.append(val)
            await gate.wait()

    sub, handle = await make_subscription(session, Slow(), inbox_maxsize=2)
    sub.enqueue(publish_result(sub.subscription_id or 0, message(1, data_change(handle, 1))))
    await asyncio.sleep(0.05)
    with caplog.at_level(logging.WARNING):
        for number in range(2, 7):
            sub.enqueue(publish_result(sub.subscription_id or 0, message(number, data_change(handle, number))))
    assert sub.dropped_messages == 3
    assert any("dropped" in r.getMessage() for r in caplog.records)
    gate.set()
    await asyncio.sleep(0.1)
    assert seen == [1, 5, 6]
    sub.close("test")


async def test_iterator_queue_full_drops_the_oldest_and_counts() -> None:
    """Part 4, 5.14.5: an unread iterator keeps the newest events."""
    session = FakeSession()
    sub, handle = await make_subscription(session, queue_maxsize=2)
    for number in range(1, 6):
        sub.enqueue(publish_result(sub.subscription_id or 0, message(number, data_change(handle, number))))
    await asyncio.sleep(0.05)
    assert [e.value for e in await collect(sub)] == [4, 5]
    assert sub.dropped_events == 3
    sub.close("test")


async def test_com77_partial_async_handler_is_awaited() -> None:
    """A handler method that returns an awaitable without being a coroutine function is still awaited."""
    session = FakeSession()
    seen: list[Any] = []

    async def record(label: str, node: Any, val: Any, data: Any) -> None:
        seen.append((label, val))

    class Handler:
        def __init__(self) -> None:
            self.datachange_notification = functools.partial(record, "partial")

    sub, handle = await make_subscription(session, Handler())
    sub.enqueue(publish_result(sub.subscription_id or 0, message(1, data_change(handle, 5))))
    await asyncio.sleep(0.05)
    assert seen == [("partial", 5)]
    sub.close("test")


async def test_handler_missing_method_is_logged_once(caplog: pytest.LogCaptureFixture) -> None:
    """A handler without the method for an event kind loses those events with one log line."""
    session = FakeSession()

    class Handler:
        pass

    sub, handle = await make_subscription(session, Handler())
    with caplog.at_level(logging.ERROR):
        for number in (1, 2, 3):
            sub.enqueue(publish_result(sub.subscription_id or 0, message(number, data_change(handle, number))))
        await asyncio.sleep(0.05)
    assert len([r for r in caplog.records if "datachange_notification" in r.getMessage()]) == 1
    assert sub.dropped_events == 3
    sub.close("test")


async def test_unknown_client_handle_after_unsubscribe_is_not_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Part 4, 5.13.6: a notification for an item that was just removed is expected and counted."""
    session = FakeSession()
    sub, handle = await make_subscription(session)
    with caplog.at_level(logging.WARNING):
        sub.enqueue(publish_result(sub.subscription_id or 0, message(1, data_change(handle + 50, 1))))
        await asyncio.sleep(0.05)
    assert sub.unknown_handle_notifications == 1
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    sub.close("test")


async def test_com74_delete_of_unknown_subscription_unregisters_the_sink() -> None:
    """Part 4, 5.14.8: an id the server doesn't know counts as deleted and the pipeline stops serving it."""
    session = FakeSession()
    sub, _ = await make_subscription(session)
    subscription_id = sub.subscription_id
    assert subscription_id in session._subscription_callbacks
    session.delete_status = ua.StatusCode(ua.StatusCodes.BadSubscriptionIdInvalid)
    await sub.delete()
    assert subscription_id not in session._subscription_callbacks
    assert sub.state is ClientSubscriptionState.DELETED


async def test_delete_raises_other_bad_status_after_the_cleanup() -> None:
    """Part 4, 5.14.8: any other Bad status is raised, but the local cleanup is done first."""
    session = FakeSession()
    sub, _ = await make_subscription(session)
    session.delete_status = ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
    with pytest.raises(ua.UaStatusCodeError):
        await sub.delete()
    assert sub.is_deleted
    assert sub.subscription_id not in session._subscription_callbacks


async def test_close_ends_the_subscription_locally() -> None:
    """Client disconnect: iterators end, the observer hears DELETED and nothing goes to the server."""
    session = FakeSession()
    events: list[SubscriptionEvent] = []

    class Watcher(Observer):
        def on_subscription_event(self, subscription_id: int | None, event: SubscriptionEvent) -> None:
            events.append(event)

    session.observer = Watcher()
    sub, _ = await make_subscription(session)
    consumer = asyncio.create_task(collect(sub, 5))
    await asyncio.sleep(0.01)
    sub.close("client disconnect")
    assert await asyncio.wait_for(consumer, 1) == []
    assert session.deleted == []
    assert events[-1] is SubscriptionEvent.DELETED
    assert sub.state is ClientSubscriptionState.DELETED
    sub.close("again")
    assert events.count(SubscriptionEvent.DELETED) == 1
    with pytest.raises(StopAsyncIteration):
        await sub.next_event(0.1)


async def test_com75_transfer_notice_ends_the_iterator_without_recreating() -> None:
    """Part 4, 5.14.7.1: another Session owns the Subscription, so it is neither recreated nor restored."""
    session = FakeSession()
    sub, _ = await make_subscription(session)
    status = ua.StatusChangeNotification(Status=ua.StatusCode(ua.StatusCodes.GoodSubscriptionTransferred))
    sub.enqueue(publish_result(sub.subscription_id or 0, message(1, status)))
    first = await sub.next_event(1)
    assert isinstance(first, StatusChangeEvent)
    with pytest.raises(StopAsyncIteration):
        await sub.next_event(1)
    assert sub.state is ClientSubscriptionState.TRANSFERRED
    assert not sub.is_stale(1.5)
    created = len(session.created)
    await sub.recreate()
    await sub.restore()
    assert len(session.created) == created


async def test_com75_bad_timeout_status_marks_the_subscription_lost() -> None:
    """Part 4, 5.14.7.1: after Bad_Timeout the server has deleted the Subscription; the watchdog recreates it."""
    session = FakeSession()
    sub, _ = await make_subscription(session)
    status = ua.StatusChangeNotification(Status=ua.StatusCode(ua.StatusCodes.BadTimeout))
    sub.enqueue(publish_result(sub.subscription_id or 0, message(1, status)))
    assert isinstance(await sub.next_event(1), StatusChangeEvent)
    assert sub.state is ClientSubscriptionState.LOST
    assert sub.is_stale(1.5)
    old_id = sub.subscription_id
    await sub.recreate()
    assert sub.subscription_id != old_id
    assert sub.state is ClientSubscriptionState.ACTIVE
    assert not sub.is_stale(1.5)


async def test_in_process_subscription_rejects_update_and_set_publishing_mode(opc) -> None:
    """The in-process Subscription of the server has no Publish pipeline to configure."""
    if opc.opc is not opc.server:
        pytest.skip("client subscriptions support these operations")
    sub = await opc.server.create_subscription(100, None)
    with pytest.raises(ua.uaerrors.UaError):
        await sub.set_publishing_mode(False)
    with pytest.raises(ua.uaerrors.UaError):
        await sub.update(ua.ModifySubscriptionParameters())
    await sub.delete()


def test_common_subscription_does_not_import_the_client_session() -> None:
    """Layering: common code depends on no client module at run time."""
    import enginir_opcua.common.subscription as module

    assert "UaSession" not in vars(module)
    assert DataChangeEvent is not None


async def make(session: FakeSession, **kwargs: Any) -> Subscription:
    sub = Subscription(session, subscription_parameters(100), **kwargs)  # type: ignore[arg-type]
    await sub.init()
    await sub.subscribe_data_change(Node(session, ua.NodeId(1, 1)))  # type: ignore[arg-type]
    return sub


def push(sub: Subscription, number: int, value: Any = None, available: list[int] | None = None) -> None:
    notifications = [] if value is None else [data_change(201, value)]
    sub.enqueue(publish_result(sub.subscription_id or 0, message(number, *notifications), available))


async def values(sub: Subscription, wait: float = 0.05) -> list[DataChangeEvent]:
    events: list[DataChangeEvent] = []
    while (event := await sub.next_event(wait)) is not None:
        assert isinstance(event, DataChangeEvent)
        events.append(event)
    return events


async def test_com68_keep_alive_does_not_move_the_expected_number() -> None:
    """Part 4, 5.14.1.1: a keep-alive carries the number of the next message and consumes nothing."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1)
    push(sub, 1)
    push(sub, 1, "first")
    events = await values(sub)
    assert [e.value for e in events] == ["first"]
    assert session.republished == []
    assert sub.last_sequence_number == 1


async def test_com68_only_keep_alives_leave_no_last_sequence_number() -> None:
    """Part 4, 5.14.1.1: with no message received, a later Republish must start at the first number."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1)
    await asyncio.sleep(0.05)
    assert sub.last_sequence_number is None


async def test_com76_duplicate_message_is_delivered_once() -> None:
    """Part 4, 5.14.1.1: a number seen twice is one message."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1, "a")
    push(sub, 2, "b")
    push(sub, 1, "a")
    events = await values(sub)
    assert [e.value for e in events] == ["a", "b"]
    assert sub.duplicates == 1


async def test_com76_gap_is_filled_by_republish() -> None:
    """Part 4, 5.14.6: a missing number that the server still lists is fetched, in order, and acknowledged."""
    session = FakeSession()
    sub = await make(session)
    session.messages[2] = message(2, data_change(201, "b"))
    push(sub, 1, "a", available=[1])
    push(sub, 3, "c", available=[2, 3])
    events = await values(sub)
    assert [e.value for e in events] == ["a", "b", "c"]
    assert [e.replayed for e in events] == [False, True, False]
    assert session.republished == [2]
    assert session.acknowledged == [(sub.subscription_id, 2)]


async def test_com76_keep_alive_ahead_of_expected_triggers_republish() -> None:
    """Part 4, 5.14.1.1: a keep-alive number above the expected one shows a missing message."""
    session = FakeSession()
    sub = await make(session)
    session.messages[2] = message(2, data_change(201, "b"))
    push(sub, 1, "a", available=[1])
    push(sub, 3, available=[2])
    events = await values(sub)
    assert [e.value for e in events] == ["a", "b"]


async def test_com76_numbers_the_server_does_not_list_are_lost() -> None:
    """Part 4, 5.14.1.1: a number missing from AvailableSequenceNumbers can't be fetched; it is counted as lost."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1, "a", available=[1])
    push(sub, 3, "c", available=[3])
    events = await values(sub)
    assert [e.value for e in events] == ["a", "c"]
    assert session.republished == []
    assert sub.lost_messages == 1


async def test_com76_sequence_wrap_to_one() -> None:
    """Part 4, 5.14.1.1: after 4294967295 the numbers continue at 1."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 4294967295, "last")
    push(sub, 1, "wrapped")
    events = await values(sub)
    assert [e.value for e in events] == ["last", "wrapped"]
    assert session.republished == []
    assert sub.lost_messages == 0


async def test_com76_republish_loop_is_bounded() -> None:
    """A huge gap never keeps the client in a Republish loop."""
    session = FakeSession()
    sub = await make(session, max_republish=3)
    for n in range(2, 12):
        session.messages[n] = message(n, data_change(201, n))
    push(sub, 1, 1, available=[1])
    push(sub, 12, 12, available=list(range(2, 13)))
    events = await values(sub)
    assert len(session.republished) == 3
    assert [e.value for e in events] == [1, 2, 3, 4, 12]
    assert sub.lost_messages == 7


async def test_com76_gap_arithmetic_is_not_a_loop() -> None:
    """A bogus number far ahead is counted, not iterated."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1, "a", available=[1])
    push(sub, 2_000_000_000, "far", available=[])
    events = await values(sub)
    assert [e.value for e in events] == ["a", "far"]
    assert sub.lost_messages == 2_000_000_000 - 2


async def test_com71_recreate_resets_sequence_tracking() -> None:
    """Part 4, 5.14.2: a new Subscription numbers its messages from 1 again."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1, "a")
    push(sub, 2, "b")
    await values(sub)
    await sub.recreate()
    push(sub, 1, "again")
    events = await values(sub)
    assert [e.value for e in events] == ["again"]
    assert session.republished == []
    assert sub.duplicates == 0


async def test_restore_republishes_from_the_expected_number_and_acknowledges() -> None:
    """Part 4, 5.14.7.4 and 5.14.6: after a transfer the messages the server kept are fetched and acknowledged."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1, "a")
    push(sub, 2, "b")
    await values(sub)
    session.messages[3] = message(3, data_change(201, "c"))
    session.messages[4] = message(4, data_change(201, "d"))
    session.transfer_result = ua.TransferResult(
        StatusCode=ua.StatusCode(ua.StatusCodes.Good), AvailableSequenceNumbers=[3, 4]
    )
    await sub.restore()
    events = await values(sub)
    assert [e.value for e in events] == ["c", "d"]
    assert all(e.replayed for e in events)
    assert session.republished[:2] == [3, 4]
    assert session.acknowledged == [(sub.subscription_id, 3), (sub.subscription_id, 4)]


async def test_restore_recreates_when_a_listed_message_cannot_be_fetched() -> None:
    """Part 4, 6.7: a hole in the data is not silent; the Subscription is recreated to get fresh values."""
    session = FakeSession()
    sub = await make(session)
    push(sub, 1, "a")
    await values(sub)
    session.transfer_result = ua.TransferResult(
        StatusCode=ua.StatusCode(ua.StatusCodes.Good), AvailableSequenceNumbers=[2]
    )
    created = len(session.created)
    await sub.restore()
    assert len(session.created) == created + 1


ALICE = ua.NodeId(1, 1)
BOB = ua.NodeId(2, 1)


@dataclass
class Setup:
    iserver: InternalServer
    sub: InternalSubscription
    sent: list[ua.PublishResult]

    @property
    def subscription_id(self) -> int:
        return self.sub.data.SubscriptionId

    async def send_data(self, count: int) -> None:
        for mid in range(count):
            item = ua.MonitoredItemNotification(
                ClientHandle=mid, Value=ua.DataValue(ua.Variant(mid, ua.VariantType.Int32))
            )
            await self.sub.enqueue_datachange_event(mid, item, 0)
            await self.sub.timer_expired()


@pytest.fixture
async def setup() -> AsyncIterator[Setup]:
    iserver = InternalServer()
    sent: list[ua.PublishResult] = []

    async def send(result: ua.PublishResult, _request: Any = None) -> None:
        sent.append(result)

    params = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=3_600_000,
        RequestedLifetimeCount=300,
        RequestedMaxKeepAliveCount=100,
        PublishingEnabled=True,
    )
    created = await iserver.subscription_service.create_subscription(params, send, ALICE, lambda _id: object())
    sub = iserver.subscription_service.subscriptions[created.SubscriptionId]
    yield Setup(iserver, sub, sent)
    await sub.stop()


def republish(setup: Setup, session: ua.NodeId, subscription_id: int, number: int) -> ua.NotificationMessage:
    params = ua.RepublishParameters(SubscriptionId=subscription_id, RetransmitSequenceNumber=number)
    return setup.iserver.subscription_service.republish(params, session)


async def test_srv12_republish_does_not_remove_the_message(setup: Setup) -> None:
    """Part 4, 5.14.6: a message leaves the retransmission queue only when it is acknowledged."""
    await setup.send_data(2)
    first = republish(setup, ALICE, setup.subscription_id, 1)
    again = republish(setup, ALICE, setup.subscription_id, 1)
    assert first.SequenceNumber == 1
    assert again.SequenceNumber == 1
    assert again.PublishTime == setup.sent[0].NotificationMessage.PublishTime
    assert list(setup.sub.available_sequence_numbers()) == [1, 2]


async def test_srv12_republish_unknown_is_message_not_available(setup: Setup) -> None:
    """Part 4, 5.14.6: asking for a message that is not in the queue is Bad_MessageNotAvailable."""
    await setup.send_data(1)
    with pytest.raises(utils.ServiceError) as error:
        republish(setup, ALICE, setup.subscription_id, 99)
    assert error.value.code == ua.StatusCodes.BadMessageNotAvailable


async def test_srv12_republish_of_an_acknowledged_message_is_message_not_available(setup: Setup) -> None:
    """Part 4, 5.14.6: an acknowledged message is gone from the retransmission queue."""
    await setup.send_data(1)
    ack = ua.SubscriptionAcknowledgement(SubscriptionId=setup.subscription_id, SequenceNumber=1)
    setup.iserver.subscription_service.publish([ack], ALICE)
    with pytest.raises(utils.ServiceError) as error:
        republish(setup, ALICE, setup.subscription_id, 1)
    assert error.value.code == ua.StatusCodes.BadMessageNotAvailable


async def test_srv12_republish_of_a_foreign_subscription_is_subscription_id_invalid(setup: Setup) -> None:
    """Part 4, 5.14.6: a subscription of another session is not visible to Republish."""
    await setup.send_data(1)
    with pytest.raises(utils.ServiceError) as error:
        republish(setup, BOB, setup.subscription_id, 1)
    assert error.value.code == ua.StatusCodes.BadSubscriptionIdInvalid


async def test_srv32_ack_results_per_entry(setup: Setup) -> None:
    """Part 4, 5.14.5.4: each acknowledgement has its own result."""
    await setup.send_data(2)
    sid = setup.subscription_id
    acks = [
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=1),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=1),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=77),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid + 1000, SequenceNumber=2),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=2),
    ]
    _count, results = setup.iserver.subscription_service.publish(acks, ALICE)
    assert [r.value for r in results] == [
        ua.StatusCodes.Good,
        ua.StatusCodes.BadSequenceNumberUnknown,
        ua.StatusCodes.BadSequenceNumberUnknown,
        ua.StatusCodes.BadSubscriptionIdInvalid,
        ua.StatusCodes.Good,
    ]
    assert list(setup.sub.available_sequence_numbers()) == []


async def test_srv32_foreign_acknowledgement_leaves_the_message(setup: Setup) -> None:
    """Part 4, 5.14.5.4: a session cannot acknowledge the messages of another session."""
    await setup.send_data(1)
    ack = ua.SubscriptionAcknowledgement(SubscriptionId=setup.subscription_id, SequenceNumber=1)
    other = ua.NodeId(5, 1)
    other_params = ua.CreateSubscriptionParameters(RequestedMaxKeepAliveCount=10, RequestedLifetimeCount=30)
    created = await setup.iserver.subscription_service.create_subscription(
        other_params, setup.sub.pub_result_callback, other, lambda _id: None
    )
    _count, results = setup.iserver.subscription_service.publish([ack], other)
    await setup.iserver.subscription_service.subscriptions[created.SubscriptionId].stop()
    assert results[0].value == ua.StatusCodes.BadSubscriptionIdInvalid
    assert list(setup.sub.available_sequence_numbers()) == [1]


async def test_srv12_oldest_unacknowledged_message_can_be_dropped(setup: Setup) -> None:
    """Part 4, 5.14.1.1: the session bounds the retransmission queue by dropping the oldest message."""
    await setup.send_data(3)
    assert setup.sub.unacknowledged_count == 3
    assert setup.sub.drop_oldest_unacknowledged() is True
    assert list(setup.sub.available_sequence_numbers()) == [2, 3]
    assert setup.sub.drop_oldest_unacknowledged() is True
    assert setup.sub.drop_oldest_unacknowledged() is True
    assert setup.sub.drop_oldest_unacknowledged() is False


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

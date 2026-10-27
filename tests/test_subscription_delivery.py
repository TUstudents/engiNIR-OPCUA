"""Delivery of notifications by the client Subscription: queues, handlers, lifecycle."""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.node import Node
from enginir_opcua.common.subscription import (
    DataChangeEvent,
    StatusChangeEvent,
    Subscription,
    SubscriptionState,
    subscription_parameters,
)
from enginir_opcua.observer import Observer, SubscriptionEvent

from .subscription_rig import FakeSession, data_change, message, publish_result


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
    assert sub.state is SubscriptionState.DELETED


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
    assert sub.state is SubscriptionState.DELETED
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
    assert sub.state is SubscriptionState.TRANSFERRED
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
    assert sub.state is SubscriptionState.LOST
    assert sub.is_stale(1.5)
    old_id = sub.subscription_id
    await sub.recreate()
    assert sub.subscription_id != old_id
    assert sub.state is SubscriptionState.ACTIVE
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

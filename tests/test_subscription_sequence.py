"""Sequence tracking, gap repair and restore of the client Subscription."""

from __future__ import annotations

import asyncio
from typing import Any

from enginir_opcua import ua
from enginir_opcua.common.node import Node
from enginir_opcua.common.subscription import DataChangeEvent, Subscription, subscription_parameters

from .subscription_rig import FakeSession, data_change, message, publish_result


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

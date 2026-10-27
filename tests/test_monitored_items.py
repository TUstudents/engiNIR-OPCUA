"""Creation and modification of monitored items."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import utils

from .monitoring import SLOW, create_items, item_request, make_server, modify_items, open_subscription, publish


@pytest.fixture(scope="module")
async def server() -> AsyncIterator[Server]:
    srv = await make_server()
    yield srv


async def new_variable(server: Server, name: str, value: int = 1) -> ua.NodeId:
    node = await server.nodes.objects.add_variable(2, name, value)
    return node.nodeid


@pytest.mark.parametrize(
    "requested, revised", [(0, 1), (1, 1), (5, 5), (1000, 1000), (5000, 1000), (4_294_967_295, 1000)]
)
async def test_srv13_queue_size_of_a_data_item_is_revised(server: Server, requested: int, revised: int) -> None:
    """Part 4, 7.21: a data item's queue size 0 or 1 gives 1; the server limits the maximum."""
    nodeid = await new_variable(server, f"QueueRevision{requested}")
    sub, _ = await open_subscription(server)
    [result] = await create_items(server, sub, item_request(nodeid, queue=requested))
    assert result.StatusCode.is_good()
    assert result.RevisedQueueSize == revised


@pytest.mark.parametrize(
    "requested, revised",
    [(-1.0, SLOW), (0.0, 10.0), (1.0, 10.0), (250.0, 250.0), (7_200_000.0, 3_600_000.0), (float("nan"), SLOW)],
)
async def test_srv13_sampling_interval_is_revised(server: Server, requested: float, revised: float) -> None:
    """Part 4, 5.13.1.2 and 7.21: negative means the publishing interval, 0 the fastest, bounds apply."""
    nodeid = await new_variable(server, f"SamplingRevision{requested}")
    sub, _ = await open_subscription(server)
    [result] = await create_items(server, sub, item_request(nodeid, sampling=requested))
    assert result.RevisedSamplingInterval == revised


async def test_srv13_modify_revises_queue_size_and_sampling_interval(server: Server) -> None:
    """Part 4, 5.13.3: Modify revises the parameters like Create does."""
    nodeid = await new_variable(server, "ModifyRevision")
    sub, _ = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, queue=5, sampling=500))
    params = ua.MonitoringParameters(ClientHandle=2, SamplingInterval=0, QueueSize=50_000, DiscardOldest=True)
    [result] = modify_items(server, sub, (created.MonitoredItemId, params))
    assert result.StatusCode.is_good()
    assert result.RevisedQueueSize == 1000
    assert result.RevisedSamplingInterval == 10.0


async def test_srv13_modify_with_an_unknown_id_fails_only_that_item(server: Server) -> None:
    """Part 4, 5.13.3.3: errors are per item, Bad_MonitoredItemIdInvalid for an unknown id."""
    nodeid = await new_variable(server, "ModifyUnknown")
    sub, _ = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, queue=5))
    params = ua.MonitoringParameters(ClientHandle=2, SamplingInterval=100, QueueSize=7, DiscardOldest=True)
    unknown, known = modify_items(server, sub, (9999, params), (created.MonitoredItemId, params))
    assert unknown.StatusCode.value == ua.StatusCodes.BadMonitoredItemIdInvalid
    assert known.StatusCode.is_good()
    assert known.RevisedQueueSize == 7


async def test_srv13_an_unknown_node_fails_only_its_item(server: Server) -> None:
    """Part 4, 5.13.2.3: Bad_NodeIdUnknown is the status of the item, the others are created."""
    nodeid = await new_variable(server, "OneBadOneGood")
    sub, _ = await open_subscription(server)
    bad, good = await create_items(
        server, sub, item_request(ua.NodeId(424242, 2), handle=1), item_request(nodeid, handle=2)
    )
    assert bad.StatusCode.value == ua.StatusCodes.BadNodeIdUnknown
    assert good.StatusCode.is_good()


OVERFLOW_BIT = 0x0480


def values_of(notifications: list[Any]) -> list[int]:
    return [n.Value.Value.Value for n in notifications]


def has_overflow(notification: Any) -> bool:
    code = notification.Value.StatusCode
    return code is not None and (code.value & OVERFLOW_BIT) == OVERFLOW_BIT


async def write(server: Server, nodeid: ua.NodeId, value: int, **timestamps: Any) -> None:
    dv = ua.DataValue(ua.Variant(value, ua.VariantType.Int64), **timestamps)
    await server.iserver.aspace.write_attribute_value(nodeid, ua.AttributeIds.Value, dv)


async def test_srv13_discard_oldest_drops_the_oldest_and_flags_the_new_first_entry(server: Server) -> None:
    """Part 4, 5.13.1.5: the oldest value is deleted and the next one gets the Overflow bit."""
    nodeid = await new_variable(server, "DiscardOldest", 0)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(nodeid, queue=3, discard_oldest=True))
    for value in (1, 2, 3, 4):
        await write(server, nodeid, value)
    notifications = await publish(sub, wire)
    assert values_of(notifications) == [2, 3, 4]
    assert has_overflow(notifications[0])
    assert not has_overflow(notifications[1])


async def test_srv13_discard_newest_replaces_the_last_entry_and_flags_it(server: Server) -> None:
    """Part 4, 5.13.1.5: with DiscardOldest false the last value is replaced and carries the Overflow bit."""
    nodeid = await new_variable(server, "DiscardNewest", 0)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(nodeid, queue=3, discard_oldest=False))
    for value in (1, 2, 3, 4):
        await write(server, nodeid, value)
    notifications = await publish(sub, wire)
    assert values_of(notifications) == [0, 1, 4]
    assert not has_overflow(notifications[0])
    assert has_overflow(notifications[2])


@pytest.mark.parametrize("discard_oldest", [True, False])
async def test_srv13_a_queue_of_one_keeps_the_newest_without_the_overflow_bit(
    server: Server, discard_oldest: bool
) -> None:
    """Part 4, 5.13.1.5: the discard policy is ignored when the queue size is one."""
    nodeid = await new_variable(server, f"QueueOne{discard_oldest}", 0)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(nodeid, queue=1, discard_oldest=discard_oldest))
    for value in (1, 2, 3):
        await write(server, nodeid, value)
    notifications = await publish(sub, wire)
    assert values_of(notifications) == [3]
    assert not has_overflow(notifications[0])


async def test_srv13_modify_to_a_smaller_queue_discards_the_excess(server: Server) -> None:
    """Part 4, 5.13.3: the queue is cut to the revised size with the discard policy in force."""
    nodeid = await new_variable(server, "ModifySmaller", 0)
    sub, wire = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, queue=5))
    for value in (1, 2, 3):
        await write(server, nodeid, value)
    params = ua.MonitoringParameters(ClientHandle=1, SamplingInterval=100, QueueSize=2, DiscardOldest=True)
    modify_items(server, sub, (created.MonitoredItemId, params))
    assert values_of(await publish(sub, wire)) == [2, 3]


async def test_srv59_disabling_an_item_deletes_its_queued_notifications(server: Server) -> None:
    """Part 4, 5.13.1.3: a Disabled item has nothing queued and samples nothing."""
    nodeid = await new_variable(server, "DisableClears", 0)
    sub, wire = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, queue=5))
    await write(server, nodeid, 1)
    await sub.monitored_item_srv.set_monitoring_mode(ua.MonitoringMode.Disabled, [created.MonitoredItemId])
    await write(server, nodeid, 2)
    assert await publish(sub, wire) == []


async def test_srv59_an_item_created_disabled_queues_nothing(server: Server) -> None:
    """Part 4, 5.13.1.3."""
    nodeid = await new_variable(server, "CreatedDisabled", 0)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(nodeid, mode=ua.MonitoringMode.Disabled, queue=5))
    await write(server, nodeid, 1)
    assert await publish(sub, wire) == []


async def test_srv59_a_sampling_item_queues_without_reporting_until_reporting_is_set(server: Server) -> None:
    """Part 4, 5.13.1.3: Sampling queues the notifications, Reporting sends them."""
    nodeid = await new_variable(server, "SamplingMode", 0)
    sub, wire = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, mode=ua.MonitoringMode.Sampling, queue=5))
    await write(server, nodeid, 1)
    await write(server, nodeid, 2)
    assert await publish(sub, wire) == []
    await sub.monitored_item_srv.set_monitoring_mode(ua.MonitoringMode.Reporting, [created.MonitoredItemId])
    assert values_of(await publish(sub, wire)) == [0, 1, 2]


async def test_srv59_leaving_disabled_takes_a_first_sample(server: Server) -> None:
    """Part 4, 5.13.1.3."""
    nodeid = await new_variable(server, "LeaveDisabled", 7)
    sub, wire = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, mode=ua.MonitoringMode.Disabled))
    await sub.monitored_item_srv.set_monitoring_mode(ua.MonitoringMode.Reporting, [created.MonitoredItemId])
    assert values_of(await publish(sub, wire)) == [7]


async def test_srv59_event_items_follow_the_monitoring_mode(server: Server) -> None:
    """Part 4, 5.13.1.3: a Disabled Event item receives no events, a Sampling one queues without reporting."""
    event_filter = ua.EventFilter(
        SelectClauses=[
            ua.SimpleAttributeOperand(
                TypeDefinitionId=ua.NodeId(ua.ObjectIds.BaseEventType),
                BrowsePath=[ua.QualifiedName("Message", 0)],
                AttributeId=ua.AttributeIds.Value,
            )
        ]
    )
    sub, wire = await open_subscription(server)
    request = item_request(
        ua.NodeId(ua.ObjectIds.Server),
        ua.AttributeIds.EventNotifier,
        mode=ua.MonitoringMode.Disabled,
        queue=10,
        filter=event_filter,
    )
    [created] = await create_items(server, sub, request)
    assert created.StatusCode.is_good()
    generator = await server.get_event_generator()
    await generator.trigger(message="disabled")
    assert await publish(sub, wire) == []
    await sub.monitored_item_srv.set_monitoring_mode(ua.MonitoringMode.Sampling, [created.MonitoredItemId])
    await generator.trigger(message="sampled")
    assert await publish(sub, wire) == []
    await sub.monitored_item_srv.set_monitoring_mode(ua.MonitoringMode.Reporting, [created.MonitoredItemId])
    notifications = await publish(sub, wire)
    assert [n.EventFields[0].Value.Text for n in notifications] == ["sampled"]


@pytest.mark.parametrize(
    "timestamps, source, server_ts",
    [
        (ua.TimestampsToReturn.Source, True, False),
        (ua.TimestampsToReturn.Server, False, True),
        (ua.TimestampsToReturn.Both, True, True),
        (ua.TimestampsToReturn.Neither, False, False),
    ],
)
async def test_srv58_timestamps_to_return_are_applied(
    server: Server, timestamps: ua.TimestampsToReturn, source: bool, server_ts: bool
) -> None:
    """Part 4, 7.39 and 5.13.2.2: only the requested timestamps stay in the notification."""
    nodeid = await new_variable(server, f"Timestamps{timestamps.name}", 0)
    now = datetime.now(UTC)
    await write(server, nodeid, 5, SourceTimestamp=now, ServerTimestamp=now)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(nodeid), timestamps=timestamps)
    [notification] = await publish(sub, wire)
    assert (notification.Value.SourceTimestamp is not None) == source
    assert (notification.Value.ServerTimestamp is not None) == server_ts


async def test_srv58_modify_applies_the_new_timestamps_to_return(server: Server) -> None:
    """Part 4, 5.13.3.2."""
    nodeid = await new_variable(server, "TimestampsModify", 0)
    now = datetime.now(UTC)
    await write(server, nodeid, 5, SourceTimestamp=now, ServerTimestamp=now)
    sub, wire = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, queue=5))
    await publish(sub, wire)
    params = ua.MonitoringParameters(ClientHandle=1, SamplingInterval=100, QueueSize=5, DiscardOldest=True)
    modify_items(server, sub, (created.MonitoredItemId, params), timestamps=ua.TimestampsToReturn.Neither)
    await write(server, nodeid, 6, SourceTimestamp=now, ServerTimestamp=now)
    [notification] = await publish(sub, wire)
    assert notification.Value.SourceTimestamp is None
    assert notification.Value.ServerTimestamp is None


async def test_srv58_an_invalid_timestamps_to_return_fails_the_request(server: Server) -> None:
    """Part 4, 5.13.2.3 and 5.13.3.3: Bad_TimestampsToReturnInvalid."""
    nodeid = await new_variable(server, "TimestampsInvalid", 0)
    sub, _ = await open_subscription(server)
    with pytest.raises(utils.ServiceError) as create_error:
        await create_items(server, sub, item_request(nodeid), timestamps=ua.TimestampsToReturn.Invalid)
    assert create_error.value.code == ua.StatusCodes.BadTimestampsToReturnInvalid
    params = ua.MonitoringParameters(ClientHandle=1, SamplingInterval=100, QueueSize=5, DiscardOldest=True)
    with pytest.raises(utils.ServiceError) as modify_error:
        modify_items(server, sub, (1, params), timestamps=ua.TimestampsToReturn.Invalid)
    assert modify_error.value.code == ua.StatusCodes.BadTimestampsToReturnInvalid


async def test_srv57_items_per_subscription_are_limited() -> None:
    """Part 4, 5.13.2.4: Bad_TooManyMonitoredItems for the items beyond the limit, the others are created."""
    server = await make_server()
    server.iserver.max_monitored_items_per_subscription = 2
    nodeid = await new_variable(server, "LimitPerSubscription", 0)
    sub, _ = await open_subscription(server)
    results = await create_items(server, sub, *(item_request(nodeid, handle=n) for n in range(3)))
    assert [r.StatusCode.value for r in results] == [
        ua.StatusCodes.Good,
        ua.StatusCodes.Good,
        ua.StatusCodes.BadTooManyMonitoredItems,
    ]
    other, _ = await open_subscription(server)
    [again] = await create_items(server, other, item_request(nodeid))
    assert again.StatusCode.is_good()


async def test_srv57_items_per_server_are_limited() -> None:
    """Part 4, 5.13.2.4."""
    server = await make_server()
    server.iserver.max_monitored_items = 3
    nodeid = await new_variable(server, "LimitPerServer", 0)
    first, _ = await open_subscription(server)
    second, _ = await open_subscription(server)
    await create_items(server, first, item_request(nodeid), item_request(nodeid))
    results = await create_items(server, second, item_request(nodeid), item_request(nodeid))
    assert [r.StatusCode.value for r in results] == [ua.StatusCodes.Good, ua.StatusCodes.BadTooManyMonitoredItems]

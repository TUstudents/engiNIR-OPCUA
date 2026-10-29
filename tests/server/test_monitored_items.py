from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import utils
from enginir_opcua.crypto.permission_rules import User, UserRole
from tests.conftest import find_free_port
from tests.harness import SessionProbe
from tests.monitoring import (
    SESSION,
    SLOW,
    create_items,
    item_request,
    make_server,
    modify_items,
    open_subscription,
    publish,
)

"""Creation and modification of monitored items."""


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


@pytest.mark.parametrize(
    ("discard_oldest", "expected", "flagged"),
    [
        pytest.param(True, [2, 3, 4], 0, id="srv13_discard_oldest_drops_the_oldest_and_flags_the_new_first_entry"),
        pytest.param(False, [0, 1, 4], 2, id="srv13_discard_newest_replaces_the_last_entry_and_flags_it"),
    ],
)
async def test_srv13_queue_overflow_flags_one_entry(
    server: Server, discard_oldest: bool, expected: list[int], flagged: int
) -> None:
    """Part 4, 5.13.1.5: the dropped or replaced entry's neighbour carries the Overflow bit, and only that one."""
    nodeid = await new_variable(server, f"Discard{discard_oldest}", 0)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(nodeid, queue=3, discard_oldest=discard_oldest))
    for value in (1, 2, 3, 4):
        await write(server, nodeid, value)
    notifications = await publish(sub, wire)
    assert values_of(notifications) == expected
    assert [has_overflow(notification) for notification in notifications] == [index == flagged for index in range(3)]


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


async def test_srv50_deleting_the_monitored_node_delivers_bad_node_id_unknown(server: Server) -> None:
    """Part 4, 5.13.1.6 and 5.8.4: the item reports Bad_NodeIdUnknown, it is not deleted."""
    node = await server.nodes.objects.add_variable(2, "DeletedWhileMonitored", 1)
    sub, wire = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(node.nodeid, queue=5))
    await publish(sub, wire)
    await node.delete()
    notifications = await publish(sub, wire)
    assert [n.Value.StatusCode.value for n in notifications] == [ua.StatusCodes.BadNodeIdUnknown]
    assert notifications[0].Value.Value.Value is None
    assert created.MonitoredItemId in sub.monitored_item_srv._monitored_items
    assert await publish(sub, wire) == []


async def test_srv52_a_node_with_a_value_callback_is_sampled_at_the_sampling_interval(server: Server) -> None:
    """Part 4, 5.13.1.2: the server samples a value that changes without a write."""
    node = await server.nodes.objects.add_variable(2, "CallbackNode", 0)
    counter = {"value": 0}

    def current(_nodeid: ua.NodeId, _attribute: ua.AttributeIds) -> ua.DataValue:
        counter["value"] += 1
        return ua.DataValue(ua.Variant(counter["value"], ua.VariantType.Int64))

    server.iserver.aspace.set_attribute_value_callback(node.nodeid, ua.AttributeIds.Value, current)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(node.nodeid, queue=50, sampling=20))
    await asyncio.sleep(0.3)
    notifications = await publish(sub, wire)
    assert len(notifications) >= 3
    assert values_of(notifications) == sorted(set(values_of(notifications)))
    await sub.stop()


async def test_srv52_the_sampler_stops_when_the_item_is_disabled_or_deleted(server: Server) -> None:
    """Part 4, 5.13.1.3."""
    node = await server.nodes.objects.add_variable(2, "CallbackStops", 0)
    calls = {"count": 0}

    def current(_nodeid: ua.NodeId, _attribute: ua.AttributeIds) -> ua.DataValue:
        calls["count"] += 1
        return ua.DataValue(ua.Variant(calls["count"], ua.VariantType.Int64))

    server.iserver.aspace.set_attribute_value_callback(node.nodeid, ua.AttributeIds.Value, current)
    sub, _ = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(node.nodeid, queue=50, sampling=20))
    await sub.monitored_item_srv.set_monitoring_mode(ua.MonitoringMode.Disabled, [created.MonitoredItemId])
    count = calls["count"]
    await asyncio.sleep(0.15)
    assert calls["count"] == count
    await sub.monitored_item_srv.set_monitoring_mode(ua.MonitoringMode.Reporting, [created.MonitoredItemId])
    await asyncio.sleep(0.15)
    assert calls["count"] > count + 2
    sub.monitored_item_srv.delete_monitored_items([created.MonitoredItemId])
    count = calls["count"]
    await asyncio.sleep(0.15)
    assert calls["count"] == count


@pytest.mark.parametrize(
    "bit, status",
    [(ua.AccessLevel.CurrentRead, ua.StatusCodes.BadNotReadable)],
)
async def test_srv51_an_item_of_a_node_the_access_level_forbids_reading_delivers_a_bad_status(
    server: Server, bit: ua.AccessLevel, status: int
) -> None:
    """Part 4, 5.13.2.1 and 5.10.2.4: the sample carries Bad_NotReadable and no value."""
    node = await server.nodes.objects.add_variable(2, "NotReadableForItems", 5)
    await node.unset_attr_bit(ua.AttributeIds.AccessLevel, bit)
    sub, wire = await open_subscription(server)
    sub.owner_user = User(role=UserRole.User, name="alice")
    [created] = await create_items(server, sub, item_request(node.nodeid, queue=5))
    assert created.StatusCode.is_good()
    [notification] = await publish(sub, wire)
    assert notification.Value.StatusCode.value == status
    assert notification.Value.Value.Value is None
    await node.set_attr_bit(ua.AttributeIds.AccessLevel, bit)
    await write(server, node.nodeid, 6)
    [notification] = await publish(sub, wire)
    assert notification.Value.Value.Value == 6


async def test_srv51_the_user_access_level_is_checked_for_the_subscriptions_user(server: Server) -> None:
    """Part 4, 5.13.2.1 and 5.10.2.4: Bad_UserAccessDenied."""
    node = await server.nodes.objects.add_variable(2, "UserDeniedForItems", 5)
    await node.unset_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.CurrentRead)
    sub, wire = await open_subscription(server)
    sub.owner_user = User(role=UserRole.Admin, name="root")
    await create_items(server, sub, item_request(node.nodeid, queue=5))
    [notification] = await publish(sub, wire)
    assert notification.Value.StatusCode.value == ua.StatusCodes.BadUserAccessDenied


async def test_srv51_the_in_process_subscription_is_trusted(server: Server) -> None:
    """Part 4, 5.13.2.1: the server's own subscription reads what it needs."""
    node = await server.nodes.objects.add_variable(2, "TrustedItems", 5)
    await node.unset_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.CurrentRead)
    sub, wire = await open_subscription(server)
    await create_items(server, sub, item_request(node.nodeid, queue=5))
    assert values_of(await publish(sub, wire)) == [5]


"""SetTriggering and the triggering behaviour of monitored items."""


MODE = ua.MonitoringMode


async def variable(server: Server, name: str) -> ua.NodeId:
    return (await server.nodes.objects.add_variable(2, name, 0)).nodeid


async def set_triggering(
    server: Server, sub: Any, triggering: int, add: list[int], remove: list[int] | None = None
) -> ua.SetTriggeringResult:
    params = ua.SetTriggeringParameters(
        SubscriptionId=sub.data.SubscriptionId,
        TriggeringItemId=triggering,
        LinksToAdd=add,
        LinksToRemove=remove or [],
    )
    return await server.iserver.subscription_service.set_triggering(params, SESSION)


async def linked_pair(
    server: Server, name: str, trigger_mode: ua.MonitoringMode = MODE.Sampling
) -> tuple[Any, Any, ua.NodeId, ua.NodeId, int, int]:
    triggering_node, linked_node = await variable(server, f"{name}Trigger"), await variable(server, f"{name}Linked")
    sub, wire = await open_subscription(server)
    trigger, linked = await create_items(
        server,
        sub,
        item_request(triggering_node, mode=trigger_mode, queue=5, handle=1),
        item_request(linked_node, mode=MODE.Sampling, queue=5, handle=2),
    )
    await publish(sub, wire)
    return sub, wire, triggering_node, linked_node, trigger.MonitoredItemId, linked.MonitoredItemId


def handles(notifications: list[Any]) -> list[int]:
    return [n.ClientHandle for n in notifications]


async def test_srv19_a_notification_of_the_triggering_item_reports_the_queued_values_of_a_sampling_item(
    server: Server,
) -> None:
    """Part 4, 5.13.1.6 and 5.13.5: the linked item reports what it queued, once."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Reports")
    result = await set_triggering(server, sub, trigger, [linked])
    assert [code.value for code in result.AddResults] == [ua.StatusCodes.Good]
    await write(server, linked_node, 1)
    await write(server, linked_node, 2)
    assert await publish(sub, wire) == []
    await write(server, trigger_node, 7)
    notifications = await publish(sub, wire)
    assert handles(notifications) == [2, 2, 2]
    await write(server, linked_node, 3)
    assert await publish(sub, wire) == []


async def test_srv19_a_triggering_item_in_reporting_mode_is_reported_too(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(
        server, "ReportingTrigger", MODE.Reporting
    )
    await set_triggering(server, sub, trigger, [linked])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [1, 2, 2]


async def test_srv19_a_disabled_triggering_item_triggers_nothing(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "DisabledTrigger")
    await set_triggering(server, sub, trigger, [linked])
    await sub.monitored_item_srv.set_monitoring_mode(MODE.Disabled, [trigger])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert await publish(sub, wire) == []


async def test_srv19_a_reporting_linked_item_is_not_affected(server: Server) -> None:
    """Part 4, 5.13.1.6: it reports on its own."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "ReportingLinked")
    await sub.monitored_item_srv.set_monitoring_mode(MODE.Reporting, [linked])
    await publish(sub, wire)
    await set_triggering(server, sub, trigger, [linked])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [2]


async def test_srv19_the_trigger_does_not_follow_links_of_linked_items(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, _, trigger, linked = await linked_pair(server, "Chain")
    third_node = await variable(server, "ChainThird")
    [third] = await create_items(server, sub, item_request(third_node, mode=MODE.Sampling, queue=5, handle=3))
    await publish(sub, wire)
    await set_triggering(server, sub, trigger, [linked])
    await set_triggering(server, sub, linked, [third.MonitoredItemId])
    await write(server, third_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [2]


async def test_srv19_links_to_remove_are_processed_before_links_to_add(server: Server) -> None:
    """Part 4, 5.13.5.2."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Order")
    await set_triggering(server, sub, trigger, [linked])
    result = await set_triggering(server, sub, trigger, [linked], [linked])
    assert [code.value for code in result.RemoveResults] == [ua.StatusCodes.Good]
    assert [code.value for code in result.AddResults] == [ua.StatusCodes.Good]
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [2, 2]


async def test_srv19_removed_links_stop_triggering(server: Server) -> None:
    """Part 4, 5.13.5."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Removed")
    await set_triggering(server, sub, trigger, [linked])
    await set_triggering(server, sub, trigger, [], [linked])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert await publish(sub, wire) == []


async def test_srv19_each_entry_has_its_own_result(server: Server) -> None:
    """Part 4, 5.13.5.2 and 5.13.5.3."""
    sub, _, _, _, trigger, linked = await linked_pair(server, "Results")
    result = await set_triggering(server, sub, trigger, [linked, 9999, trigger, linked], [8888])
    invalid = ua.StatusCodes.BadMonitoredItemIdInvalid
    assert [code.value for code in result.AddResults] == [ua.StatusCodes.Good, invalid, invalid, ua.StatusCodes.Good]
    assert [code.value for code in result.RemoveResults] == [invalid]


async def test_srv19_service_level_errors(server: Server) -> None:
    """Part 4, 5.13.5.3: unknown triggering item, nothing to do."""
    sub, _, _, _, trigger, linked = await linked_pair(server, "ServiceErrors")
    with pytest.raises(utils.ServiceError) as unknown:
        await set_triggering(server, sub, 9999, [linked])
    assert unknown.value.code == ua.StatusCodes.BadMonitoredItemIdInvalid
    with pytest.raises(utils.ServiceError) as nothing:
        await set_triggering(server, sub, trigger, [])
    assert nothing.value.code == ua.StatusCodes.BadNothingToDo
    params = ua.SetTriggeringParameters(SubscriptionId=123456, TriggeringItemId=trigger, LinksToAdd=[linked])
    with pytest.raises(utils.ServiceError) as no_subscription:
        await server.iserver.subscription_service.set_triggering(params, SESSION)
    assert no_subscription.value.code == ua.StatusCodes.BadSubscriptionIdInvalid


async def test_srv19_deleting_an_item_deletes_its_links(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Deleted")
    await set_triggering(server, sub, trigger, [linked])
    sub.monitored_item_srv.delete_monitored_items([linked])
    assert sub.monitored_item_srv._monitored_items[trigger].links == set()
    [again] = await create_items(server, sub, item_request(linked_node, mode=MODE.Sampling, queue=5, handle=5))
    await publish(sub, wire)
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert await publish(sub, wire) == []
    assert again.StatusCode.is_good()


async def test_srv19_set_triggering_is_served_over_the_wire() -> None:
    """Part 4, 5.13.5: the request reaches the service through the dispatch table."""
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await srv.start()
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = (await probe.create_session()).AuthenticationToken
        await probe.activate(token)
        nodes = [(await srv.nodes.objects.add_variable(2, f"Wire{n}", 0)).nodeid for n in range(2)]
        subscription = ua.CreateSubscriptionRequest()
        subscription.Parameters.RequestedPublishingInterval = 1000
        subscription.Parameters.RequestedLifetimeCount = 300
        subscription.Parameters.RequestedMaxKeepAliveCount = 100
        created = await probe.send(token, subscription, ua.CreateSubscriptionResponse)
        items = ua.CreateMonitoredItemsRequest()
        items.Parameters.SubscriptionId = created.Parameters.SubscriptionId
        items.Parameters.ItemsToCreate = [item_request(node, handle=n + 1) for n, node in enumerate(nodes)]
        monitored = await probe.send(token, items, ua.CreateMonitoredItemsResponse)
        first, second = (result.MonitoredItemId for result in monitored.Results)
        request = ua.SetTriggeringRequest()
        request.Parameters = ua.SetTriggeringParameters(
            SubscriptionId=created.Parameters.SubscriptionId, TriggeringItemId=first, LinksToAdd=[second]
        )
        response = await probe.send(token, request, ua.SetTriggeringResponse)
        assert [code.value for code in response.Parameters.AddResults] == [ua.StatusCodes.Good]
    finally:
        probe.close()
        await srv.stop()

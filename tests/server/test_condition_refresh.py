from __future__ import annotations

import asyncio
from typing import Any

import pytest

from enginir_opcua import ua
from tests.condition_rig import Collector, ConditionRig, make_condition_rig  # noqa: F401
from tests.server.test_conditions import ALARM, field, make, variant
from tests.waiting import wait_until

"""ConditionRefresh and ConditionRefresh2 (Part 9, 5.5.7, 5.5.8, 5.11) and the retained Conditions."""

CONDITION_TYPE = ua.NodeId(ua.ObjectIds.ConditionType)
REFRESH = ua.NodeId(ua.ObjectIds.ConditionType_ConditionRefresh)
REFRESH2 = ua.NodeId(ua.ObjectIds.ConditionType_ConditionRefresh2)
START = ua.NodeId(ua.ObjectIds.RefreshStartEventType)
END = ua.NodeId(ua.ObjectIds.RefreshEndEventType)
REQUIRED = ua.NodeId(ua.ObjectIds.RefreshRequiredEventType)


def types(collector: Collector) -> list[ua.NodeId]:
    return [event.EventType for event in collector.events]


async def refresh(rig: ConditionRig, sub: Any, *, client: Any = None, item: int | None = None) -> int:
    owner = client or rig.admin
    method = REFRESH if item is None else REFRESH2
    args = [variant(sub.subscription_id, ua.VariantType.UInt32)]
    if item is not None:
        args.append(variant(item, ua.VariantType.UInt32))
    request = ua.CallMethodRequest(ObjectId=CONDITION_TYPE, MethodId=method, InputArguments=args)
    [result] = await owner.uaclient.call([request])
    return int(result.StatusCode.value)


async def test_srv71_condition_refresh_replays_retained_conditions(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, source, _first = await make(rig)
    await condition.activate(severity=500)
    original = await rig.count(_first, 1)
    collector, sub = await rig.watch(source)
    assert await refresh(rig, sub) == 0
    await wait_until(lambda: END in types(collector))
    assert types(collector) == [START, ua.NodeId(ALARM), END]
    replay = collector.events[1]
    assert field(replay, "NodeId") == condition.condition_id
    assert field(replay, "EventId") == original[0].EventId
    assert field(replay, "Time") == original[0].Time


async def test_srv72_refresh_events_ignore_the_where_clause(condition_rig: ConditionRig) -> None:
    """Part 9, 4.5: Start and End are delivered whatever the filter says (here: only AlarmConditionType)."""
    rig = condition_rig
    _condition, source, _c = await make(rig)
    collector, sub = await rig.watch(source, ALARM)
    assert await refresh(rig, sub) == 0
    await wait_until(lambda: END in types(collector))
    assert types(collector) == [START, END]


async def test_srv73_refresh_events_reach_every_notifier_item_of_the_subscription(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, source, _c = await make(rig)
    await condition.activate(severity=500)
    collector = Collector()
    sub = await rig.admin.create_subscription(50, collector)
    server_item = await sub.subscribe_events(
        rig.admin.get_node(ua.NodeId(ua.ObjectIds.Server)), ua.ObjectIds.ConditionType
    )
    source_item = await sub.subscribe_events(rig.admin.get_node(source.nodeid), ua.ObjectIds.ConditionType)
    assert server_item != source_item
    assert await refresh(rig, sub) == 0
    await wait_until(lambda: types(collector).count(END) == 2)
    assert types(collector).count(START) == 2
    starts = [event.EventId for event in collector.events if event.EventType == START]
    assert starts[0] == starts[1]


async def test_srv74_refresh_of_another_sessions_subscription_is_denied(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    _condition, source, _c = await make(rig)
    _collector, sub = await rig.watch(source)
    assert await refresh(rig, sub, client=rig.user) == ua.StatusCodes.BadUserAccessDenied
    unknown = type("Unknown", (), {"subscription_id": 99999})()
    assert await refresh(rig, unknown) == ua.StatusCodes.BadSubscriptionIdInvalid
    assert await refresh(rig, sub, item=99999) == ua.StatusCodes.BadMonitoredItemIdInvalid


async def test_srv74_refresh_without_event_items_is_nothing_to_do(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    sub = await rig.admin.create_subscription(50, Collector())
    variable = await rig.server.nodes.objects.add_variable(rig.ns, rig.unique("Plain"), 1)
    await sub.subscribe_data_change(rig.admin.get_node(variable.nodeid))
    assert await refresh(rig, sub) == ua.StatusCodes.BadNothingToDo


async def test_srv75_each_branch_is_replayed(condition_rig: ConditionRig) -> None:
    """Part 9, 4.5: the trunk and every retained branch are sent, each with its own EventId."""
    rig = condition_rig
    condition, source, _c = await make(rig, branches=True)
    await condition.activate(severity=500)
    await condition.deactivate()
    await condition.activate(severity=500)
    collector, sub = await rig.watch(source)
    assert await refresh(rig, sub) == 0
    await wait_until(lambda: END in types(collector))
    replayed = [event for event in collector.events if event.EventType == ua.NodeId(ALARM)]
    assert len(replayed) == 2
    assert {field(event, "BranchId") for event in replayed} == {ua.NodeId(), condition.branches[0]}
    assert len({bytes(event.EventId) for event in replayed}) == 2


async def test_srv75_a_replay_shows_the_current_values_not_a_live_object(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, source, _c = await make(rig)
    await condition.activate(severity=500, message="first")
    await condition.set_severity(500)
    collector, sub = await rig.watch(source)
    assert await refresh(rig, sub) == 0
    await wait_until(lambda: END in types(collector))
    assert field(collector.events[1], "Message").Text == "first"


async def test_conditions_that_are_not_retained_are_not_replayed(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, source, _c = await make(rig)
    await condition.activate(severity=500)
    await condition.acknowledge()
    await condition.deactivate()
    collector, sub = await rig.watch(source)
    assert await refresh(rig, sub) == 0
    await wait_until(lambda: END in types(collector))
    assert types(collector) == [START, END]


async def test_refresh2_refreshes_one_item(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, source, _c = await make(rig)
    await condition.activate(severity=500)
    collector = Collector()
    sub = await rig.admin.create_subscription(50, collector)
    first = await sub.subscribe_events(rig.admin.get_node(source.nodeid), ua.ObjectIds.ConditionType)
    await sub.subscribe_events(rig.admin.get_node(ua.NodeId(ua.ObjectIds.Server)), ua.ObjectIds.ConditionType)
    assert await refresh(rig, sub, item=first) == 0
    await wait_until(lambda: END in types(collector))
    await asyncio.sleep(0.2)
    assert types(collector) == [START, ua.NodeId(ALARM), END]


async def test_refresh_required_event_goes_to_every_event_item(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    _condition, source, _c = await make(rig)
    collector, sub = await rig.watch(source)
    await rig.server.refresh_required([sub.subscription_id])
    await wait_until(lambda: REQUIRED in types(collector))


async def test_a_queue_overflow_that_loses_condition_events_asks_for_a_refresh(condition_rig: ConditionRig) -> None:
    """Part 9, 5.11.4: RefreshRequired follows an overflow in which Condition Events were lost."""
    rig = condition_rig
    condition, source, _c = await make(rig)
    collector, _sub = await rig.watch(source, queue=2)
    for _ in range(8):
        await condition.set_severity(1)
        await condition.activate(severity=500)
        await condition.deactivate()
    await wait_until(lambda: len(collector.events) >= 2)
    await asyncio.sleep(0.3)
    collector.clear()
    await condition.activate(severity=500)
    await wait_until(lambda: REQUIRED in types(collector))


@pytest.mark.parametrize("flag", ["bind_condition_methods"])
def test_the_bind_condition_methods_flag_is_gone(condition_rig: ConditionRig, flag: str) -> None:
    assert not hasattr(condition_rig.server.iserver, flag)

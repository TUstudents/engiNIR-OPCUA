from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common import conditions
from tests.condition_rig import Collector, ConditionRig, make_condition_rig  # noqa: F401
from tests.waiting import wait_until

"""The client helpers for Alarms and Conditions (Part 9)."""


def field(event: Any, name: str) -> Any:
    return getattr(event, name)


async def make_alarm(rig: ConditionRig, **options: Any) -> tuple[Any, Any, Collector, Any]:
    source = await rig.source()
    condition = await rig.server.create_condition(
        source, ua.NodeId(ua.ObjectIds.AlarmConditionType), rig.unique("Alarm"), **options
    )
    collector, sub = await rig.watch(source, ua.ObjectIds.AlarmConditionType)
    return condition, source, collector, sub


async def test_the_helpers_call_the_methods_by_condition_id(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector, _sub = await make_alarm(rig, confirmable=True, shelving=True)
    await condition.activate(severity=500)
    [event] = await rig.count(collector, 1)
    await conditions.add_comment(rig.admin, condition.condition_id, event.EventId, "looking")
    await conditions.acknowledge(rig.admin, condition.condition_id, event.EventId, "seen")
    ack = (await rig.count(collector, 3))[-1]
    assert field(ack, "AckedState/Id") is True
    await conditions.confirm(rig.admin, condition.condition_id, ack.EventId)
    await conditions.timed_shelve(rig.admin, condition.condition_id, 60_000)
    assert condition.shelving_state == "TimedShelved"
    await conditions.unshelve(rig.admin, condition.condition_id)
    await conditions.one_shot_shelve(rig.admin, condition.condition_id)
    assert condition.shelving_state == "OneShotShelved"
    await conditions.disable(rig.admin, condition.condition_id)
    assert condition.enabled is False
    await conditions.enable(rig.admin, condition.condition_id)
    assert condition.enabled is True


async def test_a_bad_result_raises_the_status(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, _collector, _sub = await make_alarm(rig)
    with pytest.raises(ua.UaStatusCodeError) as error:
        await conditions.acknowledge(rig.admin, condition.condition_id, b"unknown")
    assert error.value.code == ua.StatusCodes.BadEventIdUnknown


async def test_the_condition_filter_selects_the_condition_id_and_the_type(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    flt = await conditions.condition_event_filter(rig.admin, ua.ObjectIds.AlarmConditionType)
    assert any(not clause.BrowsePath and clause.AttributeId == ua.AttributeIds.NodeId for clause in flt.SelectClauses)
    paths = {"/".join(part.Name for part in clause.BrowsePath) for clause in flt.SelectClauses}
    assert {"Retain", "AckedState/Id", "ActiveState/Id"} <= paths
    assert not any(path.endswith(("TrueState", "FalseState")) for path in paths)


class FakeClient:
    def __init__(self, refresh2: bool) -> None:
        self.calls: list[tuple[ua.NodeId, ua.NodeId, list[Any]]] = []
        self.refresh2 = refresh2

    def get_node(self, nodeid: ua.NodeId) -> Any:
        async def call_method(method: ua.NodeId, *arguments: ua.Variant) -> None:
            self.calls.append((nodeid, method, [argument.Value for argument in arguments]))
            if method == conditions.REFRESH2 and not self.refresh2:
                raise ua.uaerrors.BadMethodInvalid()

        return SimpleNamespace(call_method=call_method)


@pytest.mark.parametrize("supported", [True, False], ids=["refresh2", "falls_back_to_refresh"])
async def test_refresh2_falls_back_to_refresh_when_the_method_is_missing(supported: bool) -> None:
    """Part 9, 5.5.8."""
    client = FakeClient(supported)
    await conditions.condition_refresh2(client, 7, 3)
    methods = [method for _node, method, _args in client.calls]
    assert methods == ([conditions.REFRESH2] if supported else [conditions.REFRESH2, conditions.REFRESH])
    assert client.calls[-1][0] == conditions.CONDITION_TYPE
    assert client.calls[-1][2][0] == 7


def make_event(
    event_type: ua.NodeId, condition: str | None = None, retain: bool = True, branch: str | None = None
) -> Any:
    return SimpleNamespace(
        EventType=event_type,
        NodeId=ua.NodeId(condition, 2) if condition else None,
        Retain=retain,
        BranchId=ua.NodeId(branch, 2) if branch else ua.NodeId(),
    )


def test_the_condition_tracker_follows_the_current_alarm_algorithm() -> None:
    """Part 9, 4.5: suspect on RefreshStart, unflag on any Event, drop what stays suspect at RefreshEnd."""
    alarm = ua.NodeId(ua.ObjectIds.AlarmConditionType)
    changes: list[tuple[Any, bool]] = []
    tracker = conditions.ConditionTracker(lambda event, retained: changes.append((event, retained)))
    tracker.event_notification(make_event(alarm, "a"))
    tracker.event_notification(make_event(alarm, "b"))
    tracker.event_notification(make_event(alarm, "b", branch="1"))
    assert len(tracker.entries) == 3
    tracker.event_notification(make_event(conditions.REFRESH_START))
    tracker.event_notification(make_event(alarm, "b"))
    tracker.event_notification(make_event(alarm, "new"))
    tracker.event_notification(make_event(conditions.REFRESH_END))
    assert sorted(key[0].Identifier for key in tracker.entries) == ["b", "new"]
    tracker.event_notification(make_event(alarm, "b", retain=False))
    assert [key[0].Identifier for key in tracker.entries] == ["new"]
    assert changes[-1][1] is False


async def test_subscribing_refreshes_by_default(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    source = await rig.source()
    condition = await rig.server.create_condition(source, ua.NodeId(ua.ObjectIds.AlarmConditionType), rig.unique("Pre"))
    await condition.activate(severity=500)
    tracker = conditions.ConditionTracker()
    sub = await rig.admin.create_subscription(50, tracker)
    await sub.subscribe_alarms_and_conditions(rig.admin.get_node(source.nodeid), ua.ObjectIds.AlarmConditionType)
    await wait_until(lambda: len(tracker.entries) == 1)
    assert next(iter(tracker.entries))[0] == condition.condition_id


async def test_subscribing_without_refresh_sees_only_new_events(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    source = await rig.source()
    condition = await rig.server.create_condition(source, ua.NodeId(ua.ObjectIds.AlarmConditionType), rig.unique("Pre"))
    await condition.activate(severity=500)
    collector = Collector()
    sub = await rig.admin.create_subscription(50, collector)
    await sub.subscribe_alarms_and_conditions(
        rig.admin.get_node(source.nodeid), ua.ObjectIds.AlarmConditionType, refresh=False
    )
    await condition.set_severity(600)
    await rig.count(collector, 1)

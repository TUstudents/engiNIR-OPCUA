from __future__ import annotations

import asyncio
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.node import Node
from tests.condition_rig import ConditionRig, make_condition_rig  # noqa: F401
from tests.waiting import wait_until

"""Part 9 Conditions and Alarms on the server: instances, state, Events, Retain and the Methods."""

ACK = ua.NodeId(ua.ObjectIds.AcknowledgeableConditionType_Acknowledge)
CONFIRM = ua.NodeId(ua.ObjectIds.AcknowledgeableConditionType_Confirm)
ENABLE = ua.NodeId(ua.ObjectIds.ConditionType_Enable)
DISABLE = ua.NodeId(ua.ObjectIds.ConditionType_Disable)
ADD_COMMENT = ua.NodeId(ua.ObjectIds.ConditionType_AddComment)
TIMED_SHELVE = ua.NodeId(ua.ObjectIds.ShelvedStateMachineType_TimedShelve)
ONE_SHOT_SHELVE = ua.NodeId(ua.ObjectIds.ShelvedStateMachineType_OneShotShelve)
UNSHELVE = ua.NodeId(ua.ObjectIds.ShelvedStateMachineType_Unshelve)
UNSHELVE2 = ua.NodeId(ua.ObjectIds.ShelvedStateMachineType_Unshelve2)
ALARM = ua.ObjectIds.AlarmConditionType
LEVEL = ua.ObjectIds.ExclusiveLevelAlarmType
NON_EXCLUSIVE = ua.ObjectIds.NonExclusiveLevelAlarmType
OFF_NORMAL = ua.ObjectIds.OffNormalAlarmType
DEVIATION = ua.ObjectIds.ExclusiveDeviationAlarmType


def field(event: Any, name: str) -> Any:
    return getattr(event, name)


def variant(value: Any, vtype: ua.VariantType) -> ua.Variant:
    return ua.Variant(value, vtype)


async def call(
    rig: ConditionRig, condition_id: ua.NodeId, method: ua.NodeId, *args: ua.Variant, user: bool = False
) -> Any:
    client = rig.user if user else rig.admin
    return await client.get_node(condition_id).call_method(method, *args)


async def status_of(rig: ConditionRig, condition_id: ua.NodeId, method: ua.NodeId, *args: ua.Variant) -> int:
    request = ua.CallMethodRequest(ObjectId=condition_id, MethodId=method, InputArguments=list(args))
    [result] = await rig.admin.uaclient.call([request])
    return int(result.StatusCode.value)


def ack_args(event_id: bytes, text: str | None = "ok") -> list[ua.Variant]:
    comment = ua.LocalizedText(text) if text is not None else ua.LocalizedText()
    return [variant(event_id, ua.VariantType.ByteString), variant(comment, ua.VariantType.LocalizedText)]


async def make(rig: ConditionRig, ctype: int = ALARM, **options: Any) -> tuple[Any, Node, Any]:
    source = await rig.source()
    condition = await rig.server.create_condition(source, ua.NodeId(ctype), rig.unique("Cond"), **options)
    collector, _sub = await rig.watch(source, ctype)
    return condition, source, collector


async def test_condition_is_a_node_with_children_and_references(condition_rig: ConditionRig) -> None:
    """Part 9, 5.5.3 and 5.12: the ConditionId is the Object, referenced from the source with HasCondition."""
    rig = condition_rig
    source = await rig.source()
    condition = await rig.server.create_condition(source, ua.NodeId(ALARM), "Pump high", confirmable=True)
    assert condition.condition_id == condition.node.nodeid
    assert await condition.node.read_node_class() == ua.NodeClass.Object
    children = {(await child.read_browse_name()).Name for child in await condition.node.get_children()}
    assert {
        "EnabledState",
        "AckedState",
        "ConfirmedState",
        "ActiveState",
        "Retain",
        "Acknowledge",
        "Confirm",
    } <= children
    has_condition = await source.get_referenced_nodes(refs=ua.ObjectIds.HasCondition)
    assert [node.nodeid for node in has_condition] == [condition.condition_id]
    components = await source.get_children(refs=ua.ObjectIds.HasComponent)
    assert condition.condition_id in [node.nodeid for node in components]
    assert rig.server.get_condition(condition.condition_id) is condition


async def test_condition_without_a_confirmed_state_has_no_confirm_method(condition_rig: ConditionRig) -> None:
    """Part 9, 5.7.2: ConfirmedState is optional; Confirm is then Bad_MethodInvalid."""
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [event] = await rig.count(collector, 1)
    status = await status_of(rig, condition.condition_id, CONFIRM, *ack_args(event.EventId))
    assert status == ua.StatusCodes.BadMethodInvalid


async def test_creating_conditions_rejects_wrong_types_and_sources(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    source = await rig.source()
    with pytest.raises(ua.UaStatusCodeError) as abstract:
        await rig.server.create_condition(source, ua.NodeId(ua.ObjectIds.ConditionType), "abstract")
    assert abstract.value.code == ua.StatusCodes.BadNodeIdInvalid
    with pytest.raises(ua.UaStatusCodeError) as not_condition:
        await rig.server.create_condition(source, ua.NodeId(ua.ObjectIds.BaseEventType), "other")
    assert not_condition.value.code == ua.StatusCodes.BadNodeIdInvalid
    with pytest.raises(ua.UaStatusCodeError) as unknown:
        await rig.server.create_condition(ua.NodeId("Nowhere", rig.ns), ua.NodeId(ALARM), "none")
    assert unknown.value.code == ua.StatusCodes.BadNodeIdUnknown


async def test_a_new_condition_raises_no_event_and_starts_in_the_initial_state(condition_rig: ConditionRig) -> None:
    """Part 9, B.1.2: the initial state is not reported; Retain is false."""
    rig = condition_rig
    condition, _source, collector = await make(rig, confirmable=True)
    assert condition.retain is False
    await asyncio.sleep(0.2)
    assert collector.condition_events() == []
    node = condition.node
    for name, expected in (
        ("Retain", False),
        ("EnabledState/Id", True),
        ("AckedState/Id", True),
        ("ActiveState/Id", False),
    ):
        child = await node.get_child([ua.QualifiedName(part, 0) for part in name.split("/")])
        assert await child.read_value() == expected, name


async def test_alarm_events_carry_all_state_fields_and_the_condition_id(condition_rig: ConditionRig) -> None:
    """Part 9, 5.5.2, 5.2: one Event with every field, the ConditionId, state texts and times."""
    rig = condition_rig
    condition, source, collector = await make(rig, confirmable=True, severity=300)
    await condition.activate(severity=700, message="Pump too hot")
    [event] = await rig.count(collector, 1)
    assert field(event, "NodeId") == condition.condition_id
    assert field(event, "Retain") is True
    assert field(event, "BranchId") == ua.NodeId()
    assert field(event, "ActiveState/Id") is True
    assert field(event, "ActiveState").Text == "Active"
    assert field(event, "AckedState/Id") is False
    assert field(event, "AckedState").Text == "Unacknowledged"
    assert field(event, "ConfirmedState/Id") is True
    assert field(event, "EnabledState").Text == "Enabled"
    assert field(event, "Severity") == 700
    assert field(event, "LastSeverity") == 300
    assert field(event, "Message").Text == "Pump too hot"
    assert field(event, "SourceNode") == source.nodeid
    assert field(event, "ConditionName") == condition.name
    assert field(event, "Quality") == ua.StatusCode()
    assert len(field(event, "EventId")) == 16
    assert field(event, "ActiveState/TransitionTime") is not None


async def test_event_ids_are_unique_for_every_event(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    await condition.deactivate()
    await condition.activate(severity=500)
    events = await rig.count(collector, 3)
    assert len({bytes(field(event, "EventId")) for event in events}) == 3


async def test_retain_follows_active_acked_and_confirmed(condition_rig: ConditionRig) -> None:
    """Part 9, B.1.2: the sequence of Events of a Condition that keeps only the current state."""
    rig = condition_rig
    condition, _source, collector = await make(rig, confirmable=True)
    await condition.activate(severity=500)
    await condition.deactivate()
    first = await rig.count(collector, 2)
    assert [field(e, "Retain") for e in first] == [True, True]
    assert [field(e, "ActiveState/Id") for e in first] == [True, False]
    await condition.acknowledge(first[-1].EventId, "seen")
    ack = (await rig.count(collector, 3))[-1]
    assert (field(ack, "AckedState/Id"), field(ack, "ConfirmedState/Id"), field(ack, "Retain")) == (True, False, True)
    await condition.confirm(ack.EventId)
    last = (await rig.count(collector, 4))[-1]
    assert (field(last, "ConfirmedState/Id"), field(last, "Retain")) == (True, False)
    assert condition.retain is False


async def test_a_change_that_leaves_retain_false_raises_no_event(condition_rig: ConditionRig) -> None:
    """Part 9, 5.5.2: Events only for Retain true and for the transition of Retain to false."""
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.set_severity(600)
    await asyncio.sleep(0.2)
    assert collector.condition_events() == []
    assert condition.retain is False


async def test_disable_and_enable(condition_rig: ConditionRig) -> None:
    """Part 9, 5.5.2, 5.5.4, 5.5.5: one Event on Disable; none while disabled; Enable re-evaluates."""
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [active] = await rig.count(collector, 1)
    assert await status_of(rig, condition.condition_id, ENABLE) == ua.StatusCodes.BadConditionAlreadyEnabled
    await call(rig, condition.condition_id, DISABLE)
    disabled = (await rig.count(collector, 2))[-1]
    assert (field(disabled, "Retain"), field(disabled, "EnabledState/Id")) == (False, False)
    assert await status_of(rig, condition.condition_id, DISABLE) == ua.StatusCodes.BadConditionAlreadyDisabled
    await condition.deactivate()
    await condition.activate(severity=500)
    await asyncio.sleep(0.2)
    assert len(collector.condition_events()) == 2
    quality_node = await condition.node.get_child([ua.QualifiedName("Quality", 0)])
    assert (
        await quality_node.read_data_value(raise_on_bad_status=False)
    ).StatusCode.value == ua.StatusCodes.BadConditionDisabled
    enabled_node = await condition.node.get_child([ua.QualifiedName("EnabledState", 0)])
    assert (await enabled_node.read_data_value()).StatusCode.is_good()
    await call(rig, condition.condition_id, ENABLE)
    enabled = (await rig.count(collector, 3))[-1]
    assert (field(enabled, "Retain"), field(enabled, "ActiveState/Id")) == (True, True)
    assert active.EventId != enabled.EventId


async def test_severity_and_quality_changes_are_events(condition_rig: ConditionRig) -> None:
    """Part 9, 4.6, 5.5.2: a change of Severity or Quality is a Condition Event; LastSeverity holds the old one."""
    rig = condition_rig
    condition, _source, collector = await make(rig, severity=100)
    await condition.activate(severity=400)
    await condition.set_severity(900)
    await condition.set_quality(ua.StatusCode(ua.StatusCodes.UncertainSensorNotAccurate))
    events = await rig.count(collector, 3)
    assert (field(events[1], "Severity"), field(events[1], "LastSeverity")) == (900, 400)
    assert field(events[2], "Quality").value == ua.StatusCodes.UncertainSensorNotAccurate


async def test_server_side_comment_and_method_comment_set_the_user(condition_rig: ConditionRig) -> None:
    """Part 9, 5.5.6: AddComment sends the Event of the state; ClientUserId is the caller."""
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [event] = await rig.count(collector, 1)
    await call(rig, condition.condition_id, ADD_COMMENT, *ack_args(event.EventId, "checked valve"))
    commented = (await rig.count(collector, 2))[-1]
    assert field(commented, "Comment").Text == "checked valve"
    assert field(commented, "ClientUserId") == "Admin"
    assert field(commented, "AckedState/Id") is False


@pytest.mark.parametrize(
    "arguments, expected",
    [
        pytest.param(lambda eid: ack_args(b"nope"), ua.StatusCodes.BadEventIdUnknown, id="unknown_event_id"),
        pytest.param(lambda eid: ack_args(eid, None), ua.StatusCodes.BadInvalidArgument, id="null_comment"),
        pytest.param(lambda eid: ack_args(eid, "x" * 5000), ua.StatusCodes.BadInvalidArgument, id="too_long"),
    ],
)
async def test_add_comment_errors(condition_rig: ConditionRig, arguments: Any, expected: int) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [event] = await rig.count(collector, 1)
    assert await status_of(rig, condition.condition_id, ADD_COMMENT, *arguments(event.EventId)) == expected


async def test_acknowledge_applies_the_comment_and_reports_errors(condition_rig: ConditionRig) -> None:
    """Part 9, 5.7.3: errors of Acknowledge; a null comment is ignored, an empty text with a locale resets it."""
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [event] = await rig.count(collector, 1)
    assert await status_of(rig, condition.condition_id, ACK, *ack_args(b"nope")) == ua.StatusCodes.BadEventIdUnknown
    await call(rig, condition.condition_id, ACK, *ack_args(event.EventId, None))
    acked = (await rig.count(collector, 2))[-1]
    assert field(acked, "AckedState/Id") is True
    assert not field(acked, "Comment") or not field(acked, "Comment").Text
    status = await status_of(rig, condition.condition_id, ACK, *ack_args(acked.EventId))
    assert status == ua.StatusCodes.BadConditionBranchAlreadyAcked


async def test_methods_on_the_type_node_are_refused(condition_rig: ConditionRig) -> None:
    """Part 9, 5.5.4 to 5.7.3: the Methods cannot be called with the ConditionType as ObjectId (the Call service
    refuses the Method declaration of a type with Bad_MethodInvalid)."""
    rig = condition_rig
    for type_id, method in (
        (ua.ObjectIds.ConditionType, ENABLE),
        (ua.ObjectIds.ConditionType, DISABLE),
        (ua.ObjectIds.AcknowledgeableConditionType, ACK),
    ):
        args = ack_args(b"x") if method == ACK else []
        assert await status_of(rig, ua.NodeId(type_id), method, *args) == ua.StatusCodes.BadMethodInvalid


async def test_methods_work_through_the_instance_method_nodes(condition_rig: ConditionRig) -> None:
    """Part 9, 5.5.4: calls with the instance's own Method node work like the well-known MethodId."""
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [event] = await rig.count(collector, 1)
    method = await condition.node.get_child([ua.QualifiedName("Acknowledge", 0)])
    await call(rig, condition.condition_id, method.nodeid, *ack_args(event.EventId))
    assert condition.acked is True


async def test_old_event_ids_are_unknown_after_a_state_change(condition_rig: ConditionRig) -> None:
    """Part 9, 5.7.3: only Events of the current state can be acknowledged."""
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [first] = await rig.count(collector, 1)
    await condition.deactivate()
    await condition.activate(severity=500)
    await rig.count(collector, 3)
    assert (
        await status_of(rig, condition.condition_id, ACK, *ack_args(first.EventId)) == ua.StatusCodes.BadEventIdUnknown
    )


async def test_the_events_of_one_state_all_acknowledge_it(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [first] = await rig.count(collector, 1)
    await condition.set_severity(600)
    await rig.count(collector, 2)
    await call(rig, condition.condition_id, ACK, *ack_args(first.EventId))
    assert condition.acked is True


async def test_deleting_a_condition_sends_the_final_event(condition_rig: ConditionRig) -> None:
    """Part 9, 4.2: the last Event of a retained Condition has Retain false."""
    rig = condition_rig
    condition, source, collector = await make(rig)
    await condition.activate(severity=500)
    await rig.count(collector, 1)
    await rig.server.delete_condition(condition)
    final = (await rig.count(collector, 2))[-1]
    assert field(final, "Retain") is False
    assert rig.server.get_condition(condition.condition_id) is None
    assert await source.get_referenced_nodes(refs=ua.ObjectIds.HasCondition) == []


async def test_client_user_id_is_the_calling_users_name(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    [event] = await rig.count(collector, 1)
    await call(rig, condition.condition_id, ACK, *ack_args(event.EventId, "mine"), user=True)
    acked = (await rig.count(collector, 2))[-1]
    assert field(acked, "ClientUserId") == "User"


async def test_branches_are_created_when_an_unacknowledged_state_changes(condition_rig: ConditionRig) -> None:
    """Part 9, 4.4, B.1.3: the unacknowledged activation becomes a branch when the alarm returns to normal."""
    rig = condition_rig
    condition, _source, collector = await make(rig, branches=True)
    await condition.activate(severity=500)
    await condition.deactivate()
    events = await rig.count(collector, 3)
    trunk_active, branch, trunk_inactive = events
    assert field(branch, "BranchId") != ua.NodeId()
    assert (field(branch, "ActiveState/Id"), field(branch, "AckedState/Id"), field(branch, "Retain")) == (
        True,
        False,
        True,
    )
    assert (field(trunk_inactive, "BranchId"), field(trunk_inactive, "AckedState/Id")) == (ua.NodeId(), True)
    assert condition.branches == [field(branch, "BranchId")]
    assert field(trunk_active, "BranchId") == ua.NodeId()
    await call(rig, condition.condition_id, ACK, *ack_args(branch.EventId))
    closed = (await rig.count(collector, 4))[-1]
    assert field(closed, "BranchId") == field(branch, "BranchId")
    assert field(closed, "Retain") is False
    assert condition.branches == []


async def test_branches_stay_off_unless_asked_for(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig)
    await condition.activate(severity=500)
    await condition.deactivate()
    events = await rig.count(collector, 2)
    assert all(field(event, "BranchId") == ua.NodeId() for event in events)
    assert condition.branches == []


async def test_exclusive_level_alarm_states_and_deadband(condition_rig: ConditionRig) -> None:
    """Part 9, 5.8.18, 5.8.19: tiers, severities per limit, deadband on the way down, LimitState."""
    rig = condition_rig
    condition, _source, collector = await make(
        rig,
        LEVEL,
        limits={"HighHigh": 90.0, "High": 70.0, "Low": 30.0, "LowLow": 10.0},
        deadbands={"High": 5.0},
        severities={"HighHigh": 900, "High": 600, "Low": 600, "LowLow": 900},
    )
    for value in (50.0, 75.0, 95.0, 85.0, 68.0, 66.0, 64.0, 5.0):
        await condition.update_value(value)
    events = await rig.count(collector, 5)
    states = [(field(e, "LimitState/CurrentState"), field(e, "Severity"), field(e, "ActiveState/Id")) for e in events]
    names = [s[0].Text if s[0] is not None else None for s in states]
    assert names == ["High", "HighHigh", "High", None, "LowLow"]
    assert [s[1] for s in states][:3] == [600, 900, 600]
    assert field(events[1], "AckedState/Id") is False
    assert field(events[3], "ActiveState/Id") is False


async def test_non_exclusive_level_alarm_states(condition_rig: ConditionRig) -> None:
    """Part 9, 4.9, 5.8.20: both High and HighHigh are true above the HighHigh limit."""
    rig = condition_rig
    condition, _source, collector = await make(rig, NON_EXCLUSIVE, limits={"HighHigh": 90.0, "High": 70.0})
    await condition.update_value(95.0)
    await condition.update_value(80.0)
    first, second = await rig.count(collector, 2)
    assert (field(first, "HighHighState/Id"), field(first, "HighState/Id")) == (True, True)
    assert (field(second, "HighHighState/Id"), field(second, "HighState/Id")) == (False, True)
    assert field(second, "ActiveState/Id") is True


async def test_limits_in_the_wrong_order_are_rejected(condition_rig: ConditionRig) -> None:
    """Part 9, 5.8.18: HighLimit must be above LowLimit, plus the deadband rules."""
    rig = condition_rig
    source = await rig.source()
    with pytest.raises(ValueError):
        await rig.server.create_condition(source, ua.NodeId(LEVEL), "bad", limits={"High": 10.0, "Low": 20.0})
    with pytest.raises(ValueError):
        await rig.server.create_condition(
            source, ua.NodeId(LEVEL), "bad2", limits={"High": 10.0, "HighHigh": 12.0}, deadbands={"HighHigh": 3.0}
        )


async def test_deviation_alarm_compares_value_minus_setpoint(condition_rig: ConditionRig) -> None:
    """Part 9, 5.8.22: the limits are relative to the setpoint."""
    rig = condition_rig
    condition, _source, collector = await make(rig, DEVIATION, limits={"High": 2.0, "Low": -1.0})
    with pytest.raises(ValueError):
        await condition.update_value(11.0)
    await condition.update_value(11.0, setpoint=10.0)
    await condition.update_value(12.5, setpoint=10.0)
    await condition.update_value(8.5, setpoint=10.0)
    events = await rig.count(collector, 2)
    assert field(events[0], "ActiveState/Id") is True
    assert field(events[1], "LimitState/CurrentState").Text == "Low"


async def test_off_normal_alarm_follows_the_value(condition_rig: ConditionRig) -> None:
    """Part 9, 5.8.24.2: active exactly while the value differs from the normal value."""
    rig = condition_rig
    condition, _source, collector = await make(rig, OFF_NORMAL, normal_value=0)
    await condition.update_value(0)
    await condition.update_value(2)
    await condition.update_value(3)
    await condition.update_value(0)
    events = await rig.count(collector, 2)
    assert [field(e, "ActiveState/Id") for e in events] == [True, False]


async def test_following_the_input_node_updates_the_alarm(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    source = await rig.source()
    sensor = await rig.server.nodes.objects.add_variable(rig.ns, rig.unique("Sensor"), 20.0)
    await sensor.set_writable()
    condition = await rig.server.create_condition(
        source, ua.NodeId(LEVEL), rig.unique("Follow"), limits={"High": 50.0}, input_node=sensor, follow_input=True
    )
    collector, _sub = await rig.watch(source, LEVEL)
    await sensor.write_value(60.0)
    [event] = await rig.count(collector, 1)
    assert field(event, "ActiveState/Id") is True
    assert field(event, "InputNode") == sensor.nodeid
    assert condition.active is True


async def test_timed_shelve_expires_and_reports_state(condition_rig: ConditionRig) -> None:
    """Part 9, 5.8.17: TimedShelve, automatic unshelve, SuppressedOrShelved, errors."""
    rig = condition_rig
    condition, _source, collector = await make(rig, shelving=True, max_time_shelved=60_000.0)
    shelving_id = (await condition.node.get_child([ua.QualifiedName("ShelvingState", 0)])).nodeid
    await condition.activate(severity=500)
    await call(rig, shelving_id, TIMED_SHELVE, variant(30_000.0, ua.VariantType.Double))
    events = await rig.count(collector, 2)
    shelved = events[-1]
    assert field(shelved, "ShelvingState/CurrentState").Text == "TimedShelved"
    assert field(shelved, "SuppressedOrShelved") is True
    code = await status_of(rig, condition.condition_id, TIMED_SHELVE, variant(100.0, ua.VariantType.Double))
    assert code == ua.StatusCodes.BadConditionAlreadyShelved
    code = await status_of(rig, condition.condition_id, ONE_SHOT_SHELVE)
    assert code == 0
    await call(rig, condition.condition_id, UNSHELVE)
    assert await status_of(rig, condition.condition_id, UNSHELVE) == ua.StatusCodes.BadConditionNotShelved
    await call(rig, condition.condition_id, TIMED_SHELVE, variant(150.0, ua.VariantType.Double))
    await wait_until(lambda: condition.shelving_state == "Unshelved", timeout=3)
    await wait_until(lambda: field(collector.condition_events()[-1], "ShelvingState/CurrentState").Text == "Unshelved")
    assert field(collector.condition_events()[-1], "SuppressedOrShelved") is False


@pytest.mark.parametrize("duration", [0.0, -5.0, 120_000.0])
async def test_timed_shelve_time_out_of_range(condition_rig: ConditionRig, duration: float) -> None:
    rig = condition_rig
    condition, _source, _collector = await make(rig, shelving=True, max_time_shelved=60_000.0)
    code = await status_of(rig, condition.condition_id, TIMED_SHELVE, variant(duration, ua.VariantType.Double))
    assert code == ua.StatusCodes.BadShelvingTimeOutOfRange


async def test_one_shot_shelve_clears_when_the_alarm_returns_to_normal(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig, shelving=True)
    await condition.activate(severity=500)
    await call(rig, condition.condition_id, ONE_SHOT_SHELVE)
    assert condition.shelving_state == "OneShotShelved"
    assert await status_of(rig, condition.condition_id, ONE_SHOT_SHELVE) == ua.StatusCodes.BadConditionAlreadyShelved
    await condition.deactivate()
    assert condition.shelving_state == "Unshelved"
    events = await rig.count(collector, 3)
    assert field(events[-1], "ShelvingState/CurrentState").Text == "Unshelved"
    assert field(events[-1], "ActiveState/Id") is False


async def test_unshelve2_applies_the_comment(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig, shelving=True)
    await condition.activate(severity=500)
    await condition.shelve_one_shot()
    comment = variant(ua.LocalizedText("back"), ua.VariantType.LocalizedText)
    await call(rig, condition.condition_id, UNSHELVE2, comment)
    last = (await rig.count(collector, 3))[-1]
    assert field(last, "Comment").Text == "back"


async def test_shelving_methods_need_a_shelving_state_and_an_enabled_condition(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    plain, _source, _collector = await make(rig)
    assert await status_of(rig, plain.condition_id, UNSHELVE) == ua.StatusCodes.BadMethodInvalid
    shelving, _source2, _collector2 = await make(rig, shelving=True)
    await shelving.disable()
    assert await status_of(rig, shelving.condition_id, ONE_SHOT_SHELVE) == ua.StatusCodes.BadConditionDisabled


async def test_suppressed_and_out_of_service_flags(condition_rig: ConditionRig) -> None:
    rig = condition_rig
    condition, _source, collector = await make(rig, suppression=True)
    await condition.activate(severity=500)
    await condition.set_out_of_service(True)
    events = await rig.count(collector, 2)
    assert field(events[1], "OutOfServiceState/Id") is True
    assert field(events[1], "SuppressedOrShelved") is True

"""Filters of monitored items: DataChangeFilter, deadbands and the filter family of an item."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.server.data_change import data_change_passes
from tests.monitoring import create_items, item_request, make_server, modify_items, open_subscription, publish


@pytest.fixture(scope="module")
async def server() -> AsyncIterator[Server]:
    srv = await make_server()
    yield srv


async def new_double(server: Server, name: str, value: Any = 0.0, eu_range: tuple[float, float] | None = None) -> Any:
    node = await server.nodes.objects.add_variable(2, name, value, ua.VariantType.Double)
    if eu_range is not None:
        await node.add_property(
            2,
            "EURange",
            ua.Range(Low=eu_range[0], High=eu_range[1]),
            datatype=ua.NodeId(ua.ObjectIds.Range),
        )
    return node


async def write(
    server: Server, nodeid: ua.NodeId, value: Any, vtype: ua.VariantType = ua.VariantType.Double, **kw: Any
) -> None:
    dv = ua.DataValue(ua.Variant(value, vtype), **kw)
    await server.iserver.aspace.write_attribute_value(nodeid, ua.AttributeIds.Value, dv)


def deadband(
    kind: ua.DeadbandType, value: float, trigger: ua.DataChangeTrigger = ua.DataChangeTrigger.StatusValue
) -> Any:
    return ua.DataChangeFilter(Trigger=trigger, DeadbandType=kind, DeadbandValue=value)


def reported(notifications: list[Any]) -> list[Any]:
    return [n.Value.Value.Value for n in notifications]


async def watch(server: Server, nodeid: ua.NodeId, flt: Any, queue: int = 20) -> tuple[Any, Any]:
    sub, wire = await open_subscription(server)
    [result] = await create_items(server, sub, item_request(nodeid, queue=queue, filter=flt))
    assert result.StatusCode.is_good(), result.StatusCode
    return sub, wire


async def test_srv14_absolute_deadband_compares_with_the_last_reported_value(server: Server) -> None:
    """Part 4, 7.22.2: the deadband is measured from the last value that was reported."""
    node = await new_double(server, "DriftAbsolute", 0.0)
    sub, wire = await watch(server, node.nodeid, deadband(ua.DeadbandType.Absolute, 10.0))
    for value in (4.0, 8.0, 12.0, 15.0):
        await write(server, node.nodeid, value)
    assert reported(await publish(sub, wire)) == [0.0, 12.0]


async def test_srv14_percent_deadband_uses_the_eu_range(server: Server) -> None:
    """Part 4, 7.22.2 and Part 8, 7.2: Percent is a share of High minus Low of the EURange property."""
    node = await new_double(server, "PercentDeadband", 0.0, eu_range=(0.0, 200.0))
    sub, wire = await watch(server, node.nodeid, deadband(ua.DeadbandType.Percent, 10.0))
    for value in (15.0, 25.0):
        await write(server, node.nodeid, value)
    assert reported(await publish(sub, wire)) == [0.0, 25.0]


async def test_srv14_percent_deadband_without_eu_range_is_refused(server: Server) -> None:
    """Part 4, 7.22.2: Bad_DeadbandFilterInvalid."""
    node = await new_double(server, "PercentNoRange", 0.0)
    sub, _ = await open_subscription(server)
    [result] = await create_items(
        server, sub, item_request(node.nodeid, filter=deadband(ua.DeadbandType.Percent, 10.0))
    )
    assert result.StatusCode.value == ua.StatusCodes.BadDeadbandFilterInvalid


@pytest.mark.parametrize("kind, value", [(ua.DeadbandType.Absolute, -1.0), (ua.DeadbandType.Absolute, float("nan"))])
async def test_srv14_a_negative_or_nan_deadband_is_refused(server: Server, kind: ua.DeadbandType, value: float) -> None:
    """Part 4, 7.22.2."""
    node = await new_double(server, f"BadDeadband{value}", 0.0)
    sub, _ = await open_subscription(server)
    [result] = await create_items(server, sub, item_request(node.nodeid, filter=deadband(kind, value)))
    assert result.StatusCode.value == ua.StatusCodes.BadDeadbandFilterInvalid


async def test_srv14_a_deadband_on_a_string_variable_is_not_allowed(server: Server) -> None:
    """Part 4, 7.22.2: a deadband applies to numeric values only."""
    node = await server.nodes.objects.add_variable(2, "StringDeadband", "text")
    sub, _ = await open_subscription(server)
    [result] = await create_items(
        server, sub, item_request(node.nodeid, filter=deadband(ua.DeadbandType.Absolute, 1.0))
    )
    assert result.StatusCode.value == ua.StatusCodes.BadFilterNotAllowed


async def test_srv14_a_deadband_on_an_array_reports_when_an_element_exceeds_it(server: Server) -> None:
    """Part 4, 7.22.2: the whole array is reported if any element differs by more than the deadband."""
    node = await server.nodes.objects.add_variable(2, "ArrayDeadband", [1.0, 2.0, 3.0], ua.VariantType.Double)
    sub, wire = await watch(server, node.nodeid, deadband(ua.DeadbandType.Absolute, 5.0))
    await write(server, node.nodeid, [1.0, 2.0, 4.0])
    await write(server, node.nodeid, [1.0, 2.0, 9.0])
    assert reported(await publish(sub, wire)) == [[1.0, 2.0, 3.0], [1.0, 2.0, 9.0]]


def test_srv14_a_non_numeric_sample_under_a_deadband_is_compared_for_equality() -> None:
    """Part 4, 7.22.2: no TypeError, a changed string is reported and an equal one is not."""
    flt = deadband(ua.DeadbandType.Absolute, 5.0)
    text = ua.DataValue(ua.Variant("a", ua.VariantType.String))
    assert not data_change_passes(text, ua.DataValue(ua.Variant("a", ua.VariantType.String)), flt, None)
    assert data_change_passes(text, ua.DataValue(ua.Variant("b", ua.VariantType.String)), flt, None)


@pytest.mark.parametrize("first, second, changes", [(float("nan"), float("nan"), False), (float("nan"), 1.0, True)])
def test_srv14_a_change_from_nan_counts_but_nan_to_nan_does_not(first: float, second: float, changes: bool) -> None:
    """Part 4, 7.22.2."""
    flt = deadband(ua.DeadbandType.Absolute, 5.0)
    last = ua.DataValue(ua.Variant(first, ua.VariantType.Double))
    assert data_change_passes(last, ua.DataValue(ua.Variant(second, ua.VariantType.Double)), flt, None) is changes


async def test_srv14_trigger_status_ignores_value_changes(server: Server) -> None:
    """Part 4, 7.22.2: Status reports only a change of the StatusCode."""
    node = await new_double(server, "TriggerStatus", 0.0)
    sub, wire = await watch(server, node.nodeid, deadband(ua.DeadbandType.None_, 0.0, ua.DataChangeTrigger.Status))
    await write(server, node.nodeid, 5.0)
    await write(server, node.nodeid, 6.0)
    await write(server, node.nodeid, 7.0, StatusCode=ua.StatusCode(ua.StatusCodes.Uncertain))
    assert reported(await publish(sub, wire)) == [0.0, 7.0]


async def test_srv14_trigger_status_value_timestamp_reports_a_new_source_timestamp(server: Server) -> None:
    """Part 4, 7.22.2."""
    node = await new_double(server, "TriggerTimestamp", 0.0)
    now = datetime.now(UTC)
    await write(server, node.nodeid, 1.0, SourceTimestamp=now)
    flt = deadband(ua.DeadbandType.None_, 0.0, ua.DataChangeTrigger.StatusValueTimestamp)
    sub, wire = await watch(server, node.nodeid, flt)
    await write(server, node.nodeid, 1.0, SourceTimestamp=now)
    await write(server, node.nodeid, 1.0, SourceTimestamp=now + timedelta(seconds=1))
    assert reported(await publish(sub, wire)) == [1.0, 1.0]


async def test_srv14_trigger_status_value_ignores_a_new_source_timestamp(server: Server) -> None:
    """Part 4, 7.22.2: the default trigger does not look at timestamps."""
    node = await new_double(server, "TriggerValue", 0.0)
    now = datetime.now(UTC)
    sub, wire = await watch(server, node.nodeid, None)
    await write(server, node.nodeid, 0.0, SourceTimestamp=now)
    assert reported(await publish(sub, wire)) == [0.0]


async def test_srv14_an_unknown_trigger_is_refused(server: Server) -> None:
    """Part 4, 7.22.2."""
    node = await new_double(server, "TriggerUnknown", 0.0)
    sub, _ = await open_subscription(server)
    [result] = await create_items(server, sub, item_request(node.nodeid, filter=ua.DataChangeFilter(Trigger=9)))
    assert result.StatusCode.value == ua.StatusCodes.BadMonitoredItemFilterInvalid


@pytest.mark.parametrize(
    "attribute, flt, expected",
    [
        (ua.AttributeIds.Value, ua.EventFilter(), ua.StatusCodes.BadFilterNotAllowed),
        (ua.AttributeIds.Value, ua.AggregateFilter(), ua.StatusCodes.BadMonitoredItemFilterUnsupported),
        (ua.AttributeIds.DisplayName, ua.DataChangeFilter(), ua.StatusCodes.BadFilterNotAllowed),
        (ua.AttributeIds.EventNotifier, ua.DataChangeFilter(), ua.StatusCodes.BadFilterNotAllowed),
        (ua.AttributeIds.EventNotifier, None, ua.StatusCodes.BadMonitoredItemFilterInvalid),
    ],
)
async def test_srv14_the_filter_must_fit_the_attribute(
    server: Server, attribute: ua.AttributeIds, flt: Any, expected: int
) -> None:
    """Part 4, 5.13.2.4 and 7.22.1."""
    node = await new_double(server, f"Family{attribute.name}{type(flt).__name__}", 0.0)
    sub, _ = await open_subscription(server)
    target = ua.NodeId(ua.ObjectIds.Server) if attribute == ua.AttributeIds.EventNotifier else node.nodeid
    ok, result = await create_items(server, sub, item_request(node.nodeid), item_request(target, attribute, filter=flt))
    assert ok.StatusCode.is_good()
    assert result.StatusCode.value == expected


async def test_srv14_an_event_item_without_a_filter_fails_only_that_item(server: Server) -> None:
    """Part 4, 5.13.2.4: Bad_MonitoredItemFilterInvalid for the item, not an error of the request."""
    node = await new_double(server, "NoEventFilter", 0.0)
    sub, _ = await open_subscription(server)
    event_item = item_request(ua.NodeId(ua.ObjectIds.Server), ua.AttributeIds.EventNotifier, handle=1)
    bad, good = await create_items(server, sub, event_item, item_request(node.nodeid, handle=2))
    assert bad.StatusCode.value == ua.StatusCodes.BadMonitoredItemFilterInvalid
    assert good.StatusCode.is_good()


async def test_srv14_an_event_item_on_an_unknown_node_is_node_id_unknown(server: Server) -> None:
    """Part 4, 5.13.2.4."""
    sub, _ = await open_subscription(server)
    [result] = await create_items(
        server,
        sub,
        item_request(ua.NodeId(777777, 2), ua.AttributeIds.EventNotifier, filter=ua.EventFilter()),
    )
    assert result.StatusCode.value == ua.StatusCodes.BadNodeIdUnknown


async def test_srv14_an_event_item_on_a_node_without_event_notifier_is_node_id_invalid(server: Server) -> None:
    """Part 4, 5.13.2.4."""
    obj = await server.nodes.objects.add_object(2, "NotANotifier")
    await obj.write_attribute(ua.AttributeIds.EventNotifier, ua.DataValue(ua.Variant(0, ua.VariantType.Byte)))
    sub, _ = await open_subscription(server)
    [result] = await create_items(
        server, sub, item_request(obj.nodeid, ua.AttributeIds.EventNotifier, filter=ua.EventFilter())
    )
    assert result.StatusCode.value == ua.StatusCodes.BadNodeIdInvalid


async def test_srv14_modify_with_a_null_filter_removes_the_filter(server: Server) -> None:
    """Part 4, 5.13.3: Modify replaces all parameters, a null filter removes the old one."""
    node = await new_double(server, "ModifyNullFilter", 0.0)
    sub, wire = await watch(server, node.nodeid, deadband(ua.DeadbandType.Absolute, 10.0))
    [mid] = list(sub.monitored_item_srv._monitored_items)
    params = ua.MonitoringParameters(ClientHandle=1, SamplingInterval=100, QueueSize=20, DiscardOldest=True)
    [result] = modify_items(server, sub, (mid, params))
    assert result.StatusCode.is_good()
    await write(server, node.nodeid, 1.0)
    assert reported(await publish(sub, wire)) == [0.0, 1.0]


async def test_srv14_modify_with_a_failing_filter_leaves_the_item_unchanged(server: Server) -> None:
    """Part 4, 5.13.3.3."""
    node = await new_double(server, "ModifyBadFilter", 0.0)
    sub, wire = await watch(server, node.nodeid, deadband(ua.DeadbandType.Absolute, 10.0))
    [mid] = list(sub.monitored_item_srv._monitored_items)
    params = ua.MonitoringParameters(
        ClientHandle=1, SamplingInterval=100, QueueSize=20, DiscardOldest=True, Filter=ua.EventFilter()
    )
    [result] = modify_items(server, sub, (mid, params))
    assert result.StatusCode.value == ua.StatusCodes.BadFilterNotAllowed
    await write(server, node.nodeid, 1.0)
    assert reported(await publish(sub, wire)) == [0.0]

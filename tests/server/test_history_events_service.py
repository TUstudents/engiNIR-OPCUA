import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from enginir_opcua import ua
from enginir_opcua.common.node import Node
from enginir_opcua.server.history import TimeDomain
from tests.history_rig import HistoryRig, at


def severity_filter(minimum: int | None) -> ua.EventFilter:
    select = ua.SimpleAttributeOperand(
        TypeDefinitionId=ua.NodeId(ua.ObjectIds.BaseEventType),
        BrowsePath=[ua.QualifiedName("Severity", 0)],
        AttributeId=ua.AttributeIds.Value,
    )
    event_filter = ua.EventFilter(SelectClauses=[select])
    if minimum is not None:
        element = ua.ContentFilterElement(
            FilterOperator=ua.FilterOperator.GreaterThan,
            FilterOperands=[select, ua.LiteralOperand(Value=ua.Variant(minimum, ua.VariantType.UInt16))],
        )
        event_filter.WhereClause = ua.ContentFilter(Elements=[element])
    return event_filter


async def read_events(
    rig: HistoryRig,
    node: Node,
    event_filter: ua.EventFilter,
    count: int = 0,
    token: bytes | None = None,
    start: float = 0,
    end: float = 1000,
) -> ua.HistoryReadResult:
    details = ua.ReadEventDetails(StartTime=at(start), EndTime=at(end), NumValuesPerNode=count, Filter=event_filter)
    return (await rig.request(details, node, token=token))[0]


def severities(result: ua.HistoryReadResult) -> list[int]:
    return [row.EventFields[0].Value for row in result.HistoryData.Events]


async def emit(rig: HistoryRig, source: ua.NodeId, values: list[tuple[float, int]]) -> None:
    generator = await rig.server.get_event_generator(emitting_node=source)
    for seconds, severity in values:
        generator.event.Severity = severity
        await generator.trigger(time_attr=at(seconds), message="message")
    await rig.server.iserver.history_manager._queue.join()


async def test_srv61_history_read_events_applies_the_where_clause(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.2.2; Part 4, 7.22.3."""
    source = await history_rig.server.nodes.objects.add_object(ua.NodeId("Where", history_rig.ns), "Where")
    await history_rig.server.historize_node_event(source, period=None)
    await emit(history_rig, source.nodeid, [(1, 100), (2, 600), (3, 200), (4, 700), (5, 800)])
    result = await read_events(history_rig, source, severity_filter(500))
    assert severities(result) == [600, 700, 800]
    everything = await read_events(history_rig, source, severity_filter(None))
    assert severities(everything) == [100, 600, 200, 700, 800]
    first = await read_events(history_rig, source, severity_filter(500), count=2)
    assert severities(first) == [600, 700]
    assert first.ContinuationPoint
    second = await read_events(history_rig, source, severity_filter(500), count=2, token=first.ContinuationPoint)
    assert severities(second) == [800]
    assert not second.ContinuationPoint


async def test_history_read_events_without_select_clause(history_rig: HistoryRig) -> None:
    """Part 4, 7.22.3."""
    source = await history_rig.server.nodes.objects.add_object(ua.NodeId("NoSelect", history_rig.ns), "NoSelect")
    await history_rig.server.historize_node_event(source, period=None)
    result = await read_events(history_rig, source, ua.EventFilter())
    assert result.StatusCode == ua.StatusCode(ua.StatusCodes.BadEventFilterInvalid)


async def test_srv21_event_history_for_a_source_other_than_the_server_object(history_rig: HistoryRig) -> None:
    """Part 11, 5.4.4."""
    source = await history_rig.server.nodes.objects.add_object(ua.NodeId("Boiler", history_rig.ns), "Boiler")
    await history_rig.server.historize_node_event(source, period=None)
    assert ua.EventNotifier.HistoryRead in await source.read_event_notifier()
    await emit(history_rig, source.nodeid, [(1, 100), (2, 200)])
    result = await read_events(history_rig, source, severity_filter(None))
    assert severities(result) == [100, 200]
    assert (await history_rig.storage.has_event(source.nodeid)) is True


async def test_srv21_historize_before_generator_stores_events(history_rig: HistoryRig) -> None:
    """Part 11, 5.4.4: the order of historize_event and the creation of the generators does not matter."""
    source = await history_rig.server.nodes.objects.add_object(ua.NodeId("Early", history_rig.ns), "Early")
    await history_rig.server.historize_node_event(source, period=None)
    etype = await history_rig.server.create_custom_event_type(
        history_rig.ns, "EarlyEvent", ua.ObjectIds.BaseEventType, [("Level", ua.VariantType.Int32)]
    )
    generator = await history_rig.server.get_event_generator(etype, source.nodeid)
    generator.event.Level = 5
    generator.event.Severity = 300
    await generator.trigger(time_attr=at(1), message="custom")
    await history_rig.server.iserver.history_manager._queue.join()
    result = await read_events(history_rig, source, severity_filter(None))
    assert severities(result) == [300]
    page = await history_rig.storage.read_event_history(source.nodeid, TimeDomain(None, None, 10))
    assert page.entries[0].value["Level"].Value == 5


async def test_srv21_notifier_history_contains_events_of_sources_below_it(history_rig: HistoryRig) -> None:
    """Part 11, 5.4.4."""
    plant = await history_rig.server.nodes.objects.add_object(ua.NodeId("Plant", history_rig.ns), "Plant")
    machine = await history_rig.server.nodes.objects.add_object(ua.NodeId("Machine", history_rig.ns), "Machine")
    await plant.add_reference(machine, ua.NodeId(ua.ObjectIds.HasEventSource))
    await history_rig.server.historize_node_event(plant, period=None)
    await emit(history_rig, machine.nodeid, [(1, 400)])
    await emit(history_rig, plant.nodeid, [(2, 500)])
    result = await read_events(history_rig, plant, severity_filter(None))
    assert severities(result) == [400, 500]


async def test_srv21_dehistorize_event_keeps_the_stored_events(history_rig: HistoryRig) -> None:
    """Part 11, 5.4.4."""
    source = await history_rig.server.nodes.objects.add_object(ua.NodeId("Stopped", history_rig.ns), "Stopped")
    await history_rig.server.historize_node_event(source, period=None)
    await emit(history_rig, source.nodeid, [(1, 100)])
    await history_rig.server.dehistorize_node_event(source)
    await emit(history_rig, source.nodeid, [(2, 200)])
    assert ua.EventNotifier.HistoryRead not in await source.read_event_notifier()
    page = await history_rig.storage.read_event_history(source.nodeid, TimeDomain(None, None, 10))
    assert len(page.entries) == 1


def fields_of(**values: Any) -> dict[str, ua.Variant]:
    return {name: ua.Variant(value) for name, value in values.items()}


async def test_srv22_event_retention_by_count_and_period(history_rig: HistoryRig) -> None:
    """Part 11, 4.2."""
    counted = ua.NodeId("Counted", history_rig.ns)
    await history_rig.storage.new_historized_event(counted, None, 2)
    for seconds in range(1, 5):
        await history_rig.storage.save_event(counted, fields_of(Severity=seconds), at(seconds))
    page = await history_rig.storage.read_event_history(counted, TimeDomain(None, None, 10))
    assert [entry.value["Severity"].Value for entry in page.entries] == [3, 4]
    aged = ua.NodeId("Aged", history_rig.ns)
    await history_rig.storage.new_historized_event(aged, timedelta(hours=1))
    now = datetime.now(UTC)
    await history_rig.storage.save_event(aged, fields_of(Severity=1), now - timedelta(hours=2))
    await history_rig.storage.save_event(aged, fields_of(Severity=2), now)
    page = await history_rig.storage.read_event_history(aged, TimeDomain(None, None, 10))
    assert [entry.value["Severity"].Value for entry in page.entries] == [2]
    unique = ua.NodeId(uuid.UUID(int=7), history_rig.ns)
    await history_rig.storage.new_historized_event(unique, None)
    assert await history_rig.storage.has_event(unique)

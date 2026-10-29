import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest

from enginir_opcua import ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.client.ua_session import UaSession
from enginir_opcua.common.node import Node
from enginir_opcua.common.utils import ServiceError
from enginir_opcua.server.history import TimeDomain
from tests.history_rig import HistoryRig, at, numbers


def code(value: int) -> ua.StatusCode:
    return ua.StatusCode(value)


async def raises_status(awaitable, status: int) -> None:
    with pytest.raises(ua.UaStatusCodeError) as error:
        await awaitable
    assert error.value.code == status


async def test_srv20_processed_and_at_time_are_history_operation_unsupported(history_rig: HistoryRig) -> None:
    """Part 4, 5.11.3.3; Part 11, 6.5.1."""
    node = await history_rig.history_variable("Unsupported", [(1, 1)])
    for details in (
        ua.ReadProcessedDetails(StartTime=at(0), EndTime=at(10)),
        ua.ReadAtTimeDetails(ReqTimes=[at(1)]),
        ua.ReadAnnotationDataDetails(ReqTimes=[at(1)]),
        ua.ReadEventDetailsSorted(StartTime=at(0), EndTime=at(10)),
    ):
        await raises_status(history_rig.request(details, node), ua.StatusCodes.BadHistoryOperationUnsupported)


async def test_srv53_read_modified_is_unsupported(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.3."""
    node = await history_rig.history_variable("Modified", [(1, 1)])
    modified = ua.ReadRawModifiedDetails(IsReadModified=True, StartTime=at(0), EndTime=at(10))
    await raises_status(history_rig.request(modified, node), ua.StatusCodes.BadHistoryOperationUnsupported)
    events = ua.ReadEventDetails2(StartTime=at(0), EndTime=at(10), ReadModified=True)
    await raises_status(history_rig.request(events, node), ua.StatusCodes.BadHistoryOperationUnsupported)


async def test_srv58_history_read_timestamps_to_return_neither_is_invalid(history_rig: HistoryRig) -> None:
    """Part 4, 5.11.3.2, 7.39."""
    node = await history_rig.history_variable("Stamps", [(1, 1)])
    await raises_status(
        history_rig.read(node, 0, 10, timestamps=ua.TimestampsToReturn.Neither),
        ua.StatusCodes.BadTimestampsToReturnInvalid,
    )
    await raises_status(
        history_rig.read(node, 0, 10, timestamps=ua.TimestampsToReturn.Invalid),
        ua.StatusCodes.BadTimestampsToReturnInvalid,
    )


async def test_srv20_unknown_node(history_rig: HistoryRig) -> None:
    """Part 4, 5.11.3.4."""
    result = await history_rig.read(ua.NodeId("Nothing", history_rig.ns), 0, 10)
    assert result.StatusCode == code(ua.StatusCodes.BadNodeIdUnknown)
    result = await history_rig.read(ua.NodeId(), 0, 10)
    assert result.StatusCode == code(ua.StatusCodes.BadNodeIdInvalid)


async def test_srv20_node_without_history_read_bit_is_not_readable(history_rig: HistoryRig) -> None:
    """Part 3, 8.57."""
    node = await history_rig.server.nodes.objects.add_variable(ua.NodeId("Plain", history_rig.ns), "Plain", 1)
    result = await history_rig.read(node, 0, 10)
    assert result.StatusCode == code(ua.StatusCodes.BadNotReadable)


async def test_srv20_not_historized_is_operation_unsupported(history_rig: HistoryRig) -> None:
    """Part 4, 5.11.3.4."""
    node = await history_rig.server.nodes.objects.add_variable(ua.NodeId("Bit", history_rig.ns), "Bit", 1)
    for attribute in (ua.AttributeIds.AccessLevel, ua.AttributeIds.UserAccessLevel):
        await node.write_attribute(attribute, ua.DataValue(ua.Variant(5, ua.VariantType.Byte)))
    assert (await history_rig.read(node, 0, 10)).StatusCode == code(ua.StatusCodes.BadHistoryOperationUnsupported)
    folder = history_rig.server.nodes.objects
    assert (await history_rig.read(folder, 0, 10)).StatusCode == code(ua.StatusCodes.BadHistoryOperationUnsupported)


async def test_srv20_user_access_level_denies_history(history_rig: HistoryRig) -> None:
    """Part 3, 8.57."""
    node = await history_rig.history_variable("Denied", [(1, 1)])
    await node.write_attribute(ua.AttributeIds.UserAccessLevel, ua.DataValue(ua.Variant(1, ua.VariantType.Byte)))
    for client in (history_rig.user, history_rig.admin):
        result = await history_rig.read(node, 0, 10, client=client)
        assert result.StatusCode == code(ua.StatusCodes.BadUserAccessDenied)


async def test_srv20_fewer_than_two_of_start_end_count_is_invalid_argument(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.1."""
    node = await history_rig.history_variable("Invalid", [(1, 1)])
    for start, end, count in ((None, None, 0), (None, None, 3), (0, None, 0), (None, 10, 0)):
        result = await history_rig.read(node, start, end, count)
        assert result.StatusCode == code(ua.StatusCodes.BadInvalidArgument)


async def test_srv20_end_only_reads_backwards_from_end(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2."""
    node = await history_rig.history_variable("EndOnly", [(i, i) for i in range(1, 10)])
    result = await history_rig.read(node, None, 4, 3)
    assert numbers(result) == [4, 3, 2]
    assert not result.ContinuationPoint


async def test_srv20_start_equal_end_returns_entries_at_that_instant(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2."""
    node = await history_rig.history_variable("Instant", [(1, 1), (2, 2), (3, 3)])
    assert numbers(await history_rig.read(node, 2, 2)) == [2]
    assert (await history_rig.read(node, 2.5, 2.5)).StatusCode == code(ua.StatusCodes.GoodNoData)


async def test_srv20_both_times_forward_and_backward(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2."""
    node = await history_rig.history_variable("Directions", [(i, i) for i in range(1, 7)])
    assert numbers(await history_rig.read(node, 2, 5)) == [2, 3, 4, 5]
    assert numbers(await history_rig.read(node, 5, 2)) == [5, 4, 3, 2]
    assert numbers(await history_rig.read(node, 2, None, 2)) == [2, 3]


async def test_srv20_num_values_with_both_times_is_a_page_with_continuation_point(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2; Part 4, 7.9."""
    node = await history_rig.history_variable("Paged", [(i, i) for i in range(1, 8)])
    first = await history_rig.read(node, 1, 7, 3)
    assert numbers(first) == [1, 2, 3]
    assert first.ContinuationPoint
    second = await history_rig.read(node, 1, 7, 3, token=first.ContinuationPoint)
    assert numbers(second) == [4, 5, 6]
    third = await history_rig.read(node, 1, 7, 3, token=second.ContinuationPoint)
    assert numbers(third) == [7]
    assert not third.ContinuationPoint
    again = await history_rig.read(node, 1, 7, 3, token=third.ContinuationPoint or second.ContinuationPoint)
    assert again.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)


async def test_srv20_backward_pages_continue_backwards(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2."""
    node = await history_rig.history_variable("BackPaged", [(i, i) for i in range(1, 8)])
    first = await history_rig.read(node, 7, 1, 3)
    assert numbers(first) == [7, 6, 5]
    second = await history_rig.read(node, 7, 1, 3, token=first.ContinuationPoint)
    assert numbers(second) == [4, 3, 2]
    third = await history_rig.read(node, 7, 1, 3, token=second.ContinuationPoint)
    assert numbers(third) == [1]


async def test_srv20_empty_range_is_good_no_data(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2."""
    node = await history_rig.history_variable("Empty", [(1, 1)])
    result = await history_rig.read(node, 100, 200)
    assert result.StatusCode == code(ua.StatusCodes.GoodNoData)
    assert numbers(result) == []


async def test_srv20_release_continuation_points(history_rig: HistoryRig) -> None:
    """Part 4, 5.11.3.2."""
    node = await history_rig.history_variable("Released", [(i, i) for i in range(1, 8)])
    first = await history_rig.read(node, 1, 7, 3)
    details = ua.ReadRawModifiedDetails(IsReadModified=False, StartTime=at(1), EndTime=at(7), NumValuesPerNode=3)
    released = await history_rig.request(details, node, token=first.ContinuationPoint, release=True)
    assert released[0].StatusCode.is_good()
    assert not released[0].ContinuationPoint
    after = await history_rig.read(node, 1, 7, 3, token=first.ContinuationPoint)
    assert after.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)


async def test_srv20_foreign_or_stale_continuation_point_is_invalid(history_rig: HistoryRig) -> None:
    """Part 4, 5.11.3.2."""
    node = await history_rig.history_variable("Foreign", [(i, i) for i in range(1, 8)])
    first = await history_rig.read(node, 1, 7, 3)
    foreign = await history_rig.read(node, 1, 7, 3, token=first.ContinuationPoint, client=history_rig.admin)
    assert foreign.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)
    own = await history_rig.read(node, 1, 7, 3, token=first.ContinuationPoint)
    assert numbers(own) == [4, 5, 6]


async def test_srv20_changed_details_with_token_is_invalid(history_rig: HistoryRig) -> None:
    """Part 11, 6.3."""
    node = await history_rig.history_variable("Changed", [(i, i) for i in range(1, 8)])
    first = await history_rig.read(node, 1, 7, 3)
    other = await history_rig.read(node, 2, 7, 3, token=first.ContinuationPoint)
    assert other.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)


async def test_srv20_history_continuation_points_are_limited_per_session(history_rig: HistoryRig) -> None:
    """Part 4, 7.9."""
    node = await history_rig.history_variable("Limited", [(i, i) for i in range(1, 8)])
    history_rig.server.iserver.max_history_continuation_points = 2
    tokens = []
    for _ in range(3):
        result = await history_rig.read(node, 1, 7, 3)
        tokens.append(result.ContinuationPoint)
    assert (await history_rig.read(node, 1, 7, 3, token=tokens[0])).StatusCode == code(
        ua.StatusCodes.BadContinuationPointInvalid
    )
    assert numbers(await history_rig.read(node, 1, 7, 3, token=tokens[2])) == [4, 5, 6]
    details = ua.ReadRawModifiedDetails(IsReadModified=False, StartTime=at(1), EndTime=at(7), NumValuesPerNode=3)
    item = ua.HistoryReadValueId(NodeId=node.nodeid)
    params = ua.HistoryReadParameters(
        HistoryReadDetails=details,
        TimestampsToReturn=ua.TimestampsToReturn.Both,
        ReleaseContinuationPoints=False,
        NodesToRead=[item, item, item],
    )
    results = await history_rig.user.uaclient.history_read(params)
    assert [r.StatusCode for r in results][-1] == code(ua.StatusCodes.BadNoContinuationPoints)


async def test_srv20_pages_never_exceed_max_history_data_response_size(history_rig: HistoryRig) -> None:
    """Part 11, 5.7.2."""
    node = await history_rig.history_variable("Capped", [(i, i) for i in range(1, 8)])
    history_rig.server.iserver.max_history_data_response_size = 3
    first = await history_rig.read(node, 1, 7, 0)
    assert numbers(first) == [1, 2, 3]
    second = await history_rig.read(node, 1, 7, 0, token=first.ContinuationPoint)
    assert numbers(second) == [4, 5, 6]
    only_start = await history_rig.read(node, 1, None, 5)
    assert numbers(only_start) == [1, 2, 3]
    rest = await history_rig.read(node, 1, None, 5, token=only_start.ContinuationPoint)
    assert numbers(rest) == [4, 5]
    assert not rest.ContinuationPoint


async def test_srv20_timestamps_to_return_source_server_both(history_rig: HistoryRig) -> None:
    """Part 11, 4.5."""
    node = await history_rig.history_variable("Timestamps", [(1, 1)])
    source = (await history_rig.read(node, 0, 2, timestamps=ua.TimestampsToReturn.Source)).HistoryData.DataValues[0]
    assert source.SourceTimestamp == at(1)
    assert source.ServerTimestamp is None
    server = (await history_rig.read(node, 0, 2, timestamps=ua.TimestampsToReturn.Server)).HistoryData.DataValues[0]
    assert server.SourceTimestamp is None
    assert server.ServerTimestamp == at(1)
    both = (await history_rig.read(node, 0, 2)).HistoryData.DataValues[0]
    assert both.SourceTimestamp == at(1)
    assert both.ServerTimestamp == at(1)


async def test_srv20_equal_timestamps_return_the_latest_with_extra_data(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2: the most recent value is returned and the ExtraData bit is set."""
    node = await history_rig.history_variable("Equal", [(1, "a"), (2, "x"), (2, "y"), (2, "z"), (3, "b")])
    result = await history_rig.read(node, 0, 10)
    assert numbers(result) == ["a", "z", "b"]
    flags = [dv.StatusCode.value & 0x0008 for dv in result.HistoryData.DataValues]
    assert flags == [0, 0x0008, 0]
    backward = await history_rig.read(node, 10, 0)
    assert numbers(backward) == ["b", "z", "a"]


async def test_srv20_equal_timestamps_are_paged_without_repeat(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2."""
    values = [(1, "a"), (2, "x"), (2, "y"), (2, "z"), (3, "b"), (3, "c"), (4, "d")]
    node = await history_rig.history_variable("EqualPaged", values)
    first = await history_rig.read(node, 0, 10, 2)
    assert numbers(first) == ["a", "z"]
    second = await history_rig.read(node, 0, 10, 2, token=first.ContinuationPoint)
    assert numbers(second) == ["c", "d"]
    assert not second.ContinuationPoint


async def test_srv20_value_without_source_timestamp_is_stored_and_read(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.3.2."""
    node = await history_rig.history_variable("NoStamp", [])
    await history_rig.storage.save_node_value(node.nodeid, ua.DataValue(ua.Variant(7), ServerTimestamp=at(1)))
    await history_rig.storage.save_node_value(node.nodeid, ua.DataValue(ua.Variant(8)))
    result = await history_rig.read(node, 0, 2)
    assert numbers(result) == [7]
    page = await history_rig.storage.read_node_history(node.nodeid, TimeDomain(None, None, 10))
    assert len(page.entries) >= 2


async def test_srv15_history_read_index_range(history_rig: HistoryRig) -> None:
    """Part 11, 6.4; Part 4, 7.27."""
    node = await history_rig.history_variable("Ranged", [])
    await history_rig.save(node, 1, [1, 2, 3, 4])
    await history_rig.save(node, 2, [5])
    result = await history_rig.read(node, 0, 3, index_range="1:2")
    values = result.HistoryData.DataValues
    assert values[0].Value.Value == [2, 3]
    assert values[1].StatusCode == code(ua.StatusCodes.BadIndexRangeNoData)
    assert values[1].Value is None or values[1].Value.Value is None
    invalid = await history_rig.read(node, 0, 3, index_range="2:1")
    assert invalid.StatusCode == code(ua.StatusCodes.BadIndexRangeInvalid)


async def test_history_return_bounds_adds_the_values_around_the_range(history_rig: HistoryRig) -> None:
    """Part 11, 4.6, Table 1."""
    node = await history_rig.history_variable("Bounds", [(0, 100), (2, 102), (3, 103), (5, 105), (6, 106)])
    inside = await history_rig.read(node, 1, 4, bounds=True)
    assert numbers(inside) == [100, 102, 103, 105]
    exact = await history_rig.read(node, 0, 5, bounds=True)
    assert numbers(exact) == [100, 102, 103, 105]
    before = await history_rig.read(node, -1, 5, bounds=True)
    first = before.HistoryData.DataValues[0]
    assert first.StatusCode == code(ua.StatusCodes.BadBoundNotFound)
    assert first.SourceTimestamp == at(-1)
    assert numbers(before)[1:] == [100, 102, 103, 105]
    after = await history_rig.read(node, 1, 7, bounds=True)
    last = after.HistoryData.DataValues[-1]
    assert last.StatusCode == code(ua.StatusCodes.BadBoundNotFound)
    assert last.SourceTimestamp == at(7)
    backward = await history_rig.read(node, 4, 1, bounds=True)
    assert numbers(backward) == [105, 103, 102, 100]
    counted = await history_rig.read(node, 1, 4, 3, bounds=True)
    assert numbers(counted) == [100, 102, 103]
    without = await history_rig.read(node, 1, 4, bounds=False)
    assert numbers(without) == [102, 103]


async def test_srv22_event_history_service_reads_through_the_storage(history_rig: HistoryRig) -> None:
    """Part 11, 6.5.2."""
    result = await history_rig.read(history_rig.server.nodes.objects, 0, 10)
    assert result.StatusCode == code(ua.StatusCodes.BadHistoryOperationUnsupported)


async def test_srv19_history_update_is_service_unsupported(history_rig: HistoryRig) -> None:
    """Part 4, 5.11.5."""
    node = await history_rig.history_variable("Update", [(1, 1)])
    details = ua.DeleteRawModifiedDetails(NodeId=node.nodeid, IsDeleteModified=False, StartTime=at(0), EndTime=at(2))
    with pytest.raises(ServiceError) as error:
        await node.history_update(details)
    assert error.value.code == ua.StatusCodes.BadServiceUnsupported


async def test_srv21_capture_keeps_every_change_in_notification_order(history_rig: HistoryRig) -> None:
    """Part 11, 4.3."""
    var = await history_rig.server.nodes.objects.add_variable(ua.NodeId("Burst", history_rig.ns), "Burst", 0)
    await history_rig.server.historize_node_data_change(var, period=None)
    for value in range(1, 51):
        await var.write_value(value)
    await asyncio.sleep(0.5)
    page = await history_rig.storage.read_node_history(var.nodeid, TimeDomain(None, None, 1000))
    stored = [entry.value.Value.Value for entry in page.entries]
    assert stored == list(range(51))


async def test_srv62_history_capabilities_have_values(history_rig: HistoryRig) -> None:
    """Part 11, 5.7.2; Part 5, 6.3.2."""
    prefix = "HistoryServerCapabilities_"

    async def value_of(name: str) -> object:
        node = history_rig.server.get_node(ua.NodeId(getattr(ua.ObjectIds, prefix + name)))
        return await node.read_value()

    assert await value_of("AccessHistoryDataCapability") is True
    assert await value_of("AccessHistoryEventsCapability") is True
    assert await value_of("MaxReturnDataValues") == 10_000
    assert await value_of("MaxReturnEventValues") == 10_000
    assert await value_of("InsertDataCapability") is False
    assert await value_of("DeleteRawCapability") is False
    assert await value_of("ServerTimestampSupported") is True
    points = history_rig.server.get_node(ua.NodeId(ua.ObjectIds.Server_ServerCapabilities_MaxHistoryContinuationPoints))
    assert await points.read_value() == 10
    rate = history_rig.server.get_node(ua.NodeId(ua.ObjectIds.Server_ServerCapabilities_MinSupportedSampleRate))
    assert await rate.read_value() == history_rig.server.iserver.min_sampling_interval_ms


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


NODE_ID = ua.NodeId(123)


async def result_count(history):
    page = await history.read_node_history(NODE_ID, TimeDomain(None, None, 1000))
    return len(page.entries)


def add_value(history, age):
    value = ua.DataValue(SourceTimestamp=datetime.now(UTC) - timedelta(hours=age))
    return history.save_node_value(NODE_ID, value)


async def test_count_limit(history):
    await history.new_historized_node(NODE_ID, period=None, count=3)
    assert 0 == await result_count(history)
    await add_value(history, 5)
    assert 1 == await result_count(history)
    await add_value(history, 4)
    assert 2 == await result_count(history)
    await add_value(history, 3)
    assert 3 == await result_count(history)
    await add_value(history, 2)
    assert 3 == await result_count(history)
    await add_value(history, 1)
    assert 3 == await result_count(history)


async def test_period_limit(history):
    await history.new_historized_node(NODE_ID, period=timedelta(hours=3))
    assert 0 == await result_count(history)
    await add_value(history, 5)
    assert 0 == await result_count(history)
    await add_value(history, 4)
    assert 0 == await result_count(history)
    await add_value(history, 2)
    assert 1 == await result_count(history)
    await add_value(history, 1)
    assert 2 == await result_count(history)
    await add_value(history, 0)
    assert 3 == await result_count(history)


async def test_combined_limit(history):
    await history.new_historized_node(NODE_ID, period=timedelta(hours=3), count=2)
    assert 0 == await result_count(history)
    await add_value(history, 5)
    assert 0 == await result_count(history)
    await add_value(history, 4)
    assert 0 == await result_count(history)
    await add_value(history, 2)
    assert 1 == await result_count(history)
    await add_value(history, 1)
    assert 2 == await result_count(history)
    await add_value(history, 0)
    assert 2 == await result_count(history)


async def test_node_history_update_sends_details_and_returns_result():
    details = ua.UpdateDataDetails()
    result = ua.HistoryUpdateResult()
    session = AsyncMock()
    session.history_update.return_value = [result]
    node = Node(session, ua.NodeId(1234, 2))

    returned = await node.history_update(details)

    assert returned is result
    session.history_update.assert_awaited_once()
    params = session.history_update.await_args.args[0]
    assert params.HistoryUpdateDetails == [details]


async def test_node_history_update_raises_for_bad_status():
    details = ua.UpdateDataDetails()
    result = ua.HistoryUpdateResult()
    result.StatusCode = ua.StatusCode(ua.StatusCodes.BadNotWritable)
    session = AsyncMock()
    session.history_update.return_value = [result]
    node = Node(session, ua.NodeId(1234, 2))

    with pytest.raises(ua.UaStatusCodeError):
        await node.history_update(details)


async def test_ua_client_history_update_delegates_to_session():
    client = UaClient()
    expected = [ua.HistoryUpdateResult()]
    client.session.history_update = AsyncMock(return_value=expected)

    result = await client.history_update(ua.HistoryUpdateParameters())

    assert result == expected
    client.session.history_update.assert_awaited_once()


async def test_ua_session_history_update_builds_request(monkeypatch):
    client = AsyncMock()
    session = UaSession(client)
    params = ua.HistoryUpdateParameters()
    details = ua.UpdateDataDetails()
    params.HistoryUpdateDetails.append(details)
    response = ua.HistoryUpdateResponse()
    response.Results = [ua.HistoryUpdateResult()]
    session._send_request = AsyncMock(return_value=b"response")
    monkeypatch.setattr("enginir_opcua.client.ua_session.struct_from_binary", lambda _type, _data: response)

    result = await session.history_update(params)

    assert result == response.Results
    request = session._send_request.await_args.args[0]
    assert isinstance(request, ua.HistoryUpdateRequest)
    assert request.Parameters is params

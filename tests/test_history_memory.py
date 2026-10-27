from datetime import UTC, datetime, timedelta

from enginir_opcua import ua
from enginir_opcua.server.history import HistoryDict, TimeDomain

BASE = datetime(2026, 1, 1, tzinfo=UTC)


async def test_srv66_memory_backend_orders_late_values() -> None:
    """Part 11, 6.5.3.2: a value with an older timestamp lands before newer ones."""
    history = HistoryDict()
    node_id = ua.NodeId("Late", 2)
    await history.new_historized_node(node_id, None)
    for seconds in (5, 1, 3, 2, 4):
        await history.save_node_value(
            node_id, ua.DataValue(ua.Variant(seconds), SourceTimestamp=BASE + timedelta(seconds=seconds))
        )
    page = await history.read_node_history(node_id, TimeDomain(None, None, 10))
    assert [entry.value.Value.Value for entry in page.entries] == [1, 2, 3, 4, 5]
    backward = await history.read_node_history(node_id, TimeDomain(None, None, 10, backward=True))
    assert [entry.value.Value.Value for entry in backward.entries] == [5, 4, 3, 2, 1]


async def test_srv66_memory_retention_works_with_late_values() -> None:
    """Part 11, 4.2."""
    history = HistoryDict()
    node_id = ua.NodeId("Retention", 2)
    now = datetime.now(UTC)
    await history.new_historized_node(node_id, timedelta(hours=3), 3)
    for hours in (0, 5, 1, 2, 4):
        await history.save_node_value(
            node_id, ua.DataValue(ua.Variant(hours), SourceTimestamp=now - timedelta(hours=hours))
        )
    page = await history.read_node_history(node_id, TimeDomain(None, None, 10))
    assert [entry.value.Value.Value for entry in page.entries] == [2, 1, 0]


async def test_srv20_memory_value_without_timestamps_does_not_raise() -> None:
    """Part 11, 6.5.3.2."""
    history = HistoryDict()
    node_id = ua.NodeId("Plain", 2)
    await history.new_historized_node(node_id, None)
    await history.save_node_value(node_id, ua.DataValue(ua.Variant(1)))
    page = await history.read_node_history(node_id, TimeDomain(None, None, 10))
    assert len(page.entries) == 1


async def test_srv20_memory_reads_after_a_position_in_both_directions() -> None:
    """Part 11, 6.3."""
    history = HistoryDict()
    node_id = ua.NodeId("After", 2)
    await history.new_historized_node(node_id, None)
    for seconds in (1, 1, 1, 2):
        await history.save_node_value(
            node_id, ua.DataValue(ua.Variant(seconds), SourceTimestamp=BASE + timedelta(seconds=seconds))
        )
    first = await history.read_node_history(node_id, TimeDomain(None, None, 2))
    assert first.more
    second = await history.read_node_history(node_id, TimeDomain(None, None, 2, after=first.entries[-1].position))
    assert [entry.position.seq for entry in first.entries + second.entries] == [1, 2, 3, 4]
    back = await history.read_node_history(node_id, TimeDomain(None, None, 2, True))
    rest = await history.read_node_history(node_id, TimeDomain(None, None, 2, True, back.entries[-1].position))
    assert [entry.position.seq for entry in back.entries + rest.entries] == [4, 3, 2, 1]

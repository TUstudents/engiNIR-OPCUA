import sqlite3
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from enginir_opcua import ua
from enginir_opcua.server.history import TimeDomain, to_ticks
from enginir_opcua.server.history_sql import HistorySQLite

BASE = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
async def history() -> AsyncIterator[HistorySQLite]:
    storage = HistorySQLite(":memory:")
    await storage.init()
    yield storage
    await storage.stop()


def value(seconds: float | None, number: int, **kwargs: object) -> ua.DataValue:
    stamp = BASE + timedelta(seconds=seconds) if seconds is not None else None
    return ua.DataValue(ua.Variant(number), SourceTimestamp=stamp, **kwargs)  # type: ignore[arg-type]


async def numbers(history: HistorySQLite, node_id: ua.NodeId, domain: TimeDomain) -> list[int]:
    return [entry.value.Value.Value for entry in (await history.read_node_history(node_id, domain)).entries]


async def test_srv22_sql_string_and_guid_node_ids(history: HistorySQLite) -> None:
    """Part 6, 5.1.12: any NodeId has its own table."""
    ids = [
        ua.NodeId("Boiler.Temp", 2),
        ua.NodeId('odd"name; DROP TABLE x', 2),
        ua.NodeId("line\nbreak and space", 3),
        ua.NodeId(uuid.UUID(int=99), 2),
        ua.NodeId(b"bytes", 2),
        ua.NodeId(77, 3),
    ]
    for index, node_id in enumerate(ids):
        await history.new_historized_node(node_id, None)
        await history.save_node_value(node_id, value(1, index))
    for index, node_id in enumerate(ids):
        assert await numbers(history, node_id, TimeDomain(None, None, 10)) == [index]
    assert len({name for name in history._tables}) == len(ids)


async def test_srv22_sql_event_columns_use_browse_names(history: HistorySQLite) -> None:
    """Part 11, 5.4."""
    source = ua.NodeId(2253)
    await history.new_historized_event(source, None)
    await history.save_event(source, {"Severity": ua.Variant(5, ua.VariantType.UInt16)}, BASE)
    await history.save_event(
        source,
        {"Severity": ua.Variant(6, ua.VariantType.UInt16), "Machine/Speed": ua.Variant(2.5)},
        BASE + timedelta(seconds=1),
    )
    page = await history.read_event_history(source, TimeDomain(None, None, 10))
    assert page.entries[0].value == {"Severity": ua.Variant(5, ua.VariantType.UInt16)}
    assert page.entries[1].value["Machine/Speed"].Value == 2.5
    await history.save_event(source, {"severity": ua.Variant(1)}, BASE + timedelta(seconds=2))
    again = await history.read_event_history(source, TimeDomain(None, None, 10))
    assert len(again.entries) == 3
    assert "severity" not in again.entries[2].value


async def test_srv22_sql_old_file_is_refused(tmp_path: Path) -> None:
    """Design: files of earlier releases are not migrated."""
    old = tmp_path / "old.db"
    connection = sqlite3.connect(old)
    connection.execute('CREATE TABLE "2_77" (_Id INTEGER PRIMARY KEY, SourceTimestamp TIMESTAMP)')
    connection.commit()
    connection.close()
    storage = HistorySQLite(str(old))
    with pytest.raises(ua.UaError, match=r"old\.db"):
        await storage.init()
    foreign = tmp_path / "foreign.db"
    connection = sqlite3.connect(foreign)
    connection.execute("PRAGMA user_version = 7")
    connection.commit()
    connection.close()
    with pytest.raises(ua.UaError, match=r"foreign\.db"):
        await HistorySQLite(str(foreign)).init()


async def test_srv22_sql_new_file_is_marked_and_reopened(tmp_path: Path) -> None:
    """Design: user_version marks the layout."""
    path = tmp_path / "new.db"
    storage = HistorySQLite(str(path))
    await storage.init()
    node_id = ua.NodeId("Reopen", 2)
    await storage.new_historized_node(node_id, None)
    await storage.save_node_value(node_id, value(1, 5))
    await storage.stop()
    assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone() == (2,)
    reopened = HistorySQLite(str(path))
    await reopened.init()
    assert await reopened.has_node(node_id)
    assert await numbers(reopened, node_id, TimeDomain(None, None, 10)) == [5]
    await reopened.stop()


async def test_srv22_sql_timestamps_are_integers(history: HistorySQLite) -> None:
    """Part 6, 5.1.4."""
    node_id = ua.NodeId("Ticks", 2)
    await history.new_historized_node(node_id, None)
    await history.save_node_value(node_id, value(1, 1, ServerTimestamp=BASE))
    async with history._db.execute('SELECT "Key", "SourceTimestamp", "ServerTimestamp" FROM "data:ns=2;s=Ticks"') as c:
        row = list(await c.fetchall())[0]
    expected = to_ticks(BASE + timedelta(seconds=1))
    assert tuple(row) == (expected, expected, to_ticks(BASE))
    assert all(isinstance(item, int) for item in row)


async def test_srv22_sql_orders_by_source_timestamp_then_id(history: HistorySQLite) -> None:
    """Part 11, 6.5.3.2."""
    node_id = ua.NodeId("Ordered", 2)
    await history.new_historized_node(node_id, None)
    for seconds, number in ((3, 3), (1, 1), (2, 2), (2, 22)):
        await history.save_node_value(node_id, value(seconds, number))
    assert await numbers(history, node_id, TimeDomain(None, None, 10)) == [1, 2, 22, 3]
    assert await numbers(history, node_id, TimeDomain(None, None, 10, backward=True)) == [3, 22, 2, 1]
    await history.save_node_value(node_id, value(None, 9))
    page = await history.read_node_history(node_id, TimeDomain(None, None, 10))
    assert len(page.entries) == 5


async def test_srv22_sql_limit_is_page_plus_one(history: HistorySQLite) -> None:
    """Part 4, 7.9."""
    node_id = ua.NodeId("Limit", 2)
    await history.new_historized_node(node_id, None)
    for number in range(10):
        await history.save_node_value(node_id, value(number, number))
    statements: list[str] = []
    await history._db.set_trace_callback(statements.append)
    page = await history.read_node_history(node_id, TimeDomain(None, None, 3))
    assert [entry.value.Value.Value for entry in page.entries] == [0, 1, 2]
    assert page.more is True
    assert any("LIMIT 4" in text for text in statements)


async def test_srv22_sql_period_retention_deletes(history: HistorySQLite) -> None:
    """Part 11, 4.2."""
    node_id = ua.NodeId("Period", 2)
    await history.new_historized_node(node_id, timedelta(hours=1))
    history._retention[f"data:{node_id.to_string()}"].saves = 1000
    now = datetime.now(UTC)
    await history.save_node_value(node_id, ua.DataValue(ua.Variant(1), SourceTimestamp=now - timedelta(hours=3)))
    await history.save_node_value(node_id, ua.DataValue(ua.Variant(2), SourceTimestamp=now))
    async with history._db.execute('SELECT COUNT(*) FROM "data:ns=2;s=Period"') as cursor:
        assert list(await cursor.fetchall()) == [(1,)]


async def test_srv22_sql_count_limit_applies_to_events(history: HistorySQLite) -> None:
    """Part 11, 4.2."""
    source = ua.NodeId(2253)
    await history.new_historized_event(source, None, 2)
    for number in range(5):
        await history.save_event(source, {"Severity": ua.Variant(number)}, BASE + timedelta(seconds=number))
    async with history._db.execute('SELECT COUNT(*) FROM "event:i=2253"') as cursor:
        assert list(await cursor.fetchall()) == [(2,)]


async def test_srv22_sql_read_error_is_data_unavailable() -> None:
    """Part 11, 6.2.2."""
    from enginir_opcua import Server
    from enginir_opcua.server.user_managers import PermissiveUserManager

    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    storage = HistorySQLite(":memory:")
    server.iserver.history_manager.set_storage(storage)
    await server.init()
    node = await server.nodes.objects.add_variable(ua.NodeId("Broken", 2), "Broken", 1)
    await server.historize_node_data_change(node, period=None)
    await storage._db.execute('DROP TABLE "data:ns=2;s=Broken"')
    details = ua.ReadRawModifiedDetails(
        IsReadModified=False, StartTime=BASE, EndTime=BASE + timedelta(hours=1), NumValuesPerNode=0
    )
    item = ua.HistoryReadValueId(NodeId=node.nodeid)
    params = ua.HistoryReadParameters(
        HistoryReadDetails=details,
        TimestampsToReturn=ua.TimestampsToReturn.Both,
        ReleaseContinuationPoints=False,
        NodesToRead=[item],
    )
    session = server.iserver.isession
    results = await session.history_read(params)
    assert results[0].StatusCode == ua.StatusCode(ua.StatusCodes.BadDataUnavailable)
    await server.stop()

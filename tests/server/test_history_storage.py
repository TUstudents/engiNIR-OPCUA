import asyncio
import sqlite3
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from enginir_opcua import ua
from enginir_opcua.common import sql_injection
from enginir_opcua.common.node import Node
from enginir_opcua.common.sql_injection import quote_identifier
from enginir_opcua.server.history import HistoryDict, TimeDomain, to_ticks
from enginir_opcua.server.history_sql import HistorySQLite


def future() -> datetime:
    return datetime.now(UTC) + timedelta(days=1)


async def test_history_var_read_one(history_server):
    """only an end time and a count: newest first"""
    res = await history_server.var.read_raw_history(None, future(), 1)
    assert 1 == len(res)
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_last_3(history_server):
    res = await history_server.var.read_raw_history(None, future(), 3)
    assert 3 == len(res)
    assert res[-1].Value.Value == history_server.values[-3]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_all2(history_server):
    res = await history_server.var.read_raw_history(None, future(), 9999)
    assert len(history_server.values) == len(res)
    assert res[-1].Value.Value == history_server.values[0]
    assert res[0].Value.Value == history_server.values[-1]


async def test_srv20_fewer_than_two_of_start_end_count_is_invalid_argument(history_server):
    """Part 11, 6.5.3.1: two of startTime, endTime and numValuesPerNode shall be specified."""
    old = datetime.now(UTC) - timedelta(days=6)
    for start, end, count in ((None, None, 0), (None, None, 5), (old, None, 0), (None, future(), 0)):
        details = ua.ReadRawModifiedDetails(
            IsReadModified=False,
            StartTime=start or ua.get_win_epoch(),
            EndTime=end or ua.get_win_epoch(),
            NumValuesPerNode=count,
            ReturnBounds=False,
        )
        with pytest.raises(ua.uaerrors.BadInvalidArgument):
            (await history_server.var.history_read(details)).StatusCode.check()


async def test_history_var_read_2_with_end(history_server):
    """only has end time, should return reverse order"""
    now = datetime.now(UTC)
    res = await history_server.var.read_raw_history(None, now, 2)
    assert 2 == len(res)
    assert res[-1].Value.Value == history_server.values[-2]


async def test_history_var_read_all(history_server):
    """both start and endtime, return from start to end"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.var.read_raw_history(old, now, 0)
    assert len(history_server.values) == len(res)
    assert res[-1].Value.Value == history_server.values[-1]
    assert res[0].Value.Value == history_server.values[0]


async def test_history_var_read_5_in_timeframe(history_server):
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.var.read_raw_history(old, now, 5)
    assert 5 == len(res)
    assert res[-1].Value.Value == history_server.values[4]
    assert res[0].Value.Value == history_server.values[0]


async def test_history_var_read_5_in_timeframe_start_greater_than_end(history_server):
    """start time greater than end time, should return reverse order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.var.read_raw_history(now, old, 5)
    assert 5 == len(res)
    assert res[-1].Value.Value == history_server.values[-5]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_6_with_start(history_server):
    """only start return original order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)
    res = await history_server.var.read_raw_history(old, None, 6)
    assert 6 == len(res)
    assert res[-1].Value.Value == history_server.values[5]
    assert res[0].Value.Value == history_server.values[0]


async def test_history_var_read_3_with_end(history_server):
    """only end return reversed order"""
    end = datetime.now(UTC) + timedelta(days=6)
    res = await history_server.var.read_raw_history(None, end, 3)
    assert 3 == len(res)
    assert res[2].Value.Value == history_server.values[-3]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_repeated_continuation_point():
    """
    Some servers do not treat numvalues=0 as "as many as you can" and answer
    with no data plus the same continuation point over and over. read_raw_history
    must not loop forever on such a server.
    """

    class _StuckServerNode(Node):
        def __init__(self):
            self.calls = 0

        async def history_read(self, details, continuation_point=None):
            self.calls += 1
            if self.calls > 10:
                raise AssertionError("read_raw_history did not stop on a repeated continuation point")
            result = ua.HistoryReadResult()
            result.StatusCode = ua.StatusCode(ua.StatusCodes.Good)
            result.ContinuationPoint = b"\x00\x00\x01\x9d"
            result.HistoryData = ua.HistoryData()
            result.HistoryData.DataValues = []
            return result

    node = _StuckServerNode()
    res = await node.read_raw_history(numvalues=0)
    assert [] == res
    assert 2 == node.calls


async def test_srv54_history_keeps_every_value_written_within_one_publish_cycle():
    """Part 4, 7.21: the capture asks for a queue of its own, a queue of one would keep only the last value."""
    from enginir_opcua import Server

    srv = Server()
    await srv.init()
    var = await srv.nodes.objects.add_variable(2, "BurstVar", 0)
    await srv.historize_node_data_change(var, count=500)
    for value in range(1, 101):
        await var.write_value(value)
    await asyncio.sleep(0.3)
    page = await srv.iserver.history_manager.storage.read_node_history(var.nodeid, TimeDomain(None, None, 1000))
    assert len(page.entries) == 101
    await srv.stop()


async def test_com15_read_raw_history_without_arguments_reads_everything_until_now(history_server):
    """Part 11, 6.5.3: a read needs two of start, end and count; the client fills in a valid range."""
    res = await history_server.var.read_raw_history()
    assert [dv.Value.Value for dv in res] == history_server.values


async def test_com15_read_raw_history_with_only_a_count_reads_the_newest(history_server):
    """Part 11, 6.5.3: a count alone becomes the newest values up to now."""
    res = await history_server.var.read_raw_history(numvalues=3)
    assert [dv.Value.Value for dv in res] == history_server.values[:-4:-1]


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


HOSTILE_NAME = 'Pressure" BLOB, "Injected'


def test_com54_identifiers_are_quoted_by_doubling_quotes() -> None:
    assert quote_identifier('a"b') == '"a""b"'
    assert quote_identifier("a\nb;c d") == '"a\nb;c d"'


def test_com54_validate_table_name_blacklist_is_gone() -> None:
    assert not hasattr(sql_injection, "validate_table_name")
    assert not hasattr(sql_injection, "sqlite3_keywords")


async def test_com54_event_column_names_cannot_add_columns() -> None:
    """A field name containing a double quote must stay a single column name."""
    history = HistorySQLite(":memory:")
    await history.init()
    source = ua.NodeId(2253)
    await history.new_historized_event(source, None)
    await history.save_event(source, {HOSTILE_NAME: ua.Variant(1, ua.VariantType.Int32)}, datetime.now(UTC))
    async with history._db.execute('PRAGMA table_info("event:i=2253")') as cursor:
        names = [row[1] for row in await cursor.fetchall()]
    assert names == ["_Id", "_Time", "_EventType", "f:" + HOSTILE_NAME]
    page = await history.read_event_history(source, TimeDomain(None, None, 10))
    assert page.entries[0].value[HOSTILE_NAME].Value == 1
    await history.stop()


async def test_com54_event_time_and_type_are_bound_as_parameters() -> None:
    history = HistorySQLite(":memory:")
    await history.init()
    source = ua.NodeId(2253)
    await history.new_historized_event(source, None)
    event_type = ua.NodeId('x", "y', 2)
    time = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    await history.save_event(source, {"EventType": ua.Variant(event_type)}, time)
    async with history._db.execute('SELECT "_Time", "_EventType" FROM "event:i=2253"') as cursor:
        rows = list(await cursor.fetchall())
    assert rows == [(to_ticks(time), str(event_type))]
    await history.stop()


async def test_history_ev_read_2_with_end(history_server):
    """only has end time, should return reverse order"""
    now = datetime.now(UTC)
    res = await history_server.srv_node.read_event_history(None, now, 2)
    assert 2 == len(res)
    assert res[-1].Severity == history_server.ev_values[-2]


async def test_history_ev_read_all(history_server):
    """both start and end time, return from start to end"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.srv_node.read_event_history(old, now, 0)
    assert 20 == len(res)
    assert res[-1].Severity == history_server.ev_values[-1]
    assert res[0].Severity == history_server.ev_values[0]


async def test_history_ev_read_5_in_timeframe(history_server):
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.srv_node.read_event_history(old, now, 5)
    assert 5 == len(res)
    assert res[-1].Severity == history_server.ev_values[4]
    assert res[0].Severity == history_server.ev_values[0]


async def test_history_ev_read_5_in_timeframe_start_greater_than_end(history_server):
    """start time greater than end time, should return reverse order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.srv_node.read_event_history(now, old, 5)
    assert 5 == len(res)
    assert res[-1].Severity == history_server.ev_values[-5]
    assert res[0].Severity == history_server.ev_values[-1]


async def test_history_ev_read_6_with_start(history_server):
    """only start return original order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)
    res = await history_server.srv_node.read_event_history(old, None, 6)
    assert 6 == len(res)
    assert res[-1].Severity == history_server.ev_values[5]
    assert res[0].Severity == history_server.ev_values[0]


async def test_history_ev_read_all_with_start(history_server):
    """only start return original order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)
    res = await history_server.srv_node.read_event_history(old, None, 100)
    assert 20 == len(res)
    assert res[-1].Severity == history_server.ev_values[-1]
    assert res[0].Severity == history_server.ev_values[0]


async def test_history_ev_read_all_with_end(history_server):
    """only end return reversed order"""
    end = datetime.now(UTC) + timedelta(days=6)
    res = await history_server.srv_node.read_event_history(None, end, 100)
    assert 20 == len(res)
    assert res[-1].Severity == history_server.ev_values[0]
    assert res[0].Severity == history_server.ev_values[-1]


async def test_history_ev_read_3_with_end(history_server):
    """only end return reversed order"""
    end = datetime.now(UTC) + timedelta(days=6)
    res = await history_server.srv_node.read_event_history(None, end, 3)
    assert 3 == len(res)
    assert res[2].Severity == history_server.ev_values[-3]
    assert res[0].Severity == history_server.ev_values[-1]


async def test_com15_read_event_history_without_arguments_reads_everything_until_now(history_server):
    """Part 11, 6.5.2: a read needs two of start, end and count; the client fills in a valid range."""
    res = await history_server.srv_node.read_event_history()
    assert [ev.Severity for ev in res] == history_server.ev_values

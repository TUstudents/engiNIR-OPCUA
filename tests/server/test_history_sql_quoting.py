from datetime import UTC, datetime

from enginir_opcua import ua
from enginir_opcua.common import sql_injection
from enginir_opcua.common.sql_injection import quote_identifier
from enginir_opcua.server.history import TimeDomain, to_ticks
from enginir_opcua.server.history_sql import HistorySQLite

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

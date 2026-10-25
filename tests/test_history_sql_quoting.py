import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from enginir_opcua import ua
from enginir_opcua.common.sql_injection import quote_identifier
from enginir_opcua.server.history_sql import HistorySQLite

HOSTILE_NAME = 'Pressure" BLOB, "Injected'


def test_com54_identifiers_are_quoted_by_doubling_quotes() -> None:
    assert quote_identifier('a"b') == '"a""b"'
    assert HistorySQLite._list_to_sql_str([HOSTILE_NAME, "Message"]) == '"Pressure"" BLOB, ""Injected", "Message"'


def test_com54_event_column_names_cannot_add_columns() -> None:
    """A browse name containing a double quote must stay a single column name."""
    columns = HistorySQLite("unused.db")._get_event_columns([HOSTILE_NAME])
    db = sqlite3.connect(":memory:")
    db.execute(f"CREATE TABLE events (_Id INTEGER, {columns})")
    names = [row[1] for row in db.execute("PRAGMA table_info(events)")]
    assert names == ["_Id", HOSTILE_NAME]


class _RecordingDb:
    def __init__(self) -> None:
        self.statements: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, sql: str, args: tuple[Any, ...]) -> None:
        self.statements.append((sql, tuple(args)))

    async def commit(self) -> None:
        pass


async def test_com54_event_time_and_type_are_bound_as_parameters() -> None:
    history = HistorySQLite("unused.db")
    db = _RecordingDb()
    history._db = db  # type: ignore[assignment]
    source = ua.NodeId(2253)
    history._datachanges_period[source] = None
    time = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
    event_type = ua.NodeId('x", "y', 2)
    event = SimpleNamespace(
        SourceNode=source,
        emitting_node=source,
        EventType=event_type,
        Time=time,
        get_event_props_as_fields_dict=lambda: {"Message": ua.Variant(ua.LocalizedText("hello"))},
    )
    await history.save_event(event)  # type: ignore[arg-type]
    sql, args = db.statements[0]
    assert str(time) not in sql
    assert 'x", "y' not in sql
    assert args[:2] == (str(time), str(event_type))

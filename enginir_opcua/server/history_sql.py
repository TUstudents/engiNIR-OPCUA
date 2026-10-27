from __future__ import annotations

import logging
import time as monotonic
from datetime import UTC, datetime, timedelta
from typing import Any

import aiosqlite

from enginir_opcua import ua

from ..common.sql_injection import quote_identifier
from ..common.utils import Buffer
from ..ua.ua_binary import variant_from_binary, variant_to_binary
from .history import (
    HistoryEntry,
    HistoryPosition,
    HistoryStorageInterface,
    Page,
    TimeDomain,
    from_ticks,
    key_of_value,
    to_ticks,
)

LAYOUT_VERSION = 2
RETENTION_BATCH = 100
RETENTION_INTERVAL_SECONDS = 10.0
IMMEDIATE_COUNT_LIMIT = 10_000
FIELD_PREFIX = "f:"
DATA_COLUMNS = '"_Id", "Key", "SourceTimestamp", "ServerTimestamp", "StatusCode", "VariantBinary"'


def data_table(node_id: ua.NodeId) -> str:
    return f"data:{node_id.to_string()}"


def event_table(node_id: ua.NodeId) -> str:
    return f"event:{node_id.to_string()}"


class _Retention:
    def __init__(self, period: timedelta | None, count: int) -> None:
        self.period = period
        self.count = count
        self.saves = 0
        self.last = monotonic.monotonic()

    def cutoff(self) -> int | None:
        return to_ticks(datetime.now(UTC) - self.period) if self.period else None

    def due(self) -> bool:
        self.saves += 1
        if self.count and self.count < IMMEDIATE_COUNT_LIMIT:
            return True
        return self.saves >= RETENTION_BATCH or monotonic.monotonic() - self.last >= RETENTION_INTERVAL_SECONDS

    def done(self) -> None:
        self.saves = 0
        self.last = monotonic.monotonic()


class HistorySQLite(HistoryStorageInterface):
    """
    history backend which stores data values and object events in a SQLite database
    this backend is intended to only be accessed via OPC UA, therefore all UA Variants saved in
    the history database are in binary format (SQLite BLOBs); times are Int64 ticks of 100 ns since 1601-01-01 UTC
    """

    def __init__(self, path: str = "history.db", max_history_data_response_size: int = 10000) -> None:
        super().__init__(max_history_data_response_size)
        self.logger = logging.getLogger(__name__)
        self._db_file = path
        self._db: aiosqlite.Connection = None  # type: ignore[assignment]
        self._tables: set[str] = set()
        self._retention: dict[str, _Retention] = {}
        self._event_columns: dict[str, set[str]] = {}

    async def init(self) -> None:
        self._db = await aiosqlite.connect(self._db_file)
        async with self._db.execute("PRAGMA user_version") as cursor:
            row = await cursor.fetchone()
        version = row[0] if row else 0
        async with self._db.execute("SELECT name FROM sqlite_master WHERE type = 'table'") as cursor:
            names = {name for (name,) in await cursor.fetchall() if not name.startswith("sqlite_")}
        if version == 0 and not names:
            await self._db.execute(f"PRAGMA user_version = {LAYOUT_VERSION}")
            await self._db.commit()
        elif version != LAYOUT_VERSION:
            await self._db.close()
            raise ua.UaError(
                f"The history file {self._db_file} has the layout of an earlier release (user_version {version}) "
                "and cannot be used; move it away or convert it"
            )
        self._tables = names

    async def stop(self) -> None:
        if self._db is not None:
            await self._db.commit()
            await self._db.close()
            self.logger.info("Historizing SQL connection closed")

    async def flush(self) -> None:
        await self._db.commit()

    async def has_node(self, node_id: ua.NodeId) -> bool:
        return data_table(node_id) in self._tables

    async def has_event(self, node_id: ua.NodeId) -> bool:
        return event_table(node_id) in self._tables

    async def new_historized_node(self, node_id: ua.NodeId, period: timedelta | None, count: int = 0) -> None:
        table = data_table(node_id)
        quoted = quote_identifier(table)
        index = quote_identifier(f"{table}:order")
        await self._db.execute(
            f"CREATE TABLE IF NOT EXISTS {quoted} ("
            '"_Id" INTEGER PRIMARY KEY AUTOINCREMENT, "Key" INTEGER NOT NULL, SourceTimestamp INTEGER, '
            "ServerTimestamp INTEGER, StatusCode INTEGER NOT NULL, Value TEXT, VariantType TEXT, "
            "VariantBinary BLOB NOT NULL)"
        )
        await self._db.execute(f'CREATE INDEX IF NOT EXISTS {index} ON {quoted} ("Key", "_Id")')
        await self._db.commit()
        self._tables.add(table)
        self._retention[table] = _Retention(period, count)

    async def save_node_value(self, node_id: ua.NodeId, datavalue: ua.DataValue) -> None:
        table = data_table(node_id)
        variant = datavalue.Value if datavalue.Value is not None else ua.Variant(None, ua.VariantType.Null)
        await self._db.execute(
            f"INSERT INTO {quote_identifier(table)} "
            '("Key", SourceTimestamp, ServerTimestamp, StatusCode, Value, VariantType, VariantBinary) '
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                key_of_value(datavalue),
                to_ticks(datavalue.SourceTimestamp) if datavalue.SourceTimestamp else None,
                to_ticks(datavalue.ServerTimestamp) if datavalue.ServerTimestamp else None,
                datavalue.StatusCode.value if datavalue.StatusCode is not None else 0,
                str(variant.Value),
                variant.VariantType.name,
                variant_to_binary(variant),
            ),
        )
        await self._retain(table)

    async def _retain(self, table: str) -> None:
        retention = self._retention.get(table)
        if retention is None or not retention.due():
            return
        quoted = quote_identifier(table)
        time_column = self._time_column(table)
        cutoff = retention.cutoff()
        if cutoff is not None:
            await self._db.execute(f"DELETE FROM {quoted} WHERE {time_column} < ?", (cutoff,))
        if retention.count:
            await self._db.execute(
                f"DELETE FROM {quoted} WHERE _Id IN (SELECT _Id FROM {quoted} "
                f"ORDER BY {time_column} DESC, _Id DESC LIMIT -1 OFFSET ?)",
                (retention.count,),
            )
        retention.done()

    @staticmethod
    def _time_column(table: str) -> str:
        return '"_Time"' if table.startswith("event:") else '"Key"'

    @staticmethod
    def _conditions(time_column: str, domain: TimeDomain, cutoff: int | None) -> tuple[str, list[Any]]:
        parts: list[str] = []
        args: list[Any] = []
        start = domain.start
        if cutoff is not None and (start is None or start < cutoff):
            start = cutoff
        if start is not None:
            parts.append(f"{time_column} >= ?")
            args.append(start)
        if domain.end is not None:
            parts.append(f"{time_column} <= ?")
            args.append(domain.end)
        if domain.after is not None:
            operator = "<" if domain.backward else ">"
            parts.append(f'({time_column}, "_Id") {operator} (?, ?)')
            args.extend(domain.after)
        return (" WHERE " + " AND ".join(parts)) if parts else "", args

    async def read_node_history(self, node_id: ua.NodeId, domain: TimeDomain) -> Page:
        table = data_table(node_id)
        if table not in self._tables:
            return Page([], False)
        retention = self._retention.get(table)
        where, args = self._conditions('"Key"', domain, retention.cutoff() if retention else None)
        order = "DESC" if domain.backward else "ASC"
        async with self._db.execute(
            f'SELECT {DATA_COLUMNS} FROM {quote_identifier(table)}{where} ORDER BY "Key" {order}, "_Id" {order} LIMIT ?',
            (*args, domain.limit + 1),
        ) as cursor:
            rows = list(await cursor.fetchall())
        entries = [
            HistoryEntry(
                HistoryPosition(row[1], row[0]),
                ua.DataValue(
                    variant_from_binary(Buffer(row[5])),
                    StatusCode=ua.StatusCode(row[4]),
                    SourceTimestamp=from_ticks(row[2]) if row[2] is not None else None,
                    ServerTimestamp=from_ticks(row[3]) if row[3] is not None else None,
                ),
            )
            for row in rows[: domain.limit]
        ]
        return Page(entries, len(rows) > domain.limit)

    async def new_historized_event(self, source_id: ua.NodeId, period: timedelta | None, count: int = 0) -> None:
        table = event_table(source_id)
        quoted = quote_identifier(table)
        index = quote_identifier(f"{table}:order")
        await self._db.execute(
            f"CREATE TABLE IF NOT EXISTS {quoted} "
            "(_Id INTEGER PRIMARY KEY AUTOINCREMENT, _Time INTEGER NOT NULL, _EventType TEXT)"
        )
        await self._db.execute(f"CREATE INDEX IF NOT EXISTS {index} ON {quoted} (_Time, _Id)")
        await self._db.commit()
        self._tables.add(table)
        self._retention[table] = _Retention(period, count)
        await self._load_event_columns(table)

    async def _load_event_columns(self, table: str) -> set[str]:
        async with self._db.execute(f"PRAGMA table_info({quote_identifier(table)})") as cursor:
            names = {row[1] for row in await cursor.fetchall()}
        self._event_columns[table] = {name for name in names if name.startswith(FIELD_PREFIX)}
        return self._event_columns[table]

    async def _ensure_columns(self, table: str, names: list[str]) -> list[str]:
        known = self._event_columns.get(table)
        if known is None:
            known = await self._load_event_columns(table)
        lowered = {name.lower(): name for name in known}
        usable = []
        for name in names:
            column = FIELD_PREFIX + name
            existing = lowered.get(column.lower())
            if existing is None:
                await self._db.execute(
                    f"ALTER TABLE {quote_identifier(table)} ADD COLUMN {quote_identifier(column)} BLOB"
                )
                known.add(column)
                lowered[column.lower()] = column
                usable.append(column)
            elif existing == column:
                usable.append(column)
            else:
                self.logger.warning("Event field %s differs from the stored column %s only by case", name, existing)
        return usable

    async def save_event(self, source_id: ua.NodeId, fields: dict[str, ua.Variant], time: datetime) -> None:
        table = event_table(source_id)
        columns = await self._ensure_columns(table, sorted(fields))
        values = [variant_to_binary(fields[column[len(FIELD_PREFIX) :]]) for column in columns]
        event_type = fields.get("EventType")
        column_text = "".join(f", {quote_identifier(column)}" for column in columns)
        marks = ", ?" * len(columns)
        await self._db.execute(
            f'INSERT INTO {quote_identifier(table)} ("_Time", "_EventType"{column_text}) VALUES (?, ?{marks})',
            (to_ticks(time), str(event_type.Value) if event_type is not None else None, *values),
        )
        await self._retain(table)

    async def read_event_history(self, source_id: ua.NodeId, domain: TimeDomain) -> Page:
        table = event_table(source_id)
        if table not in self._tables:
            return Page([], False)
        columns = sorted(self._event_columns.get(table) or await self._load_event_columns(table))
        retention = self._retention.get(table)
        where, args = self._conditions('"_Time"', domain, retention.cutoff() if retention else None)
        order = "DESC" if domain.backward else "ASC"
        selected = "".join(f", {quote_identifier(column)}" for column in columns)
        async with self._db.execute(
            f'SELECT "_Id", "_Time"{selected} FROM {quote_identifier(table)}{where} '
            f'ORDER BY "_Time" {order}, "_Id" {order} LIMIT ?',
            (*args, domain.limit + 1),
        ) as cursor:
            rows = list(await cursor.fetchall())
        entries = [
            HistoryEntry(
                HistoryPosition(row[1], row[0]),
                {
                    column[len(FIELD_PREFIX) :]: variant_from_binary(Buffer(blob))
                    for column, blob in zip(columns, row[2:])
                    if blob is not None
                },
            )
            for row in rows[: domain.limit]
        ]
        return Page(entries, len(rows) > domain.limit)

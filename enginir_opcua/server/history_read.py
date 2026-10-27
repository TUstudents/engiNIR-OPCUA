"""The HistoryRead service: request checks, time domains, paging and the shape of the answer."""

from __future__ import annotations

import dataclasses
import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.common.events import Event
from enginir_opcua.ua.numeric_range import IndexRange, select_index_range
from enginir_opcua.ua.ua_binary import struct_to_binary
from enginir_opcua.ua.uaerrors import BadIndexRangeNoData, UaStatusCodeError

from .content_filter import WhereClauseEvaluator
from .continuation_points import ContinuationPoints
from .history import HistoryEntry, HistoryPosition, Page, TimeDomain, from_ticks, to_ticks
from .node_walk import is_subtype

if TYPE_CHECKING:
    from .history import HistoryManager

_logger = logging.getLogger(__name__)

HISTORIAN_RAW_EXTRA_DATA = 0x0400 | 0x0008
SUPPORTED_DETAILS = (ua.ReadRawModifiedDetails, ua.ReadEventDetails, ua.ReadEventDetails2)
SCAN_CHUNK = 64


@dataclass(slots=True)
class HistoryCursor:
    node_id: ua.NodeId
    fingerprint: bytes
    start: int | None
    end: int | None
    backward: bool
    page_size: int
    remaining: int | None
    last: HistoryPosition


@dataclass(slots=True)
class _Group:
    key: int
    newest: HistoryEntry
    size: int
    last_position: HistoryPosition


@dataclass(slots=True)
class _Request:
    start: int | None
    end: int | None
    backward: bool
    page_size: int
    total: int | None


def _status(code: int) -> ua.StatusCode:
    return ua.StatusCode(code)


class HistoryReader:
    def __init__(self, manager: HistoryManager) -> None:
        self.manager = manager
        self.iserver = manager.iserver
        self.aspace = manager.iserver.aspace

    @property
    def page_cap(self) -> int:
        return max(
            1, min(self.iserver.max_history_data_response_size, self.manager.storage.max_history_data_response_size)
        )

    async def read(
        self,
        params: ua.HistoryReadParameters,
        points: ContinuationPoints[HistoryCursor],
        trusted: bool,
    ) -> list[ua.HistoryReadResult]:
        details = params.HistoryReadDetails
        if details is None or (isinstance(details, ua.ExtensionObject) and details.TypeId.is_null()):
            raise ua.uaerrors.BadHistoryOperationInvalid()
        if type(details) not in SUPPORTED_DETAILS or getattr(details, "IsReadModified", False):
            raise ua.uaerrors.BadHistoryOperationUnsupported()
        if getattr(details, "ReadModified", False):
            raise ua.uaerrors.BadHistoryOperationUnsupported()
        if params.TimestampsToReturn not in (
            ua.TimestampsToReturn.Source,
            ua.TimestampsToReturn.Server,
            ua.TimestampsToReturn.Both,
        ):
            raise ua.uaerrors.BadTimestampsToReturnInvalid()
        if params.ReleaseContinuationPoints:
            for item in params.NodesToRead:
                points.take(item.ContinuationPoint)
            return [ua.HistoryReadResult() for _ in params.NodesToRead]
        created: set[bytes] = set()
        results = []
        for item in params.NodesToRead:
            try:
                results.append(
                    await self._read_node(details, item, params.TimestampsToReturn, points, created, trusted)
                )
            except UaStatusCodeError as error:
                results.append(ua.HistoryReadResult(StatusCode=_status(int(error.code))))
        return results

    async def _read_node(
        self,
        details: Any,
        item: ua.HistoryReadValueId,
        timestamps: ua.TimestampsToReturn,
        points: ContinuationPoints[HistoryCursor],
        created: set[bytes],
        trusted: bool,
    ) -> ua.HistoryReadResult:
        is_event = isinstance(details, ua.ReadEventDetails)
        node = self.aspace.node_for_service(item.NodeId)
        await self._check_node(node, item.NodeId, is_event, trusted)
        index_range = IndexRange.parse(item.IndexRange) if not is_event else None
        if (
            not is_event
            and timestamps != ua.TimestampsToReturn.Source
            and not self.manager.storage.stores_server_timestamp
        ):
            raise ua.uaerrors.BadTimestampNotSupported()
        if is_event and not details.Filter.SelectClauses:
            raise ua.uaerrors.BadEventFilterInvalid()
        fingerprint = self._fingerprint(details, timestamps, item)
        token = item.ContinuationPoint or None
        cursor = None
        if token is not None:
            cursor = points.get(token)
            if cursor is None or cursor.fingerprint != fingerprint or cursor.node_id != item.NodeId:
                points.take(token)
                raise ua.uaerrors.BadContinuationPointInvalid()
            request = _Request(cursor.start, cursor.end, cursor.backward, cursor.page_size, cursor.remaining)
        else:
            request = self._request_of(details)
        try:
            if is_event:
                return await self._events(details, item, request, cursor, token, points, created, fingerprint)
            return await self._values(
                details, item, request, cursor, token, points, created, fingerprint, timestamps, index_range
            )
        except UaStatusCodeError:
            raise
        except Exception:
            _logger.exception("History read of %s failed", item.NodeId)
            raise ua.uaerrors.BadDataUnavailable() from None

    async def _check_node(self, node: Any, node_id: ua.NodeId, is_event: bool, trusted: bool) -> None:
        node_class = self.aspace.node_class_of(node)
        if is_event:
            if node_class not in (ua.NodeClass.Object, ua.NodeClass.View):
                raise ua.uaerrors.BadHistoryOperationUnsupported()
            bits = self.manager.integer_attribute(node_id, ua.AttributeIds.EventNotifier)
            if not ua.ua_binary.is_bit_set(bits, ua.EventNotifier.HistoryRead):
                raise ua.uaerrors.BadNotReadable()
            if not await self.manager.storage.has_event(node_id):
                raise ua.uaerrors.BadHistoryOperationUnsupported()
            return
        if node_class != ua.NodeClass.Variable:
            raise ua.uaerrors.BadHistoryOperationUnsupported()
        access = self.manager.integer_attribute(node_id, ua.AttributeIds.AccessLevel)
        if not ua.ua_binary.is_bit_set(access, ua.AccessLevel.HistoryRead):
            raise ua.uaerrors.BadNotReadable()
        if not trusted:
            user_node = self.aspace.read_attribute_value(node_id, ua.AttributeIds.UserAccessLevel).Value
            user_access = int(user_node.Value) if user_node is not None else access
            if not ua.ua_binary.is_bit_set(user_access, ua.AccessLevel.HistoryRead):
                raise ua.uaerrors.BadUserAccessDenied()
        if not await self.manager.storage.has_node(node_id):
            raise ua.uaerrors.BadHistoryOperationUnsupported()

    @staticmethod
    def _fingerprint(details: Any, timestamps: ua.TimestampsToReturn, item: ua.HistoryReadValueId) -> bytes:
        digest = hashlib.sha256()
        digest.update(struct_to_binary(details))
        digest.update(bytes([int(timestamps)]))
        digest.update((item.IndexRange or "").encode())
        return digest.digest()

    def _request_of(self, details: Any) -> _Request:
        epoch = ua.get_win_epoch()
        start_given = details.StartTime is not None and details.StartTime > epoch
        end_given = details.EndTime is not None and details.EndTime > epoch
        count = details.NumValuesPerNode
        start = to_ticks(details.StartTime) if start_given else None
        end = to_ticks(details.EndTime) if end_given else None
        cap = self.page_cap
        if start is not None and end is not None:
            backward = start > end
            low, high = (end, start) if backward else (start, end)
            return _Request(low, high, backward, min(count, cap) if count else cap, None)
        if count > 0 and start is not None:
            return _Request(start, None, False, min(count, cap), count)
        if count > 0 and end is not None:
            return _Request(None, end, True, min(count, cap), count)
        raise ua.uaerrors.BadInvalidArgument()

    def _domain(self, request: _Request, limit: int, after: HistoryPosition | None) -> TimeDomain:
        return TimeDomain(request.start, request.end, limit, request.backward, after)

    def _finish(
        self,
        result: ua.HistoryReadResult,
        request: _Request,
        cursor: HistoryCursor | None,
        token: bytes | None,
        points: ContinuationPoints[HistoryCursor],
        created: set[bytes],
        fingerprint: bytes,
        node_id: ua.NodeId,
        returned: int,
        more: bool,
        last: HistoryPosition | None,
    ) -> ua.HistoryReadResult:
        remaining = None if request.total is None else request.total - returned
        if remaining is not None and remaining <= 0:
            more = False
        if not more or last is None:
            if token is not None:
                points.take(token)
            return result
        if cursor is not None and token is not None:
            cursor.last = last
            cursor.remaining = remaining
            result.ContinuationPoint = points.renew(token)
            return result
        if not points.has_room():
            points.release_oldest(created)
        if not points.has_room():
            return ua.HistoryReadResult(StatusCode=_status(ua.StatusCodes.BadNoContinuationPoints))
        new_cursor = HistoryCursor(
            node_id, fingerprint, request.start, request.end, request.backward, request.page_size, remaining, last
        )
        result.ContinuationPoint = points.add(new_cursor)
        created.add(result.ContinuationPoint)
        return result

    async def _values(
        self,
        details: Any,
        item: ua.HistoryReadValueId,
        request: _Request,
        cursor: HistoryCursor | None,
        token: bytes | None,
        points: ContinuationPoints[HistoryCursor],
        created: set[bytes],
        fingerprint: bytes,
        timestamps: ua.TimestampsToReturn,
        index_range: IndexRange | None,
    ) -> ua.HistoryReadResult:
        bounds = bool(details.ReturnBounds) and cursor is None
        first_bound = await self._first_bound(item.NodeId, request, details) if bounds else None
        budget = request.page_size - (1 if first_bound is not None else 0)
        limit = budget if request.total is None else min(budget, request.total - (1 if first_bound else 0))
        entries: list[tuple[ua.DataValue, bool]] = []
        more = False
        last: HistoryPosition | None = None
        if limit > 0:
            groups, more = await self._collect_groups(
                item.NodeId, request, limit, cursor.last if cursor is not None else None
            )
            entries = [(group.newest.value, group.size > 1) for group in groups]
            last = groups[-1].last_position if groups else None
        values = [self._present(value, hidden, timestamps, index_range) for value, hidden in entries]
        if first_bound is not None:
            values.insert(0, self._present(first_bound, False, timestamps, None))
        if bounds and not more:
            last_bound = await self._last_bound(item.NodeId, request, details, values, len(entries))
            if (
                last_bound is not None
                and (request.total is None or len(values) < request.total)
                and len(values) < max(request.page_size, 1)
            ):
                values.append(self._present(last_bound, False, timestamps, None))
        result = ua.HistoryReadResult(HistoryData=ua.HistoryData(DataValues=values))
        if not values:
            result.StatusCode = _status(ua.StatusCodes.GoodNoData)
        return self._finish(
            result, request, cursor, token, points, created, fingerprint, item.NodeId, len(values), more, last
        )

    async def _collect_groups(
        self, node_id: ua.NodeId, request: _Request, need: int, after: HistoryPosition | None
    ) -> tuple[list[_Group], bool]:
        storage = self.manager.storage
        finished: list[_Group] = []
        group: _Group | None = None
        while True:
            page = await storage.read_node_history(node_id, self._domain(request, need + SCAN_CHUNK, after))
            for entry in page.entries:
                key = entry.position.key
                if group is not None and group.key == key:
                    group.size += 1
                    group.last_position = entry.position
                    if not request.backward:
                        group.newest = entry
                else:
                    if group is not None:
                        finished.append(group)
                        if len(finished) > need:
                            return finished[:need], True
                    group = _Group(key, entry, 1, entry.position)
                after = entry.position
            if not page.more:
                break
        if group is not None:
            finished.append(group)
        return finished[:need], len(finished) > need

    async def _first_bound(self, node_id: ua.NodeId, request: _Request, details: Any) -> ua.DataValue | None:
        edge = request.end if request.backward else request.start
        if edge is None:
            return None
        outside = await self._nearest(node_id, edge, toward_older=not request.backward)
        if outside is not None and outside.position.key == edge:
            return None
        if outside is not None:
            return outside.value
        return ua.DataValue(StatusCode=_status(ua.StatusCodes.BadBoundNotFound), SourceTimestamp=from_ticks(edge))

    async def _last_bound(
        self, node_id: ua.NodeId, request: _Request, details: Any, values: list[ua.DataValue], count: int
    ) -> ua.DataValue | None:
        edge = request.start if request.backward else request.end
        if edge is None:
            return None
        outside = await self._nearest(node_id, edge, toward_older=request.backward)
        if outside is not None and outside.position.key == edge:
            return None
        if outside is not None:
            return outside.value
        return ua.DataValue(StatusCode=_status(ua.StatusCodes.BadBoundNotFound), SourceTimestamp=from_ticks(edge))

    async def _nearest(self, node_id: ua.NodeId, edge: int, toward_older: bool) -> HistoryEntry | None:
        if toward_older:
            domain = TimeDomain(None, edge, 1, True)
        else:
            domain = TimeDomain(edge, None, 1, False)
        page = await self.manager.storage.read_node_history(node_id, domain)
        if not page.entries:
            return None
        newest = page.entries[0]
        return HistoryEntry(newest.position, newest.value)

    @staticmethod
    def _present(
        value: ua.DataValue,
        hidden: bool,
        timestamps: ua.TimestampsToReturn,
        index_range: IndexRange | None,
    ) -> ua.DataValue:
        out = dataclasses.replace(value)
        if timestamps == ua.TimestampsToReturn.Source:
            out.ServerTimestamp = None
            out.ServerPicoseconds = None
        elif timestamps == ua.TimestampsToReturn.Server:
            out.SourceTimestamp = None
            out.SourcePicoseconds = None
        if index_range is not None and (out.StatusCode is None or out.StatusCode.is_good()):
            try:
                if out.Value is None:
                    raise BadIndexRangeNoData()
                out.Value = index_range.select(out.Value)
            except BadIndexRangeNoData:
                out.Value = None
                out.StatusCode = _status(ua.StatusCodes.BadIndexRangeNoData)
        if hidden:
            current = out.StatusCode.value if out.StatusCode is not None else 0
            out.StatusCode = _status(current | HISTORIAN_RAW_EXTRA_DATA)
        return out

    async def _events(
        self,
        details: Any,
        item: ua.HistoryReadValueId,
        request: _Request,
        cursor: HistoryCursor | None,
        token: bytes | None,
        points: ContinuationPoints[HistoryCursor],
        created: set[bytes],
        fingerprint: bytes,
    ) -> ua.HistoryReadResult:
        storage = self.manager.storage
        evaluator = WhereClauseEvaluator(_logger, self.aspace, details.Filter.WhereClause)
        need = request.page_size if request.total is None else min(request.page_size, request.total)
        matches: list[tuple[HistoryPosition, Event]] = []
        after = cursor.last if cursor is not None else None
        more = False
        while True:
            page: Page = await storage.read_event_history(item.NodeId, self._domain(request, need + SCAN_CHUNK, after))
            for entry in page.entries:
                after = entry.position
                event = Event.from_field_dict(entry.value)
                if evaluator.eval(event):
                    if len(matches) == need:
                        more = True
                        break
                    matches.append((entry.position, event))
            if more or not page.more:
                break
        rows = []
        for _, event in matches:
            rows.append(
                ua.HistoryEventFieldList(
                    EventFields=event.to_event_fields(
                        details.Filter.SelectClauses, lambda c, a: is_subtype(self.aspace, c, a), select_index_range
                    )
                )
            )
        result = ua.HistoryReadResult(HistoryData=ua.HistoryEvent(Events=rows))
        if not rows:
            result.StatusCode = _status(ua.StatusCodes.GoodNoData)
        last = matches[-1][0] if matches else None
        return self._finish(
            result, request, cursor, token, points, created, fingerprint, item.NodeId, len(rows), more, last
        )

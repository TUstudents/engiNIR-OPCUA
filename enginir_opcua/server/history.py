from __future__ import annotations

import asyncio
import copy
import logging
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, NamedTuple

from enginir_opcua import ua
from enginir_opcua.common.subscription import Subscription

if TYPE_CHECKING:
    from enginir_opcua.common.events import Event
    from enginir_opcua.common.node import Node

    from .continuation_points import ContinuationPoints
    from .history_read import HistoryCursor
    from .internal_server import InternalServer

_logger = logging.getLogger(__name__)

MAX_SEQUENCE = 2**63 - 1
CAPTURE_DRAIN_SECONDS = 5.0
HAS_HISTORY_READ = 1 << ua.AccessLevel.HistoryRead
HISTORY_READ_EVENTS = 1 << ua.EventNotifier.HistoryRead


class UaNodeAlreadyHistorizedError(ua.UaError):
    pass


def to_ticks(moment: datetime) -> int:
    return ua.datetime_to_win_epoch(moment)


def from_ticks(ticks: int) -> datetime:
    return ua.win_epoch_to_datetime(ticks)


def key_of_value(datavalue: ua.DataValue) -> int:
    moment = datavalue.SourceTimestamp or datavalue.ServerTimestamp or datetime.now(UTC)
    return to_ticks(moment)


class HistoryPosition(NamedTuple):
    key: int
    seq: int


@dataclass(frozen=True, slots=True)
class TimeDomain:
    start: int | None
    end: int | None
    limit: int
    backward: bool = False
    after: HistoryPosition | None = None


@dataclass(slots=True)
class HistoryEntry:
    position: HistoryPosition
    value: Any


@dataclass(slots=True)
class Page:
    entries: list[HistoryEntry]
    more: bool


class HistoryStorageInterface:
    """
    Interface of a history backend.
    Must be implemented by backends. Times are Int64 ticks of 100 ns since 1601-01-01 UTC. Entries are ordered
    by their position, (key time, capture sequence); reads return at most `domain.limit` entries and say whether
    more follow.
    """

    stores_server_timestamp: bool = True

    def __init__(self, max_history_data_response_size: int = 10000) -> None:
        self.max_history_data_response_size = max_history_data_response_size

    async def init(self) -> None:
        raise NotImplementedError

    async def has_node(self, node_id: ua.NodeId) -> bool:
        raise NotImplementedError

    async def has_event(self, node_id: ua.NodeId) -> bool:
        raise NotImplementedError

    async def new_historized_node(self, node_id: ua.NodeId, period: timedelta | None, count: int = 0) -> None:
        raise NotImplementedError

    async def save_node_value(self, node_id: ua.NodeId, datavalue: ua.DataValue) -> None:
        raise NotImplementedError

    async def read_node_history(self, node_id: ua.NodeId, domain: TimeDomain) -> Page:
        raise NotImplementedError

    async def new_historized_event(self, source_id: ua.NodeId, period: timedelta | None, count: int = 0) -> None:
        raise NotImplementedError

    async def save_event(self, source_id: ua.NodeId, fields: dict[str, ua.Variant], time: datetime) -> None:
        raise NotImplementedError

    async def read_event_history(self, source_id: ua.NodeId, domain: TimeDomain) -> Page:
        raise NotImplementedError

    async def flush(self) -> None:
        return None

    async def stop(self) -> None:
        raise NotImplementedError


class _MemoryStore:
    def __init__(self, period: timedelta | None, count: int) -> None:
        self.period = period
        self.count = count
        self.positions: list[HistoryPosition] = []
        self.values: list[Any] = []
        self.next_seq = 0

    def cutoff(self) -> int | None:
        if not self.period:
            return None
        return to_ticks(datetime.now(UTC) - self.period)

    def add(self, key: int, value: Any) -> None:
        self.next_seq += 1
        position = HistoryPosition(key, self.next_seq)
        index = bisect_right(self.positions, position)
        self.positions.insert(index, position)
        self.values.insert(index, value)
        self.apply_retention()

    def apply_retention(self) -> None:
        cutoff = self.cutoff()
        drop = bisect_left(self.positions, (cutoff, 0)) if cutoff is not None else 0
        if self.count and len(self.positions) - drop > self.count:
            drop = len(self.positions) - self.count
        if drop:
            del self.positions[:drop]
            del self.values[:drop]

    def read(self, domain: TimeDomain) -> Page:
        start = domain.start
        cutoff = self.cutoff()
        if cutoff is not None and (start is None or start < cutoff):
            start = cutoff
        low = 0 if start is None else bisect_left(self.positions, (start, 0))
        high = len(self.positions) if domain.end is None else bisect_right(self.positions, (domain.end, MAX_SEQUENCE))
        if domain.after is not None:
            if domain.backward:
                high = min(high, bisect_left(self.positions, domain.after))
            else:
                low = max(low, bisect_right(self.positions, domain.after))
        indexes = range(high - 1, low - 1, -1) if domain.backward else range(low, high)
        taken = [HistoryEntry(self.positions[i], self.values[i]) for i in indexes[: domain.limit + 1]]
        return Page(taken[: domain.limit], len(taken) > domain.limit)


class HistoryDict(HistoryStorageInterface):
    """
    Very minimal history backend storing data in memory, in lists ordered by position
    """

    def __init__(self, max_history_data_response_size: int = 10000) -> None:
        super().__init__(max_history_data_response_size)
        self._datachanges: dict[ua.NodeId, _MemoryStore] = {}
        self._events: dict[ua.NodeId, _MemoryStore] = {}

    async def init(self) -> None:
        pass

    async def has_node(self, node_id: ua.NodeId) -> bool:
        return node_id in self._datachanges

    async def has_event(self, node_id: ua.NodeId) -> bool:
        return node_id in self._events

    async def new_historized_node(self, node_id: ua.NodeId, period: timedelta | None, count: int = 0) -> None:
        store = self._datachanges.get(node_id)
        if store is None:
            self._datachanges[node_id] = _MemoryStore(period, count)
        else:
            store.period, store.count = period, count

    async def save_node_value(self, node_id: ua.NodeId, datavalue: ua.DataValue) -> None:
        self._datachanges[node_id].add(key_of_value(datavalue), copy.deepcopy(datavalue))

    async def read_node_history(self, node_id: ua.NodeId, domain: TimeDomain) -> Page:
        store = self._datachanges.get(node_id)
        if store is None:
            return Page([], False)
        return store.read(domain)

    async def new_historized_event(self, source_id: ua.NodeId, period: timedelta | None, count: int = 0) -> None:
        store = self._events.get(source_id)
        if store is None:
            self._events[source_id] = _MemoryStore(period, count)
        else:
            store.period, store.count = period, count

    async def save_event(self, source_id: ua.NodeId, fields: dict[str, ua.Variant], time: datetime) -> None:
        self._events[source_id].add(to_ticks(time), dict(fields))

    async def read_event_history(self, source_id: ua.NodeId, domain: TimeDomain) -> Page:
        store = self._events.get(source_id)
        if store is None:
            return Page([], False)
        return store.read(domain)

    async def stop(self) -> None:
        pass


@dataclass(slots=True)
class Registration:
    kind: str
    handle: Any


class SubHandler:
    def __init__(self, manager: HistoryManager) -> None:
        self.manager = manager

    def datachange_notification(self, node: Node, val: Any, data: Any) -> None:
        self.manager.enqueue_value(node.nodeid, data.monitored_item.Value)

    def event_notification(self, event: Event) -> None:
        pass


class HistoryManager:
    def __init__(self, iserver: InternalServer) -> None:
        self.iserver = iserver
        self.storage: HistoryStorageInterface = HistoryDict()
        self._sub: Subscription | None = None
        self._registry: dict[ua.NodeId, Registration] = {}
        self._queue: asyncio.Queue[tuple[Any, ...]] = asyncio.Queue()
        self._consumer: asyncio.Task[None] | None = None

    async def init(self) -> None:
        await self.storage.init()
        self._ensure_consumer()
        await self._write_capabilities()

    async def _write_capabilities(self) -> None:
        ids = ua.ObjectIds
        flags = {
            ids.HistoryServerCapabilities_AccessHistoryDataCapability: True,
            ids.HistoryServerCapabilities_AccessHistoryEventsCapability: True,
            ids.HistoryServerCapabilities_InsertDataCapability: False,
            ids.HistoryServerCapabilities_ReplaceDataCapability: False,
            ids.HistoryServerCapabilities_UpdateDataCapability: False,
            ids.HistoryServerCapabilities_DeleteRawCapability: False,
            ids.HistoryServerCapabilities_DeleteAtTimeCapability: False,
            ids.HistoryServerCapabilities_InsertAnnotationCapability: False,
            ids.HistoryServerCapabilities_InsertEventCapability: False,
            ids.HistoryServerCapabilities_ReplaceEventCapability: False,
            ids.HistoryServerCapabilities_UpdateEventCapability: False,
            ids.HistoryServerCapabilities_DeleteEventCapability: False,
            ids.HistoryServerCapabilities_ServerTimestampSupported: self.storage.stores_server_timestamp,
        }
        for node_id, flag in flags.items():
            await self._set_trusted(ua.NodeId(node_id), ua.AttributeIds.Value, flag, ua.VariantType.Boolean)
        size = self.iserver.max_history_data_response_size
        for node_id in (
            ids.HistoryServerCapabilities_MaxReturnDataValues,
            ids.HistoryServerCapabilities_MaxReturnEventValues,
        ):
            await self._set_trusted(ua.NodeId(node_id), ua.AttributeIds.Value, size, ua.VariantType.UInt32)

    def set_storage(self, storage: HistoryStorageInterface) -> None:
        """
        set the desired HistoryStorageInterface which History Manager will use for historizing
        """
        if self._registry:
            raise ua.UaError("The history storage cannot be replaced while nodes are historized")
        self.storage = storage

    def _ensure_consumer(self) -> None:
        if self._consumer is None or self._consumer.done():
            self._consumer = asyncio.create_task(self._consume())

    async def _consume(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item[0] == "value":
                    await self.storage.save_node_value(item[1], item[2])
                else:
                    await self.storage.save_event(item[1], item[2], item[3])
            except Exception:
                _logger.exception("History entry for %s was dropped", item[1])
            finally:
                self._queue.task_done()
            if self._queue.empty():
                try:
                    await self.storage.flush()
                except Exception:
                    _logger.exception("History storage could not be flushed")

    def enqueue_value(self, node_id: ua.NodeId, datavalue: ua.DataValue) -> None:
        self._ensure_consumer()
        self._queue.put_nowait(("value", node_id, datavalue))

    def enqueue_event(self, node_id: ua.NodeId, event: Event) -> None:
        self._ensure_consumer()
        fields = event.get_event_props_as_fields_dict()
        self._queue.put_nowait(("event", node_id, copy.deepcopy(fields), getattr(event, "Time", datetime.now(UTC))))

    async def _create_subscription(self) -> Subscription:
        params = ua.CreateSubscriptionParameters()
        params.RequestedPublishingInterval = 10
        params.RequestedLifetimeCount = 3000
        params.RequestedMaxKeepAliveCount = 10000
        params.MaxNotificationsPerPublish = 0
        params.PublishingEnabled = True
        params.Priority = 0
        subscription = Subscription(self.iserver.isession, params, SubHandler(self))
        await subscription.init()
        return subscription

    async def _set_trusted(self, node_id: ua.NodeId, attribute: ua.AttributeIds, value: Any, vtype: Any) -> None:
        status = await self.iserver.aspace.write_attribute_value(
            node_id, attribute, ua.DataValue(ua.Variant(value, vtype))
        )
        status.check()

    def integer_attribute(self, node_id: ua.NodeId, attribute: ua.AttributeIds) -> int:
        value = self.iserver.aspace.read_attribute_value(node_id, attribute).Value
        return int(value.Value) if value is not None and value.Value is not None else 0

    def _node_class(self, node_id: ua.NodeId) -> int:
        node = self.iserver.aspace.get(node_id)
        if node is None:
            raise ua.uaerrors.BadNodeIdUnknown()
        return self.iserver.aspace.node_class_of(node) or 0

    async def _add_bit(self, node_id: ua.NodeId, attribute: ua.AttributeIds, bit: int, on: bool) -> None:
        current = self.integer_attribute(node_id, attribute)
        await self._set_trusted(node_id, attribute, (current | bit) if on else (current & ~bit), ua.VariantType.Byte)

    @property
    def sampling_interval_ms(self) -> float:
        return self.iserver.history_sampling_interval_ms or self.iserver.min_sampling_interval_ms

    async def historize_data_change(
        self, node: Node, period: timedelta | None = timedelta(days=7), count: int = 0
    ) -> None:
        """
        Subscribe to the nodes' data changes and store the data in the active storage.
        """
        node_id = node.nodeid
        if self._node_class(node_id) != ua.NodeClass.Variable:
            raise ua.uaerrors.BadNodeClassInvalid()
        if node_id in self._registry:
            raise UaNodeAlreadyHistorizedError(f"Node {node} is already historized")
        if self._sub is None:
            self._sub = await self._create_subscription()
        await self.storage.new_historized_node(node_id, period, count)
        await self._add_bit(node_id, ua.AttributeIds.AccessLevel, HAS_HISTORY_READ, True)
        await self._add_bit(node_id, ua.AttributeIds.UserAccessLevel, HAS_HISTORY_READ, True)
        await self._set_trusted(node_id, ua.AttributeIds.Historizing, True, ua.VariantType.Boolean)
        mfilter = ua.DataChangeFilter(Trigger=ua.DataChangeTrigger.StatusValueTimestamp)
        handle = await self._sub._subscribe(
            node,
            ua.AttributeIds.Value,
            mfilter,
            queuesize=self.iserver.max_monitored_item_queue_size,
            sampling_interval=ua.Double(self.sampling_interval_ms),
        )
        self._registry[node_id] = Registration("data", handle)

    async def historize_event(self, source: Node, period: timedelta | None = timedelta(days=7), count: int = 0) -> None:
        """
        Store the events that reach the source node: its own and those of every source below it in the notifier
        hierarchy, whatever their event type.
        """
        node_id = source.nodeid
        if self._node_class(node_id) not in (ua.NodeClass.Object, ua.NodeClass.View):
            raise ua.uaerrors.BadNodeClassInvalid()
        if node_id in self._registry:
            raise UaNodeAlreadyHistorizedError(f"Events from {source} are already historized")
        await self.storage.new_historized_event(node_id, period, count)
        await self._add_bit(node_id, ua.AttributeIds.EventNotifier, HISTORY_READ_EVENTS, True)
        handle = self.iserver.subscription_service.add_event_sink(
            node_id, lambda event: self.enqueue_event(node_id, event)
        )
        self._registry[node_id] = Registration("event", handle)

    async def dehistorize(self, node: Node) -> None:
        """
        Stop storing the data or events of the node. The stored history remains readable.
        """
        registration = self._registry.pop(node.nodeid, None)
        if registration is None:
            _logger.error("History Manager isn't subscribed to %s", node)
            return
        if registration.kind == "data":
            if self._sub is not None:
                await self._sub.unsubscribe(registration.handle)
            await self._add_bit(node.nodeid, ua.AttributeIds.AccessLevel, HAS_HISTORY_READ, False)
            await self._add_bit(node.nodeid, ua.AttributeIds.UserAccessLevel, HAS_HISTORY_READ, False)
            await self._set_trusted(node.nodeid, ua.AttributeIds.Historizing, False, ua.VariantType.Boolean)
        else:
            self.iserver.subscription_service.remove_event_sink(registration.handle)
            await self._add_bit(node.nodeid, ua.AttributeIds.EventNotifier, HISTORY_READ_EVENTS, False)

    async def read_history(
        self, params: ua.HistoryReadParameters, points: ContinuationPoints[HistoryCursor], trusted: bool = False
    ) -> list[ua.HistoryReadResult]:
        from .history_read import HistoryReader

        return await HistoryReader(self).read(params, points, trusted)

    async def stop(self) -> None:
        """
        Stop the capture, wait for the queued entries and stop the active storage
        """
        if self._consumer is not None:
            try:
                await asyncio.wait_for(self._queue.join(), CAPTURE_DRAIN_SECONDS)
            except TimeoutError:
                _logger.warning("History capture queue was not drained in time")
            self._consumer.cancel()
            try:
                await self._consumer
            except asyncio.CancelledError:
                pass
            self._consumer = None
        await self.storage.stop()

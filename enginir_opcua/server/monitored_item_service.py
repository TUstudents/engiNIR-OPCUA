"""
server side implementation of a subscription object
"""

from __future__ import annotations

import copy
import dataclasses
import logging
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.common import utils

from .address_space import AddressSpace
from .content_filter import MAX_FILTER_ELEMENTS, EventFilterChecker, WhereClauseEvaluator
from .data_change import data_change_passes
from .index_range import select_index_range
from .node_walk import is_subtype

if TYPE_CHECKING:
    from .internal_subscription import InternalSubscription


@dataclass
class MonitoredItemLimits:
    max_queue_size: int = 1000
    default_event_queue_size: int = 100
    min_sampling_interval: float = 10.0
    max_sampling_interval: float = 3_600_000.0
    max_items_per_subscription: int = 10_000
    max_items: int = 100_000
    items_in_server: Callable[[], int] = field(default=lambda: 0)


OVERFLOW_INFO_BITS = 0x0480
HAS_PROPERTY = ua.NodeId(ua.ObjectIds.HasProperty)
BASE_DATA_TYPE = ua.NodeId(ua.ObjectIds.BaseDataType)
NUMBER = ua.NodeId(ua.ObjectIds.Number)
VALID_TIMESTAMPS = (
    ua.TimestampsToReturn.Source,
    ua.TimestampsToReturn.Server,
    ua.TimestampsToReturn.Both,
    ua.TimestampsToReturn.Neither,
)


class MonitoredItemData:
    def __init__(self) -> None:
        self.client_handle: int | None = None
        self.callback_handle: int | None = None
        self.monitored_item_id: int | None = None
        self.mode: ua.MonitoringMode | None = None
        self.read_value_id: ua.ReadValueId | None = None
        self.filter: Any = None
        self.last_sample: ua.DataValue | None = None
        self.last_reported: ua.DataValue | None = None
        self.where_clause_evaluator: WhereClauseEvaluator | None = None
        self.usable_selects: list[bool] = []
        self.queue_size: int = 0
        self.sampling_interval: float = 0.0
        self.discard_oldest: bool = True
        self.timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both
        self.held: list[Any] = []


class MonitoredItemService:
    """
    Implements monitored item service for one subscription
    """

    def __init__(self, isub: "InternalSubscription", aspace: AddressSpace) -> None:
        self.logger = logging.getLogger(f"{__name__}.{isub.data.SubscriptionId}")
        self.isub: "InternalSubscription" = isub
        self.aspace: AddressSpace = aspace
        self._monitored_items: dict[int, MonitoredItemData] = {}
        self._monitored_events: dict[ua.NodeId, list[int]] = {}
        self._monitored_datachange: dict[int, int] = {}
        self._monitored_item_counter = 111

    def __str__(self) -> str:
        return f"MonitoredItemService({self.isub.data.SubscriptionId})"

    def item_count(self) -> int:
        return len(self._monitored_items)

    def delete_all_monitored_items(self) -> None:
        self.delete_monitored_items([mdata.monitored_item_id for mdata in self._monitored_items.values()])

    @staticmethod
    def _check_timestamps(timestamps: ua.TimestampsToReturn) -> None:
        if timestamps not in VALID_TIMESTAMPS:
            raise utils.ServiceError(ua.StatusCodes.BadTimestampsToReturnInvalid)

    async def create_monitored_items(
        self, params: ua.CreateMonitoredItemsParameters
    ) -> list[ua.MonitoredItemCreateResult]:
        self._check_timestamps(params.TimestampsToReturn)
        results: list[ua.MonitoredItemCreateResult] = []
        for item in params.ItemsToCreate:
            if item.MonitoringMode not in tuple(ua.MonitoringMode):
                result = ua.MonitoredItemCreateResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadMonitoringModeInvalid))
            elif item.ItemToMonitor.AttributeId == ua.AttributeIds.EventNotifier:
                result = self._create_events_monitored_item(item, params.TimestampsToReturn)
            else:
                result = await self._create_data_change_monitored_item(item, params.TimestampsToReturn)
            results.append(result)
        return results

    async def resend_initial_values(self) -> None:
        for mid, mdata in list(self._monitored_items.items()):
            read_value_id = mdata.read_value_id
            if mdata.mode != ua.MonitoringMode.Reporting or read_value_id is None or mdata.callback_handle is None:
                continue
            if read_value_id.AttributeId == ua.AttributeIds.EventNotifier or self.isub.has_queued_datachange(mid):
                continue
            value = mdata.last_sample
            if value is None:
                value = self.aspace.read_attribute_value(read_value_id.NodeId, read_value_id.AttributeId)
            self._queue_data(mdata, value)

    def modify_monitored_items(self, params: ua.ModifyMonitoredItemsParameters) -> list[ua.MonitoredItemModifyResult]:
        self._check_timestamps(params.TimestampsToReturn)
        results: list[ua.MonitoredItemModifyResult] = []
        for item in params.ItemsToModify:
            results.append(self._modify_monitored_item(item, params.TimestampsToReturn))
        return results

    async def trigger_datachange(self, handle: int, nodeid: ua.NodeId, attr: ua.AttributeIds) -> None:
        self.logger.debug("triggering datachange for handle %s, nodeid %s, and attribute %s", handle, nodeid, attr)
        dv = self.aspace.read_attribute_value(nodeid, attr)
        await self.datachange_callback(handle, dv)

    def _modify_monitored_item(
        self, params: ua.MonitoredItemModifyRequest, timestamps: ua.TimestampsToReturn
    ) -> ua.MonitoredItemModifyResult:
        mdata = self._monitored_items.get(params.MonitoredItemId)
        if mdata is None:
            return ua.MonitoredItemModifyResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadMonitoredItemIdInvalid))
        requested = params.RequestedParameters
        is_event = self._is_event_item(mdata)
        node_id = mdata.read_value_id.NodeId if mdata.read_value_id is not None else None
        new_filter = self._normalise_filter(requested.Filter)
        status = self._check_filter(mdata.read_value_id, new_filter)
        if not status.is_good():
            return ua.MonitoredItemModifyResult(StatusCode=status)
        filter_result = None
        if is_event:
            status, filter_result = self._check_event_filter(new_filter)
            if not status.is_good():
                return ua.MonitoredItemModifyResult(StatusCode=status, FilterResult=filter_result)
            mdata.where_clause_evaluator = WhereClauseEvaluator(self.logger, self.aspace, new_filter.WhereClause)
            mdata.usable_selects = [code.is_good() for code in filter_result.SelectClauseResults]
        mdata.filter = new_filter
        mdata.sampling_interval = self._revise_sampling_interval(requested.SamplingInterval, node_id, is_event)
        mdata.queue_size = self._revise_queue_size(requested.QueueSize, is_event)
        mdata.discard_oldest = requested.DiscardOldest
        mdata.client_handle = requested.ClientHandle
        mdata.timestamps = timestamps
        self._trim(mdata)
        return ua.MonitoredItemModifyResult(
            RevisedSamplingInterval=mdata.sampling_interval,
            RevisedQueueSize=mdata.queue_size,
            FilterResult=filter_result,
        )

    @staticmethod
    def _is_event_item(mdata: MonitoredItemData) -> bool:
        return mdata.read_value_id is not None and mdata.read_value_id.AttributeId == ua.AttributeIds.EventNotifier

    def _commit_monitored_item(self, result: ua.MonitoredItemCreateResult, mdata: MonitoredItemData) -> None:
        if result.StatusCode.is_good():
            self._monitored_items[result.MonitoredItemId] = mdata

    def _at_limit(self) -> bool:
        limits = self.isub.limits
        return len(self._monitored_items) >= limits.max_items_per_subscription or (
            limits.items_in_server() >= limits.max_items
        )

    def _make_monitored_item_common(
        self, params: ua.MonitoredItemCreateRequest, timestamps: ua.TimestampsToReturn
    ) -> tuple[ua.MonitoredItemCreateResult, MonitoredItemData]:
        result = ua.MonitoredItemCreateResult()
        is_event = params.ItemToMonitor.AttributeId == ua.AttributeIds.EventNotifier
        requested = params.RequestedParameters
        result.RevisedSamplingInterval = self._revise_sampling_interval(
            requested.SamplingInterval, params.ItemToMonitor.NodeId, is_event
        )
        result.RevisedQueueSize = self._revise_queue_size(requested.QueueSize, is_event)
        self._monitored_item_counter += 1
        result.MonitoredItemId = self._monitored_item_counter
        self.logger.debug("Creating MonitoredItem with id %s", result.MonitoredItemId)
        mdata = MonitoredItemData()
        mdata.mode = params.MonitoringMode
        mdata.read_value_id = params.ItemToMonitor
        mdata.client_handle = requested.ClientHandle
        mdata.monitored_item_id = result.MonitoredItemId
        mdata.queue_size = result.RevisedQueueSize
        mdata.sampling_interval = result.RevisedSamplingInterval
        mdata.discard_oldest = requested.DiscardOldest
        mdata.timestamps = timestamps
        mdata.filter = requested.Filter
        return result, mdata

    def _revise_queue_size(self, requested: int, is_event: bool) -> int:
        limits = self.isub.limits
        if is_event and requested == 0:
            return min(limits.default_event_queue_size, limits.max_queue_size)
        return min(max(int(requested), 1), limits.max_queue_size)

    def _revise_sampling_interval(self, requested: float, node_id: ua.NodeId | None, is_event: bool) -> float:
        if is_event:
            return 0.0
        limits = self.isub.limits
        if math.isnan(requested) or requested < 0:
            interval = self.isub.data.RevisedPublishingInterval
        else:
            interval = requested
        interval = max(interval, limits.min_sampling_interval, self._node_minimum_sampling_interval(node_id))
        return min(interval, limits.max_sampling_interval)

    def _node_minimum_sampling_interval(self, node_id: ua.NodeId | None) -> float:
        if node_id is None:
            return 0.0
        dv = self.aspace.read_attribute_value(node_id, ua.AttributeIds.MinimumSamplingInterval)
        if dv.Value is None or (dv.StatusCode is not None and dv.StatusCode.is_bad()):
            return 0.0
        if not isinstance(dv.Value.Value, int | float):
            return 0.0
        return max(float(dv.Value.Value), 0.0)

    def _create_events_monitored_item(
        self, params: ua.MonitoredItemCreateRequest, timestamps: ua.TimestampsToReturn
    ) -> ua.MonitoredItemCreateResult:
        self.logger.info(
            "request to subscribe to events for node %s and attribute %s",
            params.ItemToMonitor.NodeId,
            params.ItemToMonitor.AttributeId,
        )

        result, mdata = self._make_monitored_item_common(params, timestamps)
        node_id = params.ItemToMonitor.NodeId
        if node_id is None:
            result.StatusCode = ua.StatusCode(ua.StatusCodes.BadNodeIdInvalid)
            return result
        dv = self.aspace.read_attribute_value(node_id, ua.AttributeIds.EventNotifier)
        if dv.StatusCode is not None and dv.StatusCode.is_bad():
            result.StatusCode = dv.StatusCode
            return result
        ev_notify_byte = dv.Value.Value if dv.Value is not None else None
        if ev_notify_byte is None or not ua.ua_binary.is_bit_set(ev_notify_byte, ua.EventNotifier.SubscribeToEvents):
            result.StatusCode = ua.StatusCode(ua.StatusCodes.BadNodeIdInvalid)
            return result
        mdata.filter = self._normalise_filter(mdata.filter)
        status = self._check_filter(params.ItemToMonitor, mdata.filter)
        if status.is_good():
            status, result.FilterResult = self._check_event_filter(mdata.filter)
        if not status.is_good():
            result.StatusCode = status
            return result
        if self._at_limit():
            result.StatusCode = ua.StatusCode(ua.StatusCodes.BadTooManyMonitoredItems)
            return result
        mdata.where_clause_evaluator = WhereClauseEvaluator(self.logger, self.aspace, mdata.filter.WhereClause)
        mdata.usable_selects = [code.is_good() for code in result.FilterResult.SelectClauseResults]
        self._commit_monitored_item(result, mdata)
        if params.ItemToMonitor.NodeId not in self._monitored_events:
            self._monitored_events[params.ItemToMonitor.NodeId] = []
        self._monitored_events[params.ItemToMonitor.NodeId].append(result.MonitoredItemId)
        return result

    async def _create_data_change_monitored_item(
        self, params: ua.MonitoredItemCreateRequest, timestamps: ua.TimestampsToReturn
    ) -> ua.MonitoredItemCreateResult:
        self.logger.info(
            "request to subscribe to datachange for node %s and attribute %s",
            params.ItemToMonitor.NodeId,
            params.ItemToMonitor.AttributeId,
        )

        result, mdata = self._make_monitored_item_common(params, timestamps)
        result.StatusCode, handle = self.aspace.add_datachange_callback(
            params.ItemToMonitor.NodeId, params.ItemToMonitor.AttributeId, self.datachange_callback
        )

        self.logger.debug("adding callback return status %s and handle %s", result.StatusCode, handle)
        if result.StatusCode.is_good():
            mdata.filter = self._normalise_filter(mdata.filter)
            status = self._check_filter(params.ItemToMonitor, mdata.filter)
            if not status.is_good():
                self.aspace.delete_datachange_callback(handle)
                result.StatusCode = status
            elif self._at_limit():
                self.aspace.delete_datachange_callback(handle)
                result.StatusCode = ua.StatusCode(ua.StatusCodes.BadTooManyMonitoredItems)
        mdata.callback_handle = handle
        self._commit_monitored_item(result, mdata)
        if result.StatusCode.is_good():
            self._monitored_datachange[handle] = result.MonitoredItemId
            if mdata.mode != ua.MonitoringMode.Disabled:
                await self.trigger_datachange(handle, params.ItemToMonitor.NodeId, params.ItemToMonitor.AttributeId)
        return result

    async def set_monitoring_mode(self, mode: ua.MonitoringMode, ids: list[int]) -> list[ua.StatusCode]:
        self.logger.info("set monitoring mode to %s for items %s", mode, ids)
        if mode not in tuple(ua.MonitoringMode):
            raise utils.ServiceError(ua.StatusCodes.BadMonitoringModeInvalid)
        results: list[ua.StatusCode] = []
        for mid in ids:
            results.append(await self._set_monitoring_mode(mode, mid))
        return results

    async def _set_monitoring_mode(self, mode: ua.MonitoringMode, mid: int) -> ua.StatusCode:
        mdata = self._monitored_items.get(mid)
        if mdata is None:
            return ua.StatusCode(ua.StatusCodes.BadMonitoredItemIdInvalid)
        previous_mode = mdata.mode
        if mode == previous_mode:
            return ua.StatusCode()
        is_event = self._is_event_item(mdata)
        if mode == ua.MonitoringMode.Disabled:
            self._clear(mdata)
            mdata.mode = mode
        elif previous_mode == ua.MonitoringMode.Disabled:
            mdata.mode = mode
            if not is_event and mdata.callback_handle is not None and mdata.read_value_id is not None:
                await self.trigger_datachange(
                    mdata.callback_handle, mdata.read_value_id.NodeId, mdata.read_value_id.AttributeId
                )
        elif mode == ua.MonitoringMode.Reporting:
            mdata.mode = mode
            self._release_held(mdata)
        else:
            mdata.held = self.isub.take_queue(mid, is_event)
            mdata.mode = mode
        return ua.StatusCode()

    def _clear(self, mdata: MonitoredItemData) -> None:
        mdata.held = []
        mdata.last_sample = None
        mdata.last_reported = None
        if mdata.monitored_item_id is not None:
            self.isub.take_queue(mdata.monitored_item_id, self._is_event_item(mdata))

    def _release_held(self, mdata: MonitoredItemData) -> None:
        held, mdata.held = mdata.held, []
        for notification in held:
            self._push(mdata, notification)

    def delete_monitored_items(self, ids: list[int]) -> list[ua.StatusCode]:
        self.logger.debug("delete monitored items %s", ids)
        results: list[ua.StatusCode] = []
        for mid in ids:
            results.append(self._delete_monitored_items(mid))
        return results

    def _delete_monitored_items(self, mid: int) -> ua.StatusCode:
        mdata = self._monitored_items.get(mid)
        if mdata is None:
            return ua.StatusCode(ua.StatusCodes.BadMonitoredItemIdInvalid)
        for node_key, mid_list in self._monitored_events.items():
            if mid in mid_list:
                mid_list.remove(mid)
                if not mid_list:
                    self._monitored_events.pop(node_key)
                break
        for handle, owner_mid in self._monitored_datachange.items():
            if owner_mid == mid:
                self.aspace.delete_datachange_callback(handle)
                self._monitored_datachange.pop(handle)
                break
        self._clear(mdata)
        self._monitored_items.pop(mid)
        return ua.StatusCode()

    @staticmethod
    def _with_timestamps(value: ua.DataValue, timestamps: ua.TimestampsToReturn) -> ua.DataValue:
        keep_source = timestamps in (ua.TimestampsToReturn.Source, ua.TimestampsToReturn.Both)
        keep_server = timestamps in (ua.TimestampsToReturn.Server, ua.TimestampsToReturn.Both)
        return dataclasses.replace(
            value,
            SourceTimestamp=value.SourceTimestamp if keep_source else None,
            SourcePicoseconds=value.SourcePicoseconds if keep_source else None,
            ServerTimestamp=value.ServerTimestamp if keep_server else None,
            ServerPicoseconds=value.ServerPicoseconds if keep_server else None,
        )

    def _queue_data(self, mdata: MonitoredItemData, value: ua.DataValue) -> None:
        notification = ua.MonitoredItemNotification(
            ClientHandle=mdata.client_handle, Value=self._with_timestamps(copy.deepcopy(value), mdata.timestamps)
        )
        self._push(mdata, notification)

    def _active_queue(self, mdata: MonitoredItemData) -> list[Any]:
        if mdata.mode == ua.MonitoringMode.Reporting and mdata.monitored_item_id is not None:
            return self.isub.queue_of(mdata.monitored_item_id, self._is_event_item(mdata))
        return mdata.held

    def _push(self, mdata: MonitoredItemData, notification: Any) -> None:
        queue = self._active_queue(mdata)
        size = max(mdata.queue_size, 1)
        excess = len(queue) - size + 1
        if excess <= 0:
            queue.append(notification)
            return
        if size == 1:
            queue[:] = [notification]
            return
        if mdata.discard_oldest:
            del queue[:excess]
            queue.append(notification)
            self._flag_overflow(queue[0])
        else:
            del queue[len(queue) - excess :]
            queue.append(notification)
            self._flag_overflow(queue[-1])

    def _trim(self, mdata: MonitoredItemData) -> None:
        queue = self._active_queue(mdata)
        size = max(mdata.queue_size, 1)
        if len(queue) <= size:
            return
        if mdata.discard_oldest:
            del queue[: len(queue) - size]
        else:
            del queue[size:]
        if size > 1 and queue:
            self._flag_overflow(queue[0] if mdata.discard_oldest else queue[-1])

    @staticmethod
    def _flag_overflow(notification: Any) -> None:
        if not isinstance(notification, ua.MonitoredItemNotification) or notification.Value is None:
            return
        code = notification.Value.StatusCode.value if notification.Value.StatusCode is not None else 0
        notification.Value = dataclasses.replace(
            notification.Value, StatusCode=ua.StatusCode(code | OVERFLOW_INFO_BITS)
        )

    async def datachange_callback(self, handle: int, value: ua.DataValue, error: ua.StatusCode | None = None) -> None:
        if error:
            self.logger.info(
                "subscription %s: datachange callback called with handle '%s' and error '%s'", self, handle, error
            )
            await self.trigger_statuschange(error)
        else:
            mid = self._monitored_datachange[handle]
            mdata = self._monitored_items[mid]
            if mdata.mode == ua.MonitoringMode.Disabled:
                return
            mdata.last_sample = copy.deepcopy(value)
            flt = mdata.filter if isinstance(mdata.filter, ua.uaprotocol_auto.DataChangeFilter) else None
            eu_range = None
            if flt is not None and flt.DeadbandType == ua.DeadbandType.Percent and mdata.read_value_id is not None:
                eu_range = self._eu_range(mdata.read_value_id.NodeId)
            if data_change_passes(mdata.last_reported, value, flt, eu_range):
                mdata.last_reported = mdata.last_sample
                self._queue_data(mdata, value)

    def _eu_range(self, node_id: ua.NodeId) -> tuple[float, float] | None:
        data = self.aspace.get(node_id)
        if data is None:
            return None
        for ref in data.references:
            if ref.IsForward and ref.ReferenceTypeId == HAS_PROPERTY and ref.BrowseName.Name == "EURange":
                dv = self.aspace.read_attribute_value(ref.NodeId, ua.AttributeIds.Value)
                value = dv.Value.Value if dv.Value is not None else None
                if isinstance(value, ua.Range):
                    return float(value.Low), float(value.High)
        return None

    @staticmethod
    def _normalise_filter(flt: Any) -> Any:
        if isinstance(flt, ua.ExtensionObject) and (flt.Body is None or flt.TypeId.is_null()):
            return None
        return flt

    def _check_event_filter(self, flt: ua.EventFilter) -> tuple[ua.StatusCode, ua.EventFilterResult]:
        ok, filter_result = EventFilterChecker(self.aspace).check(flt)
        if len(flt.WhereClause.Elements) > MAX_FILTER_ELEMENTS:
            return ua.StatusCode(ua.StatusCodes.BadContentFilterInvalid), filter_result
        if not ok:
            return ua.StatusCode(ua.StatusCodes.BadMonitoredItemFilterInvalid), filter_result
        return ua.StatusCode(), filter_result

    def _check_filter(self, item: ua.ReadValueId | None, flt: Any) -> ua.StatusCode:
        code = self._filter_status(item, flt)
        return ua.StatusCode(code)

    def _filter_status(self, item: ua.ReadValueId | None, flt: Any) -> int:
        if item is None:
            return ua.StatusCodes.BadInternalError
        if item.AttributeId == ua.AttributeIds.EventNotifier:
            return self._event_filter_status(flt)
        if flt is None:
            return ua.StatusCodes.Good
        if item.AttributeId != ua.AttributeIds.Value or isinstance(flt, ua.uaprotocol_auto.EventFilter):
            return ua.StatusCodes.BadFilterNotAllowed
        if isinstance(flt, ua.uaprotocol_auto.AggregateFilter):
            return ua.StatusCodes.BadMonitoredItemFilterUnsupported
        if not isinstance(flt, ua.uaprotocol_auto.DataChangeFilter):
            return ua.StatusCodes.BadMonitoredItemFilterInvalid
        return self._data_change_filter_status(item.NodeId, flt)

    @staticmethod
    def _event_filter_status(flt: Any) -> int:
        if isinstance(flt, ua.uaprotocol_auto.EventFilter):
            return ua.StatusCodes.Good
        if isinstance(flt, ua.uaprotocol_auto.DataChangeFilter):
            return ua.StatusCodes.BadFilterNotAllowed
        if isinstance(flt, ua.uaprotocol_auto.AggregateFilter):
            return ua.StatusCodes.BadMonitoredItemFilterUnsupported
        return ua.StatusCodes.BadMonitoredItemFilterInvalid

    def _data_change_filter_status(self, node_id: ua.NodeId, flt: ua.DataChangeFilter) -> int:
        if flt.Trigger not in tuple(ua.DataChangeTrigger):
            return ua.StatusCodes.BadMonitoredItemFilterInvalid
        if flt.DeadbandType not in tuple(ua.DeadbandType):
            return ua.StatusCodes.BadMonitoredItemFilterInvalid
        if flt.DeadbandType == ua.DeadbandType.None_:
            return ua.StatusCodes.Good
        if not self._holds_numbers(node_id):
            return ua.StatusCodes.BadFilterNotAllowed
        if math.isnan(flt.DeadbandValue) or flt.DeadbandValue < 0:
            return ua.StatusCodes.BadDeadbandFilterInvalid
        if flt.DeadbandType == ua.DeadbandType.Percent:
            if flt.DeadbandValue > 100 or self._eu_range(node_id) is None:
                return ua.StatusCodes.BadDeadbandFilterInvalid
        return ua.StatusCodes.Good

    def _holds_numbers(self, node_id: ua.NodeId) -> bool:
        dv = self.aspace.read_attribute_value(node_id, ua.AttributeIds.DataType)
        data_type = dv.Value.Value if dv.Value is not None else None
        if not isinstance(data_type, ua.NodeId):
            return True
        return data_type == BASE_DATA_TYPE or is_subtype(self.aspace, data_type, NUMBER)

    async def trigger_event(self, event: Any, mid: int | None = None) -> bool:
        if event.emitting_node not in self._monitored_events:
            self.logger.debug("%s has NO subscription for events %s from node: %s", self, event, event.emitting_node)
            return False

        self.logger.debug("%s has subscription for events %s from node: %s", self, event, event.emitting_node)
        if mid is not None:
            await self._trigger_event(event, mid)
        else:
            mids = self._monitored_events[event.emitting_node]
            for mid in mids:
                await self._trigger_event(event, mid)
        return True

    async def _trigger_event(self, event: Any, mid: int) -> None:
        if mid not in self._monitored_items:
            self.logger.debug(
                "Could not find monitored items for id %s for event %s in subscription %s", mid, event, self
            )
            return
        mdata = self._monitored_items[mid]
        if mdata.mode == ua.MonitoringMode.Disabled:
            return
        if mdata.where_clause_evaluator is None or not mdata.where_clause_evaluator.eval(event):
            self.logger.info("%s, %s, Event %s does not fit WhereClause, not generating event", self, mid, event)
            return
        fieldlist = ua.EventFieldList()
        fieldlist.ClientHandle = mdata.client_handle
        clauses = mdata.filter.SelectClauses
        fields = event.to_event_fields(clauses, self._is_subtype, select_index_range)
        fieldlist.EventFields = [
            field if usable else ua.Variant(None) for field, usable in zip(fields, mdata.usable_selects)
        ]
        self._push(mdata, fieldlist)

    def _is_subtype(self, candidate: ua.NodeId, ancestor: ua.NodeId) -> bool:
        return is_subtype(self.aspace, candidate, ancestor)

    async def trigger_statuschange(self, code: ua.StatusCode) -> None:
        await self.isub.enqueue_statuschange(code)

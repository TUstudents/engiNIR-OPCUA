"""The ConditionManager: Condition instances, the Methods, ConditionRefresh and the retained Conditions."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine, Mapping
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.common import event_objects, events
from enginir_opcua.common.instantiate_util import instantiate
from enginir_opcua.common.node import Node

from ..internal_session import current_call_session
from ..node_walk import is_subtype, notifiers_of
from . import limits as limit_logic
from .condition import OBJECT_CHILD_FIELDS, Condition, Spec, stamp_event

if TYPE_CHECKING:
    from ..internal_server import InternalServer

_logger = logging.getLogger(__name__)

T = ua.NodeId
CONDITION_TYPE = T(ua.ObjectIds.ConditionType)
ACKNOWLEDGEABLE = T(ua.ObjectIds.AcknowledgeableConditionType)
ALARM_TYPE = T(ua.ObjectIds.AlarmConditionType)
LIMIT_ALARM = T(ua.ObjectIds.LimitAlarmType)
EXCLUSIVE_LIMIT = T(ua.ObjectIds.ExclusiveLimitAlarmType)
NON_EXCLUSIVE_LIMIT = T(ua.ObjectIds.NonExclusiveLimitAlarmType)
DEVIATION_TYPES = (
    T(ua.ObjectIds.ExclusiveDeviationAlarmType),
    T(ua.ObjectIds.NonExclusiveDeviationAlarmType),
)
OFF_NORMAL = T(ua.ObjectIds.OffNormalAlarmType)
HAS_EVENT_SOURCE = T(ua.ObjectIds.HasEventSource)
HAS_CONDITION = T(ua.ObjectIds.HasCondition)
HAS_COMPONENT = T(ua.ObjectIds.HasComponent)
SERVER = T(ua.ObjectIds.Server)
TIERS = ("HighHigh", "High", "Low", "LowLow")
LIMIT_PROPERTIES = {
    **{f"{tier}Limit": tier for tier in TIERS},
}
SHELVING_METHODS = {
    ua.ObjectIds.ShelvedStateMachineType_TimedShelve,
    ua.ObjectIds.ShelvedStateMachineType_TimedShelve2,
    ua.ObjectIds.ShelvedStateMachineType_OneShotShelve,
    ua.ObjectIds.ShelvedStateMachineType_OneShotShelve2,
    ua.ObjectIds.ShelvedStateMachineType_Unshelve,
    ua.ObjectIds.ShelvedStateMachineType_Unshelve2,
}


def _is_meta(name: str) -> bool:
    return name.endswith(("/TrueState", "/FalseState"))


class ConditionManager:
    def __init__(self, iserver: InternalServer) -> None:
        self.iserver = iserver
        self.conditions: dict[ua.NodeId, Condition] = {}
        self._shelving_owner: dict[ua.NodeId, Condition] = {}
        self._templates: dict[ua.NodeId, Any] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._refreshing: set[int] = set()
        self.audit_hook: Any = None

    @property
    def aspace(self) -> Any:
        return self.iserver.aspace

    def spawn(self, coroutine: Coroutine[Any, Any, None]) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def init(self) -> None:
        handlers = {
            ua.ObjectIds.ConditionType_Enable: self._enable,
            ua.ObjectIds.ConditionType_Disable: self._disable,
            ua.ObjectIds.ConditionType_AddComment: self._add_comment,
            ua.ObjectIds.AcknowledgeableConditionType_Acknowledge: self._acknowledge,
            ua.ObjectIds.AcknowledgeableConditionType_Confirm: self._confirm,
            ua.ObjectIds.ShelvedStateMachineType_TimedShelve: self._timed_shelve,
            ua.ObjectIds.ShelvedStateMachineType_TimedShelve2: self._timed_shelve2,
            ua.ObjectIds.ShelvedStateMachineType_OneShotShelve: self._one_shot_shelve,
            ua.ObjectIds.ShelvedStateMachineType_OneShotShelve2: self._one_shot_shelve2,
            ua.ObjectIds.ShelvedStateMachineType_Unshelve: self._unshelve,
            ua.ObjectIds.ShelvedStateMachineType_Unshelve2: self._unshelve2,
            ua.ObjectIds.ConditionType_ConditionRefresh: self._refresh,
            ua.ObjectIds.ConditionType_ConditionRefresh2: self._refresh2,
        }
        for method_id, handler in handlers.items():
            self.aspace.add_method_callback(ua.NodeId(method_id), handler)
        self.iserver.method_service.ownership_hooks.append(self._owns_shelving_method)

    def _owns_shelving_method(self, object_id: ua.NodeId, method_id: ua.NodeId) -> bool:
        if method_id.NamespaceIndex != 0 or method_id.Identifier not in SHELVING_METHODS:
            return False
        return object_id in self.conditions

    async def stop(self) -> None:
        for condition in self.conditions.values():
            condition._cancel_shelve_timer()
        for task in list(self._tasks):
            task.cancel()

    # ---- delivery

    async def deliver(self, event: Any) -> None:
        await self.iserver.subscription_service.trigger_event(event)

    def retained(self) -> list[Any]:
        found: list[Any] = []
        for condition in self.conditions.values():
            found.extend(condition.retained_events())
        return found

    # ---- creating Conditions

    async def create(
        self,
        source: Node | ua.NodeId | None,
        condition_type: Node | ua.NodeId | int,
        name: str,
        *,
        node_id: ua.NodeId | None = None,
        namespace: int | None = None,
        notifier: Node | ua.NodeId | None = None,
        confirmable: bool = False,
        shelving: bool = False,
        suppression: bool = False,
        branches: bool = False,
        severity: int = 1,
        condition_class: ua.NodeId | None = None,
        quality: ua.StatusCode | None = None,
        comment_max_length: int | None = None,
        limits: Mapping[str, float] | None = None,
        deadbands: Mapping[str, float] | None = None,
        severities: Mapping[str, int] | None = None,
        input_node: Node | ua.NodeId | None = None,
        normal_value: Any = None,
        normal_node: Node | ua.NodeId | None = None,
        setpoint_node: Node | ua.NodeId | None = None,
        follow_input: bool = False,
        max_time_shelved: float | None = None,
    ) -> Condition:
        isession = self.iserver.isession
        type_id = _nodeid(condition_type)
        aspace = self.aspace
        if aspace.get(type_id) is None or not is_subtype(aspace, type_id, CONDITION_TYPE) or type_id == CONDITION_TYPE:
            raise ua.uaerrors.BadNodeIdInvalid()
        abstract = aspace.read_attribute_value(type_id, ua.AttributeIds.IsAbstract)
        if abstract.Value is not None and abstract.Value.Value is True:
            raise ua.uaerrors.BadNodeIdInvalid()
        source_node = None
        source_name = None
        if source is not None:
            source_node = source if isinstance(source, Node) else Node(isession, source)
            if aspace.get(source_node.nodeid) is None:
                raise ua.uaerrors.BadNodeIdUnknown()
            source_name = (await source_node.read_browse_name()).Name
        spec = self._spec_for(
            type_id, confirmable, shelving, suppression, branches, comment_max_length, max_time_shelved
        )
        limits = dict(limits or {})
        deadbands = dict(deadbands or {})
        severities = {name: int(value) for name, value in (severities or {}).items()}
        if spec.exclusive or spec.non_exclusive:
            limit_logic.validate_limits(limits, deadbands, deviation=spec.deviation, exclusive=spec.exclusive)
        elif limits or deadbands:
            raise ValueError("Limits only fit the limit alarm types")
        if spec.off_normal and normal_value is None and normal_node is None:
            raise ValueError("An off-normal alarm needs normal_value or normal_node")
        if not 1 <= severity <= 1000:
            raise ValueError("Severity must be between 1 and 1000")
        optional = self._optional_children(spec, limits, deadbands, severities, max_time_shelved, setpoint_node)
        parent = await self._parent_for(source_node)
        index = namespace if namespace is not None else (type_id.NamespaceIndex or source_node_ns(source_node) or 2)
        if node_id is not None and aspace.get(node_id) is not None:
            raise ua.uaerrors.BadNodeIdExists()
        type_node = Node(isession, type_id)
        created = await instantiate(
            parent,
            type_node,
            nodeid=node_id,
            bname=ua.QualifiedName(name, index),
            idx=index,
            instantiate_optional=False,
            optional=optional,
        )
        node = created[0]
        template = await self._template(type_id)
        paths = await self._paths_of(node)
        condition = Condition(
            self, node, name, type_id, source_node.nodeid if source_node else None, source_name, spec, template, paths
        )
        condition.trunk.severity = severity
        if quality is not None:
            condition.trunk.quality = quality
        if condition_class is not None:
            condition.condition_class = condition_class
            browse = aspace.read_attribute_value(condition_class, ua.AttributeIds.DisplayName)
            if browse.Value is not None and isinstance(browse.Value.Value, ua.LocalizedText):
                condition.condition_class_name = browse.Value.Value
        condition.limits, condition.deadbands, condition.severities = limits, deadbands, severities
        condition.input_node = _nodeid(input_node) if input_node is not None else ua.NodeId()
        condition.normal_value = normal_value
        condition.normal_node = _nodeid(normal_node) if normal_node is not None else ua.NodeId()
        condition.setpoint_node = _nodeid(setpoint_node) if setpoint_node is not None else ua.NodeId()
        self.conditions[node.nodeid] = condition
        if shelving:
            self._shelving_owner[paths["ShelvingState"]] = condition
        await self._link(condition, source_node, notifier)
        await self._bind_instance_methods(condition)
        await condition._mirror(condition.trunk)
        if follow_input and condition.input_node != ua.NodeId():
            self._follow(condition)
        return condition

    def _spec_for(
        self,
        type_id: ua.NodeId,
        confirmable: bool,
        shelving: bool,
        suppression: bool,
        branches: bool,
        comment_max_length: int | None,
        max_time_shelved: float | None,
    ) -> Spec:
        aspace = self.aspace
        spec = Spec()
        spec.has_ack = is_subtype(aspace, type_id, ACKNOWLEDGEABLE)
        spec.has_active = is_subtype(aspace, type_id, ALARM_TYPE)
        spec.has_confirm = confirmable
        spec.has_shelving = shelving
        spec.has_suppression = suppression
        spec.branches = branches
        spec.exclusive = is_subtype(aspace, type_id, EXCLUSIVE_LIMIT)
        spec.non_exclusive = is_subtype(aspace, type_id, NON_EXCLUSIVE_LIMIT)
        spec.deviation = any(is_subtype(aspace, type_id, deviation) for deviation in DEVIATION_TYPES)
        spec.off_normal = is_subtype(aspace, type_id, OFF_NORMAL)
        spec.max_time_shelved = max_time_shelved
        if comment_max_length is not None:
            spec.comment_max_length = comment_max_length
        if (confirmable and not spec.has_ack) or ((shelving or suppression) and not spec.has_active):
            raise ValueError(
                "confirmable, shelving and suppression need an AlarmConditionType or an AcknowledgeableConditionType"
            )
        return spec

    @staticmethod
    def _optional_children(
        spec: Spec,
        limits: Mapping[str, float],
        deadbands: Mapping[str, float],
        severities: Mapping[str, int],
        max_time_shelved: float | None,
        setpoint_node: Any,
    ) -> list[str]:
        optional: list[str] = []
        if spec.has_confirm:
            optional += ["ConfirmedState", "Confirm"]
        if spec.has_shelving:
            optional += [
                "ShelvingState",
                "ShelvingState/TimedShelve2",
                "ShelvingState/OneShotShelve2",
                "ShelvingState/Unshelve2",
            ]
        if max_time_shelved is not None:
            optional.append("MaxTimeShelved")
        if spec.has_suppression:
            optional += ["SuppressedState", "OutOfServiceState"]
        optional += [f"{tier}Limit" for tier in limits]
        optional += [f"{tier}Deadband" for tier in deadbands]
        optional += [f"Severity{tier}" for tier in severities]
        if spec.non_exclusive:
            optional += [f"{tier}State" for tier in limits]
        return optional

    async def _parent_for(self, source: Node | None) -> Node:
        isession = self.iserver.isession
        if source is None:
            return Node(isession, ua.NodeId(ua.ObjectIds.ObjectsFolder))
        if await source.read_node_class() == ua.NodeClass.Object:
            return source
        parents = await source.get_referenced_nodes(
            refs=ua.ObjectIds.HierarchicalReferences, direction=ua.BrowseDirection.Inverse
        )
        return parents[0] if parents else Node(isession, ua.NodeId(ua.ObjectIds.ObjectsFolder))

    async def _template(self, type_id: ua.NodeId) -> Any:
        if type_id not in self._templates:
            template = await events.get_event_obj_from_type_node(Node(self.iserver.isession, type_id))
            template.add_property("NodeId", None, ua.VariantType.NodeId)
            for name in [name for name in template.data_types if _is_meta(name)]:
                del template.data_types[name]
                template.__dict__.pop(name, None)
            for name, vtype in OBJECT_CHILD_FIELDS.items():
                if name not in template.data_types and _wanted(name, type_id, self.aspace):
                    template.add_property(name, None, vtype)
            self._templates[type_id] = template
        return self._templates[type_id]

    async def _paths_of(self, node: Node) -> dict[str, ua.NodeId]:
        paths: dict[str, ua.NodeId] = {}

        async def walk(current: Node, prefix: str) -> None:
            for child in await current.get_children():
                name = (await child.read_browse_name()).Name
                path = f"{prefix}/{name}" if prefix else name
                paths[path] = child.nodeid
                await walk(child, path)

        await walk(node, "")
        return paths

    async def _link(self, condition: Condition, source: Node | None, notifier: Node | ua.NodeId | None) -> None:
        if source is None:
            return
        isession = self.iserver.isession
        refs = [
            ua.AddReferencesItem(
                SourceNodeId=source.nodeid,
                ReferenceTypeId=HAS_CONDITION,
                IsForward=True,
                TargetNodeId=condition.node.nodeid,
                TargetNodeClass=ua.NodeClass.Object,
            )
        ]
        if await source.read_node_class() == ua.NodeClass.Object:
            data = self.aspace.get(source.nodeid)
            has = data is not None and any(
                ref.NodeId == condition.node.nodeid
                and ref.IsForward
                and is_subtype(self.aspace, ref.ReferenceTypeId, HAS_COMPONENT)
                for ref in data.references
            )
            if not has:
                refs.append(
                    ua.AddReferencesItem(
                        SourceNodeId=source.nodeid,
                        ReferenceTypeId=HAS_COMPONENT,
                        IsForward=True,
                        TargetNodeId=condition.node.nodeid,
                        TargetNodeClass=ua.NodeClass.Object,
                    )
                )
        data = self.aspace.get(source.nodeid)
        is_event_source = data is not None and any(
            not ref.IsForward and is_subtype(self.aspace, ref.ReferenceTypeId, HAS_EVENT_SOURCE)
            for ref in data.references
        )
        if not is_event_source:
            holder = _nodeid(notifier) if notifier is not None else SERVER
            refs.append(
                ua.AddReferencesItem(
                    SourceNodeId=holder,
                    ReferenceTypeId=HAS_EVENT_SOURCE,
                    IsForward=True,
                    TargetNodeId=source.nodeid,
                    TargetNodeClass=await source.read_node_class(),
                )
            )
        for result in await isession.add_references(refs):
            if result.is_bad() and result.value != ua.StatusCodes.BadDuplicateReferenceNotAllowed:
                result.check()
        try:
            bits = await source.read_event_notifier()
        except ua.UaStatusCodeError:
            return
        if ua.EventNotifier.SubscribeToEvents not in bits:
            await source.set_event_notifier([*bits, ua.EventNotifier.SubscribeToEvents])

    def _follow(self, condition: Condition) -> None:
        async def changed() -> None:
            value = self.aspace.read_attribute_value(condition.input_node, ua.AttributeIds.Value)
            if value.Value is None or (value.StatusCode is not None and value.StatusCode.is_bad()):
                return
            try:
                setpoint = None
                if condition.spec.deviation and not condition.setpoint_node.is_null():
                    sp = self.aspace.read_attribute_value(condition.setpoint_node, ua.AttributeIds.Value)
                    setpoint = sp.Value.Value if sp.Value is not None else None
                await condition.update_value(value.Value.Value, setpoint)
            except ValueError:
                _logger.warning("Condition %s cannot follow its input node", condition.name)

        async def callback(handle: int, datavalue: ua.DataValue) -> None:
            self.spawn(changed())

        _status, handle = self.aspace.add_datachange_callback(condition.input_node, ua.AttributeIds.Value, callback)
        condition.callback_handles.append(handle)

    async def delete(self, condition: Condition) -> None:
        await condition.close()
        self.conditions.pop(condition.condition_id, None)
        for path, owner in list(self._shelving_owner.items()):
            if owner is condition:
                del self._shelving_owner[path]
        for handle in condition.callback_handles:
            self.aspace.delete_datachange_callback(handle)
        source = condition.source_id
        isession = self.iserver.isession
        if source is not None:
            await isession.delete_references(
                [
                    ua.DeleteReferencesItem(
                        SourceNodeId=source,
                        ReferenceTypeId=HAS_CONDITION,
                        IsForward=True,
                        TargetNodeId=condition.condition_id,
                        DeleteBidirectional=True,
                    )
                ]
            )
        await condition.node.delete(delete_references=True, recursive=True)

    def get(self, condition_id: ua.NodeId | Node) -> Condition | None:
        return self.conditions.get(_nodeid(condition_id))

    # ---- the Methods

    async def _bind_instance_methods(self, condition: Condition) -> None:
        handlers = {
            "Enable": self._enable,
            "Disable": self._disable,
            "AddComment": self._add_comment,
            "Acknowledge": self._acknowledge,
            "Confirm": self._confirm,
            "ShelvingState/TimedShelve": self._timed_shelve,
            "ShelvingState/TimedShelve2": self._timed_shelve2,
            "ShelvingState/OneShotShelve": self._one_shot_shelve,
            "ShelvingState/OneShotShelve2": self._one_shot_shelve2,
            "ShelvingState/Unshelve": self._unshelve,
            "ShelvingState/Unshelve2": self._unshelve2,
        }
        for path, handler in handlers.items():
            nodeid = condition._paths.get(path)
            if nodeid is not None:
                self.aspace.add_method_callback(nodeid, handler)

    def _condition_of(self, parent: ua.NodeId, *, shelving: bool = False) -> Condition:
        condition = self.conditions.get(parent)
        if condition is None and shelving:
            condition = self._shelving_owner.get(parent)
        if condition is None:
            raise ua.uaerrors.BadNodeIdInvalid()
        return condition

    async def _enable(self, parent: ua.NodeId) -> None:
        await self._condition_of(parent).enable()
        self._audit("Enable", parent)

    async def _disable(self, parent: ua.NodeId) -> None:
        await self._condition_of(parent).disable()
        self._audit("Disable", parent)

    async def _add_comment(self, parent: ua.NodeId, event_id: ua.Variant, comment: ua.Variant) -> None:
        await self._condition_of(parent).add_comment(_text(comment), _event_id(event_id))
        self._audit("AddComment", parent, _event_id(event_id), _text(comment))

    async def _acknowledge(self, parent: ua.NodeId, event_id: ua.Variant, comment: ua.Variant) -> None:
        await self._condition_of(parent).acknowledge(_event_id(event_id), _text(comment))
        self._audit("Acknowledge", parent, _event_id(event_id), _text(comment))

    async def _confirm(self, parent: ua.NodeId, event_id: ua.Variant, comment: ua.Variant) -> None:
        await self._condition_of(parent).confirm(_event_id(event_id), _text(comment))
        self._audit("Confirm", parent, _event_id(event_id), _text(comment))

    async def _timed_shelve(self, parent: ua.NodeId, time: ua.Variant) -> None:
        await self._condition_of(parent, shelving=True).shelve_timed(float(time.Value))
        self._audit("TimedShelve", parent)

    async def _timed_shelve2(self, parent: ua.NodeId, time: ua.Variant, comment: ua.Variant) -> None:
        await self._condition_of(parent, shelving=True).shelve_timed(float(time.Value), _text(comment))
        self._audit("TimedShelve2", parent, None, _text(comment))

    async def _one_shot_shelve(self, parent: ua.NodeId) -> None:
        await self._condition_of(parent, shelving=True).shelve_one_shot()
        self._audit("OneShotShelve", parent)

    async def _one_shot_shelve2(self, parent: ua.NodeId, comment: ua.Variant) -> None:
        await self._condition_of(parent, shelving=True).shelve_one_shot(_text(comment))
        self._audit("OneShotShelve2", parent, None, _text(comment))

    async def _unshelve(self, parent: ua.NodeId) -> None:
        await self._condition_of(parent, shelving=True).unshelve()
        self._audit("Unshelve", parent)

    async def _unshelve2(self, parent: ua.NodeId, comment: ua.Variant) -> None:
        await self._condition_of(parent, shelving=True).unshelve(_text(comment))
        self._audit("Unshelve2", parent, None, _text(comment))

    def _audit(self, method: str, parent: ua.NodeId, event_id: bytes | None = None, comment: Any = None) -> None:
        if self.audit_hook is None:
            return
        try:
            self.audit_hook(method, parent, event_id, comment)
        except Exception:
            _logger.exception("Audit hook failed for %s", method)

    # ---- refresh

    def _subscription_of(self, subscription_id: int) -> Any:
        service = self.iserver.subscription_service
        subscription = service.subscriptions.get(subscription_id)
        if subscription is None:
            raise ua.uaerrors.BadSubscriptionIdInvalid()
        session = current_call_session.get()
        if session is not None and session.session_id != subscription.session_id:
            raise ua.uaerrors.BadUserAccessDenied()
        return subscription

    async def _refresh(self, parent: ua.NodeId, subscription_id: ua.Variant) -> None:
        if parent != CONDITION_TYPE:
            raise ua.uaerrors.BadNodeIdInvalid()
        sid = int(subscription_id.Value)
        subscription = self._subscription_of(sid)
        items = subscription.monitored_item_srv.event_item_ids()
        if not items:
            raise ua.uaerrors.BadNothingToDo()
        await self._run_refresh(sid, items)

    async def _refresh2(self, parent: ua.NodeId, subscription_id: ua.Variant, item_id: ua.Variant) -> None:
        if parent != CONDITION_TYPE:
            raise ua.uaerrors.BadNodeIdInvalid()
        sid = int(subscription_id.Value)
        subscription = self._subscription_of(sid)
        mid = int(item_id.Value)
        if mid not in subscription.monitored_item_srv.event_item_ids():
            raise ua.uaerrors.BadMonitoredItemIdInvalid()
        await self._run_refresh(sid, [mid])

    async def _run_refresh(self, subscription_id: int, items: list[int]) -> None:
        if subscription_id in self._refreshing:
            raise ua.uaerrors.BadRefreshInProgress()
        self._refreshing.add(subscription_id)
        try:
            service = self.iserver.subscription_service
            sub = service.subscriptions[subscription_id]
            msrv = sub.monitored_item_srv
            start = self._refresh_event(ua.ObjectIds.RefreshStartEventType, "RefreshStart")
            end = self._refresh_event(ua.ObjectIds.RefreshEndEventType, "RefreshEnd")
            await service.deliver_to_subscription(subscription_id, start, items, bypass_where=True)
            for event in self.retained():
                notifiers = notifiers_of(self.aspace, event.emitting_node)
                for mid in items:
                    node = msrv.item_node(mid)
                    if node in notifiers:
                        await msrv.trigger_event(event, mid, notifiers=[node])
            await service.deliver_to_subscription(subscription_id, end, items, bypass_where=True)
        finally:
            self._refreshing.discard(subscription_id)

    def _refresh_event(self, type_id: int, text: str) -> Any:
        classes = {
            ua.ObjectIds.RefreshStartEventType: event_objects.RefreshStartEvent,
            ua.ObjectIds.RefreshEndEventType: event_objects.RefreshEndEvent,
            ua.ObjectIds.RefreshRequiredEventType: event_objects.RefreshRequiredEvent,
        }
        event: Any = classes[type_id](SERVER, text, 1)
        event.emitting_node = SERVER
        event.SourceName = "Server"
        event.Message = ua.LocalizedText(text)
        stamp_event(event)
        event.EventId = event.EventId.Value
        return event

    async def refresh_required(self, subscription_ids: list[int] | None = None) -> None:
        service = self.iserver.subscription_service
        for sid in subscription_ids if subscription_ids is not None else list(service.subscriptions):
            event = self._refresh_event(ua.ObjectIds.RefreshRequiredEventType, "RefreshRequired")
            event.Severity = 100
            await service.deliver_to_subscription(sid, event, None, bypass_where=True)


def _nodeid(value: Node | ua.NodeId | int) -> ua.NodeId:
    if isinstance(value, Node):
        return value.nodeid
    if isinstance(value, ua.NodeId):
        return value
    return ua.NodeId(value)


def source_node_ns(source: Node | None) -> int:
    return source.nodeid.NamespaceIndex if source is not None else 0


def _text(comment: ua.Variant) -> ua.LocalizedText | None:
    value = comment.Value
    return value if isinstance(value, ua.LocalizedText) else None


def _event_id(event_id: ua.Variant) -> bytes:
    value = event_id.Value
    return bytes(value) if value is not None else b""


def _wanted(name: str, type_id: ua.NodeId, aspace: Any) -> bool:
    if name.startswith("ShelvingState"):
        return is_subtype(aspace, type_id, ALARM_TYPE)
    return is_subtype(aspace, type_id, EXCLUSIVE_LIMIT)

"""A Condition instance: its state, its Events and the rules of OPC 10000-9."""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import logging
import secrets
from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.common.node import Node
from enginir_opcua.crypto.permission_rules import UserRole

from ..event_generator import stamp_event
from ..internal_session import current_call_session
from . import limits as limit_logic

if TYPE_CHECKING:
    from .manager import ConditionManager

_logger = logging.getLogger(__name__)

NULL_ID = ua.NodeId()
EVENT_IDS_KEPT = 64
MAX_BRANCHES = 32
MAX_SHELVING_MS = 24 * 3600 * 1000.0
DEFAULT_COMMENT_LENGTH = 1024
SHELVED_STATES = {
    "Unshelved": ua.ObjectIds.ShelvedStateMachineType_Unshelved,
    "TimedShelved": ua.ObjectIds.ShelvedStateMachineType_TimedShelved,
    "OneShotShelved": ua.ObjectIds.ShelvedStateMachineType_OneShotShelved,
}
LIMIT_STATES = {
    "HighHigh": ua.ObjectIds.ExclusiveLimitStateMachineType_HighHigh,
    "High": ua.ObjectIds.ExclusiveLimitStateMachineType_High,
    "Low": ua.ObjectIds.ExclusiveLimitStateMachineType_Low,
    "LowLow": ua.ObjectIds.ExclusiveLimitStateMachineType_LowLow,
}
TWO_STATE_NAMES = {
    "EnabledState": ("Enabled", "Disabled"),
    "AckedState": ("Acknowledged", "Unacknowledged"),
    "ConfirmedState": ("Confirmed", "Unconfirmed"),
    "ActiveState": ("Active", "Inactive"),
    "SuppressedState": ("Suppressed", "Unsuppressed"),
    "OutOfServiceState": ("Out of Service", "In Service"),
}
KEPT_WHILE_DISABLED = {
    "EventId",
    "EventType",
    "SourceNode",
    "SourceName",
    "Time",
    "ReceiveTime",
    "LocalTime",
    "Message",
    "Severity",
    "NodeId",
    "ConditionName",
    "ConditionClassId",
    "ConditionClassName",
    "BranchId",
    "Retain",
    "SupportsFilteredRetain",
    "EnabledState",
    "EnabledState/Id",
    "EnabledState/TransitionTime",
}
KEPT_ON_NODES = {"EventId", "EventType", "SourceNode", "SourceName", "Time", "EnabledState", "EnabledState/Id"}
OBJECT_CHILD_FIELDS: dict[str, ua.VariantType] = {
    "ShelvingState/CurrentState": ua.VariantType.LocalizedText,
    "ShelvingState/CurrentState/Id": ua.VariantType.NodeId,
    "ShelvingState/LastTransition": ua.VariantType.LocalizedText,
    "ShelvingState/LastTransition/TransitionTime": ua.VariantType.DateTime,
    "ShelvingState/UnshelveTime": ua.VariantType.Double,
    "LimitState/CurrentState": ua.VariantType.LocalizedText,
    "LimitState/CurrentState/Id": ua.VariantType.NodeId,
    "LimitState/LastTransition": ua.VariantType.LocalizedText,
    "LimitState/LastTransition/TransitionTime": ua.VariantType.DateTime,
}


@dataclasses.dataclass
class Spec:
    has_ack: bool = False
    has_active: bool = False
    has_confirm: bool = False
    has_shelving: bool = False
    has_suppression: bool = False
    exclusive: bool = False
    non_exclusive: bool = False
    deviation: bool = False
    off_normal: bool = False
    branches: bool = False
    comment_max_length: int = DEFAULT_COMMENT_LENGTH
    max_time_shelved: float | None = None


@dataclasses.dataclass(eq=False)
class Branch:
    branch_id: ua.NodeId
    acked: bool = True
    confirmed: bool = True
    active: bool = False
    limit: str | None = None
    tiers: dict[str, bool] = dataclasses.field(default_factory=dict)
    severity: int = 1
    last_severity: int = 0
    quality: ua.StatusCode = dataclasses.field(default_factory=ua.StatusCode)
    comment: ua.LocalizedText | None = None
    comment_time: datetime | None = None
    client_user_id: str = ""
    message: ua.LocalizedText = dataclasses.field(default_factory=ua.LocalizedText)
    retain: bool = False
    app_retain: bool = False
    times: dict[str, datetime] = dataclasses.field(default_factory=dict)
    last_transition: str | None = None
    severity_time: datetime | None = None
    quality_time: datetime | None = None
    event_ids: deque[bytes] = dataclasses.field(default_factory=lambda: deque(maxlen=EVENT_IDS_KEPT))
    state_key: tuple[Any, ...] = ()
    last_event_id: bytes | None = None
    last_event_time: datetime | None = None

    def pending(self, confirmable: bool) -> bool:
        return not self.acked or (confirmable and not self.confirmed)

    def key(self) -> tuple[Any, ...]:
        return (self.active, self.limit, tuple(sorted(self.tiers.items())), self.acked, self.confirmed)


def caller_name(manager: ConditionManager) -> str:
    session = current_call_session.get()
    if session is None or not session.external:
        return "server"
    user = session.user
    return user.name or (user.role.name if isinstance(user.role, UserRole) else str(user.role))


def comment_is_null(comment: ua.LocalizedText | None) -> bool:
    return comment is None or (not comment.Text and not comment.Locale)


class Condition:
    def __init__(
        self,
        manager: ConditionManager,
        node: Node,
        name: str,
        type_id: ua.NodeId,
        source_id: ua.NodeId | None,
        source_name: str | None,
        spec: Spec,
        template: Any,
        paths: dict[str, ua.NodeId],
    ) -> None:
        self.manager = manager
        self.node = node
        self.name = name
        self.type_id = type_id
        self.source_id = source_id
        self.source_name = source_name
        self.spec = spec
        self._template = template
        self._paths = paths
        self._mirrored: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self.enabled = True
        self.shelving = "Unshelved"
        self.shelve_deadline: float | None = None
        self.shelve_handle: asyncio.TimerHandle | None = None
        self.suppressed = False
        self.out_of_service = False
        self.condition_class = ua.NodeId(ua.ObjectIds.BaseConditionClassType)
        self.condition_class_name = ua.LocalizedText("BaseConditionClassType")
        self.limits: dict[str, float] = {}
        self.deadbands: dict[str, float] = {}
        self.severities: dict[str, int] = {}
        self.input_node: ua.NodeId = NULL_ID
        self.normal_value: Any = None
        self.normal_node: ua.NodeId = NULL_ID
        self.setpoint_node: ua.NodeId = NULL_ID
        self.last_value: float | None = None
        self.last_setpoint: float | None = None
        self.branch_counter = 0
        self.branch_map: dict[ua.NodeId, Branch] = {}
        now = datetime.now(UTC)
        self.trunk = Branch(NULL_ID, times={"Enabled": now})
        self.callback_handles: list[int] = []
        self._closing: list[Branch] = []

    # ---- reading the state

    @property
    def condition_id(self) -> ua.NodeId:
        return self.node.nodeid

    @property
    def retain(self) -> bool:
        return self.trunk.retain

    @property
    def acked(self) -> bool:
        return self.trunk.acked

    @property
    def confirmed(self) -> bool:
        return self.trunk.confirmed

    @property
    def active(self) -> bool:
        return self.trunk.active

    @property
    def severity(self) -> int:
        return self.trunk.severity

    @property
    def shelving_state(self) -> str:
        return self.shelving

    @property
    def branches(self) -> list[ua.NodeId]:
        return list(self.branch_map)

    def last_event_id(self, branch_id: ua.NodeId | None = None) -> bytes | None:
        branch = self.trunk if branch_id is None or branch_id.is_null() else self.branch_map.get(branch_id)
        return branch.last_event_id if branch is not None else None

    # ---- public operations

    async def enable(self) -> None:
        async with self._lock:
            if self.enabled:
                raise ua.uaerrors.BadConditionAlreadyEnabled()
            now = datetime.now(UTC)
            self.enabled = True
            self.trunk.times["Enabled"] = now
            self._evaluate_last_value(now)
            await self._publish([self.trunk], f"{self.name} enabled")

    async def disable(self) -> None:
        async with self._lock:
            if not self.enabled:
                raise ua.uaerrors.BadConditionAlreadyDisabled()
            now = datetime.now(UTC)
            was = [branch for branch in self._all_branches() if branch.retain]
            self.enabled = False
            self.trunk.times["Enabled"] = now
            self._cancel_shelve_timer()
            closed = list(self.branch_map.values())
            self.branch_map = {}
            for branch in [self.trunk, *closed]:
                branch.retain = False
            events = [(self.trunk, True)] + [(branch, True) for branch in closed if any(branch is w for w in was)]
            await self._emit(events, f"{self.name} disabled")
            await self._mirror(self.trunk)

    async def activate(self, severity: int | None = None, message: str | ua.LocalizedText | None = None) -> None:
        if not self.spec.has_ack:
            raise ua.uaerrors.BadInvalidState()
        async with self._lock:
            now = datetime.now(UTC)
            emits = self._set_alarm_state(now, True, self.trunk.limit, dict(self.trunk.tiers), severity)
            await self._publish(emits, message or f"{self.name} active")

    async def deactivate(self, message: str | ua.LocalizedText | None = None) -> None:
        if not self.spec.has_ack:
            raise ua.uaerrors.BadInvalidState()
        async with self._lock:
            now = datetime.now(UTC)
            emits = self._set_alarm_state(now, False, None, {k: False for k in self.trunk.tiers}, None)
            await self._publish(emits, message or f"{self.name} returned to normal")

    async def set_severity(self, severity: int) -> None:
        async with self._lock:
            self._check_severity(severity)
            if severity == self.trunk.severity:
                return
            now = datetime.now(UTC)
            self._change_severity(self.trunk, severity, now)
            await self._publish([self.trunk], "severity changed")

    async def set_quality(self, quality: ua.StatusCode) -> None:
        async with self._lock:
            if quality == self.trunk.quality:
                return
            self.trunk.quality = quality
            self.trunk.quality_time = datetime.now(UTC)
            await self._publish([self.trunk], "quality changed")

    async def set_retain(self, retain: bool) -> None:
        async with self._lock:
            if retain == self.trunk.app_retain:
                return
            self.trunk.app_retain = retain
            await self._publish([self.trunk], "retain changed")

    async def set_suppressed(self, flag: bool) -> None:
        await self._set_flag("suppressed", "Suppressed", flag)

    async def set_out_of_service(self, flag: bool) -> None:
        await self._set_flag("out_of_service", "OutOfService", flag)

    async def acknowledge(
        self, event_id: bytes | None = None, comment: str | ua.LocalizedText | None = None, *, user: str | None = None
    ) -> None:
        async with self._lock:
            self._need_enabled()
            branch = self._find_branch(event_id)
            if branch.acked:
                raise ua.uaerrors.BadConditionBranchAlreadyAcked()
            now = datetime.now(UTC)
            self._apply_comment(branch, comment, now, user, null_is_error=False)
            branch.acked = True
            branch.times["Acked"] = now
            if self.spec.has_confirm:
                branch.confirmed = False
                branch.times["Confirmed"] = now
            await self._publish_branch(branch, f"{self.name} acknowledged")

    async def confirm(
        self, event_id: bytes | None = None, comment: str | ua.LocalizedText | None = None, *, user: str | None = None
    ) -> None:
        async with self._lock:
            if not self.spec.has_confirm:
                raise ua.uaerrors.BadMethodInvalid()
            self._need_enabled()
            branch = self._find_branch(event_id)
            if branch.confirmed:
                raise ua.uaerrors.BadConditionBranchAlreadyConfirmed()
            now = datetime.now(UTC)
            self._apply_comment(branch, comment, now, user, null_is_error=False)
            branch.confirmed = True
            branch.times["Confirmed"] = now
            await self._publish_branch(branch, f"{self.name} confirmed")

    async def add_comment(
        self, comment: str | ua.LocalizedText, event_id: bytes | None = None, *, user: str | None = None
    ) -> None:
        async with self._lock:
            self._need_enabled()
            branch = self._find_branch(event_id)
            self._apply_comment(branch, comment, datetime.now(UTC), user, null_is_error=True)
            await self._publish([branch], "comment added", forced=[branch])

    async def update_value(self, value: Any, setpoint: float | None = None) -> None:
        async with self._lock:
            now = datetime.now(UTC)
            if self.spec.off_normal:
                self.last_value = value
                active = value != self._normal()
                emits = self._set_alarm_state(now, active, None, {}, None)
                await self._publish(emits, f"{self.name}: off normal" if active else f"{self.name} returned to normal")
                return
            number = self._as_number(value)
            if self.spec.deviation:
                if setpoint is None:
                    raise ValueError("A deviation alarm needs a setpoint")
                self.last_setpoint = self._as_number(setpoint)
            self.last_value = number
            if not self.enabled:
                return
            emits, text = self._evaluate(now)
            await self._publish(emits, text)

    async def set_limits(
        self,
        limits: Mapping[str, float] | None = None,
        deadbands: Mapping[str, float] | None = None,
        severities: Mapping[str, int] | None = None,
    ) -> None:
        async with self._lock:
            new_limits = {**self.limits, **(limits or {})}
            new_bands = {**self.deadbands, **(deadbands or {})}
            limit_logic.validate_limits(
                new_limits, new_bands, deviation=self.spec.deviation, exclusive=self.spec.exclusive
            )
            self.limits, self.deadbands = new_limits, new_bands
            self.severities = {**self.severities, **(severities or {})}
            if self.last_value is not None and self.enabled:
                emits, text = self._evaluate(datetime.now(UTC))
                await self._publish(emits, text)
            else:
                await self._mirror(self.trunk)

    async def shelve_timed(
        self, milliseconds: float, comment: str | ua.LocalizedText | None = None, *, user: str | None = None
    ) -> None:
        async with self._lock:
            self._need_shelving()
            limit = min(self.spec.max_time_shelved or MAX_SHELVING_MS, MAX_SHELVING_MS)
            if not 0 < milliseconds <= limit:
                raise ua.uaerrors.BadShelvingTimeOutOfRange()
            if self.shelving == "TimedShelved":
                raise ua.uaerrors.BadConditionAlreadyShelved()
            await self._shelve("TimedShelved", milliseconds, comment, user)

    async def shelve_one_shot(self, comment: str | ua.LocalizedText | None = None, *, user: str | None = None) -> None:
        async with self._lock:
            self._need_shelving()
            if self.shelving == "OneShotShelved":
                raise ua.uaerrors.BadConditionAlreadyShelved()
            await self._shelve("OneShotShelved", self.spec.max_time_shelved, comment, user)

    async def unshelve(self, comment: str | ua.LocalizedText | None = None, *, user: str | None = None) -> None:
        async with self._lock:
            self._need_shelving()
            if self.shelving == "Unshelved":
                raise ua.uaerrors.BadConditionNotShelved()
            await self._unshelve(comment, user)

    # ---- state rules

    def _need_enabled(self) -> None:
        if not self.enabled:
            raise ua.uaerrors.BadConditionDisabled()

    def _need_shelving(self) -> None:
        if not self.spec.has_shelving:
            raise ua.uaerrors.BadMethodInvalid()
        self._need_enabled()

    def _all_branches(self) -> list[Branch]:
        return [self.trunk, *self.branch_map.values()]

    def _find_branch(self, event_id: bytes | None) -> Branch:
        if event_id is None:
            return self.trunk
        for branch in self._all_branches():
            if event_id in branch.event_ids:
                return branch
        raise ua.uaerrors.BadEventIdUnknown()

    def _check_severity(self, severity: int) -> None:
        if not 1 <= severity <= 1000:
            raise ValueError("Severity must be between 1 and 1000")

    def _change_severity(self, branch: Branch, severity: int, now: datetime) -> None:
        if severity != branch.severity:
            branch.last_severity = branch.severity
            branch.severity = severity
            branch.severity_time = now

    def _apply_comment(
        self,
        branch: Branch,
        comment: str | ua.LocalizedText | None,
        now: datetime,
        user: str | None,
        *,
        null_is_error: bool,
    ) -> None:
        if isinstance(comment, str):
            comment = ua.LocalizedText(comment)
        if comment_is_null(comment):
            if null_is_error:
                raise ua.uaerrors.BadInvalidArgument()
            return
        assert comment is not None
        if len(comment.Text or "") > self.spec.comment_max_length:
            raise ua.uaerrors.BadInvalidArgument()
        branch.comment = comment
        branch.comment_time = now
        branch.client_user_id = user if user is not None else caller_name(self.manager)

    def _retain_of(self, branch: Branch) -> bool:
        if not self.enabled:
            return False
        if branch.branch_id != NULL_ID:
            return branch.pending(self.spec.has_confirm)
        if self.spec.has_ack:
            alarm = self.spec.has_active and branch.active
            return alarm or branch.pending(self.spec.has_confirm) or bool(self.branch_map) or branch.app_retain
        return branch.app_retain

    async def _set_flag(self, attribute: str, state: str, flag: bool) -> None:
        async with self._lock:
            if getattr(self, attribute) == flag:
                return
            setattr(self, attribute, flag)
            self.trunk.times[state] = datetime.now(UTC)
            await self._publish([self.trunk], f"{self.name} {state}")

    def _normal(self) -> Any:
        if not self.normal_node.is_null():
            value = self.manager.aspace.read_attribute_value(self.normal_node, ua.AttributeIds.Value)
            return value.Value.Value if value.Value is not None else None
        return self.normal_value

    @staticmethod
    def _as_number(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError("The value of a limit alarm must be a number")
        return float(value)

    def _evaluate_last_value(self, now: datetime) -> None:
        if self.last_value is None:
            return
        if self.spec.off_normal:
            self._set_alarm_state(now, self.last_value != self._normal(), None, {}, None)
        else:
            self._evaluate(now)

    def _evaluate(self, now: datetime) -> tuple[list[Branch], str]:
        assert self.last_value is not None
        value = self.last_value - (self.last_setpoint or 0.0) if self.spec.deviation else self.last_value
        trunk = self.trunk
        if self.spec.exclusive:
            tier = limit_logic.exclusive_tier(value, self.limits, self.deadbands, trunk.limit)
            severity = self.severities.get(tier, None) if tier else None
            emits = self._set_alarm_state(now, tier is not None, tier, {}, severity)
            text = f"{self.name}: {tier} limit exceeded" if tier else f"{self.name} returned to normal"
            return emits, text
        states = limit_logic.non_exclusive_states(value, self.limits, self.deadbands, trunk.tiers)
        on = [tier for tier, flag in states.items() if flag]
        severity = limit_logic.tier_severity(on, self.severities, trunk.severity) if on else None
        emits = self._set_alarm_state(now, bool(on), None, states, severity)
        text = f"{self.name}: {', '.join(on)} limit exceeded" if on else f"{self.name} returned to normal"
        return emits, text

    def _set_alarm_state(
        self,
        now: datetime,
        active: bool,
        limit: str | None,
        tiers: dict[str, bool],
        severity: int | None,
    ) -> list[Branch]:
        trunk = self.trunk
        if not self.enabled:
            return []
        sub_change = active and trunk.active and (limit != trunk.limit or tiers != trunk.tiers)
        severity_change = severity is not None and severity != trunk.severity
        if active == trunk.active and not sub_change:
            if severity_change:
                assert severity is not None
                self._change_severity(trunk, severity, now)
                return [trunk]
            return []
        emits: list[Branch] = []
        if self.spec.branches and trunk.pending(self.spec.has_confirm):
            emits.append(self._open_branch(now))
            trunk.acked = True
            trunk.confirmed = True
        previous = trunk.limit
        if active != trunk.active:
            trunk.times["Active"] = now
        trunk.active = active
        trunk.limit = limit
        trunk.tiers = dict(tiers)
        trunk.last_transition = f"{previous}To{limit}" if previous and limit and previous != limit else None
        trunk.times["Effective"] = now
        if active:
            trunk.acked = False
            trunk.confirmed = True
            trunk.times["Acked"] = now
        if severity is not None:
            self._change_severity(trunk, severity, now)
        emits.append(trunk)
        if not active and self.shelving == "OneShotShelved":
            self._clear_shelving()
        return emits

    def _open_branch(self, now: datetime) -> Branch:
        if len(self.branch_map) >= MAX_BRANCHES:
            oldest = next(iter(self.branch_map))
            _logger.warning("Condition %s has %s branches; closing the oldest", self.name, MAX_BRANCHES)
            self._closing.append(self.branch_map.pop(oldest))
        self.branch_counter += 1
        branch = dataclasses.replace(
            self.trunk,
            tiers=dict(self.trunk.tiers),
            times=dict(self.trunk.times),
            event_ids=deque(self.trunk.event_ids, maxlen=EVENT_IDS_KEPT),
        )
        branch.branch_id = ua.NodeId(self.branch_counter, self.condition_id.NamespaceIndex)
        branch.retain = True
        self.branch_map[branch.branch_id] = branch
        return branch

    # ---- shelving

    async def _shelve(self, state: str, milliseconds: float | None, comment: Any, user: str | None) -> None:
        self._cancel_shelve_timer()
        now = datetime.now(UTC)
        self.shelving = state
        self.trunk.times["Shelving"] = now
        self.shelve_deadline = None
        if milliseconds is not None:
            loop = asyncio.get_running_loop()
            self.shelve_deadline = loop.time() + milliseconds / 1000.0
            self.shelve_handle = loop.call_later(
                milliseconds / 1000.0, lambda: self.manager.spawn(self._expire_shelving())
            )
        self._apply_comment(self.trunk, comment, now, user, null_is_error=False)
        await self._publish([self.trunk], f"{self.name} {state}")

    async def _unshelve(self, comment: Any, user: str | None) -> None:
        now = datetime.now(UTC)
        self._clear_shelving()
        self._apply_comment(self.trunk, comment, now, user, null_is_error=False)
        await self._publish([self.trunk], f"{self.name} unshelved")

    def _clear_shelving(self) -> None:
        self._cancel_shelve_timer()
        self.shelving = "Unshelved"
        self.trunk.times["Shelving"] = datetime.now(UTC)

    def _cancel_shelve_timer(self) -> None:
        if self.shelve_handle is not None:
            self.shelve_handle.cancel()
            self.shelve_handle = None
        self.shelve_deadline = None

    async def _expire_shelving(self) -> None:
        async with self._lock:
            if self.shelving == "Unshelved" or not self.enabled:
                return
            self.shelve_handle = None
            await self._unshelve(None, None)

    def _remaining_shelve_ms(self) -> float:
        if self.shelve_deadline is None:
            return 0.0 if self.shelving == "Unshelved" else (self.spec.max_time_shelved or MAX_SHELVING_MS)
        return max(0.0, (self.shelve_deadline - asyncio.get_running_loop().time()) * 1000.0)

    # ---- events

    async def _publish_branch(self, branch: Branch, message: str) -> None:
        await self._publish([branch], message)

    async def _publish(
        self,
        branches: list[Branch],
        message: str | ua.LocalizedText,
        forced: list[Branch] | None = None,
    ) -> None:
        closures, self._closing = self._closing, []
        order: list[Branch] = []
        for branch in [*branches, *closures]:
            if not any(branch is other for other in order):
                order.append(branch)
        if not any(self.trunk is other for other in order) and self._retain_of(self.trunk) != self.trunk.retain:
            order.append(self.trunk)
        events: list[tuple[Branch, bool]] = []
        for branch in order:
            previous = branch.retain
            branch.retain = False if any(branch is other for other in closures) else self._retain_of(branch)
            force = any(branch is other for other in forced or [])
            if branch.retain or previous or force:
                events.append((branch, force))
        for branch in list(self.branch_map.values()):
            if not branch.retain:
                del self.branch_map[branch.branch_id]
        await self._emit(events, message)
        await self._mirror(self.trunk)

    async def _emit(self, events: list[tuple[Branch, bool]], message: str | ua.LocalizedText) -> None:
        text = message if isinstance(message, ua.LocalizedText) else ua.LocalizedText(message)
        for branch, _force in events:
            branch.message = text
            event = self._build(branch)
            stamp_event(event)
            branch.last_event_id = event.EventId.Value
            branch.last_event_time = event.Time
            key = branch.key()
            if key != branch.state_key:
                branch.event_ids.clear()
                branch.state_key = key
            branch.event_ids.append(branch.last_event_id)
            event.EventId = event.EventId.Value
            await self.manager.deliver(event)

    def retained_events(self) -> list[Any]:
        found = []
        for branch in self._all_branches():
            if branch.retain and branch.last_event_id is not None:
                found.append(self.build_replay(branch))
        return found

    def build_replay(self, branch: Branch) -> Any:
        event = self._build(branch)
        event.EventId = branch.last_event_id
        event.Time = branch.last_event_time
        event.ReceiveTime = datetime.now(UTC)
        return event

    def _two_state(
        self, event: Any, name: str, value: bool, since: datetime | None, display: str | None = None
    ) -> None:
        if f"{name}/Id" not in event.data_types:
            return
        true_text, false_text = TWO_STATE_NAMES.get(name, (f"{name[:-5]} active", f"{name[:-5]} inactive"))
        setattr(event, name, ua.LocalizedText(true_text if value else false_text))
        setattr(event, f"{name}/Id", value)
        for suffix in ("TransitionTime", "EffectiveTransitionTime"):
            if f"{name}/{suffix}" in event.data_types:
                setattr(event, f"{name}/{suffix}", since)
        if display is not None and f"{name}/EffectiveDisplayName" in event.data_types:
            setattr(event, f"{name}/EffectiveDisplayName", ua.LocalizedText(display))

    def _build(self, branch: Branch) -> Any:
        event = copy.copy(self._template)
        times = branch.times
        spec = self.spec
        event.emitting_node = self.source_id if self.source_id is not None else ua.NodeId(ua.ObjectIds.Server)
        event.EventType = self.type_id
        event.SourceNode = self.source_id if self.source_id is not None else NULL_ID
        event.SourceName = self.source_name
        event.NodeId = self.condition_id
        event.ConditionName = self.name
        event.ConditionClassId = self.condition_class
        event.ConditionClassName = self.condition_class_name
        event.BranchId = branch.branch_id
        event.Retain = branch.retain
        event.SupportsFilteredRetain = False
        event.Message = branch.message
        event.Severity = branch.severity
        event.LastSeverity = branch.last_severity
        event.Quality = branch.quality
        event.Comment = branch.comment
        event.ClientUserId = branch.client_user_id
        for name, when in (
            ("LastSeverity/SourceTimestamp", branch.severity_time),
            ("Quality/SourceTimestamp", branch.quality_time),
            ("Comment/SourceTimestamp", branch.comment_time),
        ):
            if name in event.data_types:
                setattr(event, name, when)
        self._two_state(event, "EnabledState", self.enabled, times.get("Enabled"))
        if spec.has_ack:
            self._two_state(event, "AckedState", branch.acked, times.get("Acked"))
        if spec.has_confirm:
            self._two_state(event, "ConfirmedState", branch.confirmed, times.get("Confirmed"))
        if spec.has_active:
            display = f"Active/{branch.limit}" if branch.active and branch.limit else None
            self._two_state(
                event,
                "ActiveState",
                branch.active,
                times.get("Active"),
                display or ("Active" if branch.active else "Inactive"),
            )
            if "ActiveState/EffectiveTransitionTime" in event.data_types:
                setattr(event, "ActiveState/EffectiveTransitionTime", times.get("Effective", times.get("Active")))
            event.InputNode = self.input_node
            event.SuppressedOrShelved = self.suppressed or self.out_of_service or self.shelving != "Unshelved"
            if spec.has_suppression:
                self._two_state(event, "SuppressedState", self.suppressed, times.get("Suppressed"))
                self._two_state(event, "OutOfServiceState", self.out_of_service, times.get("OutOfService"))
            if spec.max_time_shelved is not None:
                event.MaxTimeShelved = spec.max_time_shelved
        self._limit_fields(event, branch)
        if spec.has_shelving:
            self._shelving_fields(event)
        if spec.off_normal:
            event.NormalState = self.normal_node
        if spec.deviation:
            event.SetpointNode = self.setpoint_node
        if not self.enabled:
            for name in list(event.data_types):
                if name not in KEPT_WHILE_DISABLED:
                    setattr(event, name, None)
        return event

    def _limit_fields(self, event: Any, branch: Branch) -> None:
        for tier, value in self.limits.items():
            setattr(event, f"{tier}Limit", value)
        for tier, value in self.deadbands.items():
            setattr(event, f"{tier}Deadband", value)
        for tier, value in self.severities.items():
            setattr(event, f"Severity{tier}", value)
        if self.spec.exclusive:
            state = branch.limit if branch.active else None
            transition = branch.last_transition if state else None
            setattr(event, "LimitState/CurrentState", ua.LocalizedText(state) if state else None)
            setattr(event, "LimitState/CurrentState/Id", ua.NodeId(LIMIT_STATES[state]) if state else None)
            setattr(event, "LimitState/LastTransition", ua.LocalizedText(transition) if transition else None)
            setattr(
                event, "LimitState/LastTransition/TransitionTime", branch.times.get("Effective") if transition else None
            )
        elif self.spec.non_exclusive:
            for tier in limit_logic.TIERS:
                if tier in self.limits:
                    self._two_state(event, f"{tier}State", branch.tiers.get(tier, False), branch.times.get("Effective"))

    def _shelving_fields(self, event: Any) -> None:
        state = self.shelving
        setattr(event, "ShelvingState/CurrentState", ua.LocalizedText(state))
        setattr(event, "ShelvingState/CurrentState/Id", ua.NodeId(SHELVED_STATES[state]))
        setattr(event, "ShelvingState/LastTransition", None)
        setattr(event, "ShelvingState/LastTransition/TransitionTime", self.trunk.times.get("Shelving"))
        setattr(event, "ShelvingState/UnshelveTime", self._remaining_shelve_ms())

    # ---- the address space mirror

    async def _mirror(self, branch: Branch) -> None:
        event = self._build(branch)
        status = ua.StatusCode(ua.StatusCodes.BadConditionDisabled)
        for name, nodeid in self._paths.items():
            if name not in event.data_types:
                continue
            value = getattr(event, name, None)
            keep = self.enabled or name in KEPT_ON_NODES
            marker = (keep, repr(value))
            if self._mirrored.get(name) == marker:
                continue
            self._mirrored[name] = marker
            try:
                if keep:
                    datavalue = ua.DataValue(ua.Variant(value, event.data_types[name]))
                else:
                    datavalue = ua.DataValue(StatusCode=status)
                await self.manager.aspace.write_attribute(nodeid, ua.AttributeIds.Value, datavalue, trusted=True)
            except Exception:
                _logger.debug("Could not mirror %s of %s", name, self.name, exc_info=True)

    async def close(self) -> None:
        async with self._lock:
            self._cancel_shelve_timer()
            events = [(branch, True) for branch in self._all_branches() if branch.retain]
            for branch in self._all_branches():
                branch.retain = False
            self.branch_map = {}
            if events:
                await self._emit(events, f"{self.name} deleted")


def new_event_id() -> bytes:
    return secrets.token_bytes(16)

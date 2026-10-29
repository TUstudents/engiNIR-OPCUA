"""
Server diagnostics (OPC 10000-5 v1.05, 6.3.3 to 6.3.5, 7.8 to 7.16 and 12.8 to 12.15).

The counters run all the time; the nodes below Server/ServerDiagnostics show them. The Session and Subscription
detail (the Object of each Session) exists only while EnabledFlag is TRUE.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua

from ..crypto.permission_rules import ROLE_RANK, UserRole
from .diagnostics_counters import UINT32_MASK, SubscriptionCounters
from .internal_session import SESSION_ID_NAMESPACE, Session, current_call_session
from .model_change import suppress_model_change

if TYPE_CHECKING:
    from .internal_server import InternalServer
    from .internal_subscription import InternalSubscription

_logger = logging.getLogger(__name__)

DIAGNOSTICS_NAMESPACE = SESSION_ID_NAMESPACE
USER_ID_HISTORY_SIZE = 10
SECURITY_STATUS_NAMES = (
    "BadSecurityChecksFailed",
    "BadSecurityModeInsufficient",
    "BadSecurityPolicyRejected",
    "BadUserAccessDenied",
    "BadIdentityTokenInvalid",
    "BadIdentityTokenRejected",
    "BadApplicationSignatureInvalid",
    "BadUserSignatureInvalid",
    "BadCertificateInvalid",
    "BadCertificateTimeInvalid",
    "BadCertificateIssuerTimeInvalid",
    "BadCertificateHostNameInvalid",
    "BadCertificateUriInvalid",
    "BadCertificateUseNotAllowed",
    "BadCertificateIssuerUseNotAllowed",
    "BadCertificateUntrusted",
    "BadCertificateRevocationUnknown",
    "BadCertificateIssuerRevocationUnknown",
    "BadCertificateRevoked",
    "BadCertificateIssuerRevoked",
    "BadCertificatePolicyCheckFailed",
    "BadSecurityPolicyRejected",
)
SECURITY_STATUSES = frozenset(
    getattr(ua.StatusCodes, name) for name in SECURITY_STATUS_NAMES if hasattr(ua.StatusCodes, name)
)
SESSION_FIELD_OF_SERVICE = {
    f.name[: -len("Count")]: f.name
    for f in fields(ua.SessionDiagnosticsDataType)
    if "ServiceCounterDataType" in str(f.type) and f.name not in ("TotalRequestCount",)
}
AUTHENTICATION_MECHANISM = (
    (ua.AnonymousIdentityToken, "Anonymous"),
    (ua.UserNameIdentityToken, "UserName"),
    (ua.X509IdentityToken, "Certificate"),
    (ua.IssuedIdentityToken, "IssuedToken"),
)


def _u32(value: int) -> int:
    return value & UINT32_MASK


@dataclass
class ServerCounters:
    cumulated_sessions: int = 0
    security_rejected_sessions: int = 0
    rejected_sessions: int = 0
    session_timeouts: int = 0
    session_aborts: int = 0
    cumulated_subscriptions: int = 0
    security_rejected_requests: int = 0
    rejected_requests: int = 0


@dataclass
class SessionStats:
    connected_at: datetime
    client_description: ua.ApplicationDescription
    server_uri: str
    endpoint_url: str
    locale_ids: list[str] = field(default_factory=list)
    user_history: list[str] = field(default_factory=list)
    authentication_mechanism: str = ""
    total: int = 0
    unauthorized: int = 0
    services: dict[str, list[int]] = field(default_factory=dict)


def _is_security(status: int) -> bool:
    return (status & 0xFFFF0000) in {code & 0xFFFF0000 for code in SECURITY_STATUSES}


class DiagnosticsCollector:
    """Owned by the internal server; the hooks of the session manager, dispatcher and subscriptions call it."""

    def __init__(self, iserver: InternalServer) -> None:
        self.iserver = iserver
        self._enabled = False
        self._installed = False
        self.counters = ServerCounters()
        self.sessions: dict[ua.NodeId, SessionStats] = {}
        self._objects: dict[ua.NodeId, list[ua.NodeId]] = {}
        self._tasks: set[asyncio.Task[Any]] = set()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, enable: bool) -> None:
        if enable == self._enabled:
            return
        self._enabled = enable
        if not self._installed:
            return
        if enable:
            self._reset()
            for session in list(self.iserver.session_manager.sessions.values()):
                self._create_session_nodes(session)
        else:
            for session_id in list(self._objects):
                self._delete_session_nodes(session_id)

    def _reset(self) -> None:
        manager = self.iserver.session_manager
        self.counters = ServerCounters(
            cumulated_sessions=len(manager.sessions),
            cumulated_subscriptions=len(self.iserver.subscription_service.subscriptions),
        )
        for stats in self.sessions.values():
            stats.total = stats.unauthorized = 0
            stats.services.clear()
        for sub in self.iserver.subscription_service.subscriptions.values():
            sub.counters = SubscriptionCounters()

    def session_object_names(self) -> list[str]:
        manager = self.iserver.session_manager
        return [session.name for session_id in self._objects if (session := manager.session_by_id(session_id))]

    def _stats(self, session: Session) -> SessionStats | None:
        return self.sessions.get(session.id)

    def session_created(self, session: Session, params: ua.CreateSessionParameters) -> None:
        self.counters.cumulated_sessions = _u32(self.counters.cumulated_sessions + 1)
        self.sessions[session.id] = SessionStats(
            connected_at=datetime.now(UTC),
            client_description=params.ClientDescription,
            server_uri=params.ServerUri or self.iserver_application_uri(),
            endpoint_url=params.EndpointUrl or "",
        )
        if self._enabled:
            self._create_session_nodes(session)

    def iserver_application_uri(self) -> str:
        endpoints = self.iserver.endpoints
        return endpoints[0].Server.ApplicationUri if endpoints else ""

    def session_activated(self, session: Session, params: ua.ActivateSessionParameters) -> None:
        stats = self._stats(session)
        if stats is None:
            return
        stats.locale_ids = list(params.LocaleIds or [])
        user = session.user
        name = user.name or user.id or ""
        stats.user_history.append(name)
        del stats.user_history[:-USER_ID_HISTORY_SIZE]
        token = params.UserIdentityToken
        stats.authentication_mechanism = next(
            (label for cls, label in AUTHENTICATION_MECHANISM if isinstance(token, cls)), "Anonymous"
        )

    def session_ended(self, session: Session, reason: str) -> None:
        if reason == "timeout":
            self.counters.session_timeouts = _u32(self.counters.session_timeouts + 1)
        elif reason == "abort":
            self.counters.session_aborts = _u32(self.counters.session_aborts + 1)

    def session_forgotten(self, session: Session) -> None:
        self.sessions.pop(session.id, None)
        self._delete_session_nodes(session.id)

    def channel_rejected(self, status: int) -> None:
        if _is_security(status):
            self.counters.security_rejected_requests = _u32(self.counters.security_rejected_requests + 1)
            self.counters.rejected_requests = _u32(self.counters.rejected_requests + 1)

    def request_done(self, session: Session | None, service: str | None, status: int) -> None:
        stats = self._stats(session) if session is not None else None
        bad = status != ua.StatusCodes.Good
        if stats is not None:
            stats.total += 1
            if bad and status == ua.StatusCodes.BadUserAccessDenied:
                stats.unauthorized += 1
            if service is not None:
                counter = stats.services.setdefault(service, [0, 0])
                counter[0] += 1
                counter[1] += 1 if bad else 0
        if not bad:
            return
        self.counters.rejected_requests = _u32(self.counters.rejected_requests + 1)
        security = _is_security(status)
        if security:
            self.counters.security_rejected_requests = _u32(self.counters.security_rejected_requests + 1)
        if service in ("CreateSession", "ActivateSession"):
            self.counters.rejected_sessions = _u32(self.counters.rejected_sessions + 1)
            if security:
                self.counters.security_rejected_sessions = _u32(self.counters.security_rejected_sessions + 1)

    def subscription_created(self) -> None:
        self.counters.cumulated_subscriptions = _u32(self.counters.cumulated_subscriptions + 1)

    def summary(self) -> ua.ServerDiagnosticsSummaryDataType:
        counters = self.counters
        subscriptions = self.iserver.subscription_service.subscriptions
        views = sum(
            1 for node_id in self.iserver.aspace.keys() if node_id.NamespaceIndex != 0 and self._is_view(node_id)
        )
        return ua.ServerDiagnosticsSummaryDataType(
            ServerViewCount=views,
            CurrentSessionCount=len(self.iserver.session_manager.sessions),
            CumulatedSessionCount=counters.cumulated_sessions,
            SecurityRejectedSessionCount=counters.security_rejected_sessions,
            RejectedSessionCount=counters.rejected_sessions,
            SessionTimeoutCount=counters.session_timeouts,
            SessionAbortCount=counters.session_aborts,
            CurrentSubscriptionCount=len(subscriptions),
            CumulatedSubscriptionCount=counters.cumulated_subscriptions,
            PublishingIntervalCount=len({sub.data.RevisedPublishingInterval for sub in subscriptions.values()}),
            SecurityRejectedRequestsCount=counters.security_rejected_requests,
            RejectedRequestsCount=counters.rejected_requests,
        )

    def _is_view(self, node_id: ua.NodeId) -> bool:
        node = self.iserver.aspace.get(node_id)
        return node is not None and self.iserver.aspace.node_class_of(node) == ua.NodeClass.View

    def session_diagnostics(self) -> list[ua.SessionDiagnosticsDataType]:
        if not self._enabled:
            return []
        manager = self.iserver.session_manager
        result = [
            self._session_structure(session)
            for session in sorted(manager.sessions.values(), key=lambda s: s.created_at)
            if session.id in self.sessions
        ]
        return result

    def _session_structure(self, session: Session) -> ua.SessionDiagnosticsDataType:
        stats = self.sessions[session.id]
        subscriptions = [
            s for s in self.iserver.subscription_service.subscriptions.values() if s.session_id == session.id
        ]
        channel = session.bound_channel
        limits = getattr(channel, "_limits", None)
        structure = ua.SessionDiagnosticsDataType(
            SessionId=session.id,
            SessionName=session.name,
            ClientDescription=stats.client_description,
            ServerUri=stats.server_uri,
            EndpointUrl=stats.endpoint_url,
            LocaleIds=list(stats.locale_ids),
            ActualSessionTimeout=session.revised_timeout_ms,
            MaxResponseMessageSize=getattr(limits, "send_max_message_size", 0) or 0,
            ClientConnectionTime=stats.connected_at,
            ClientLastContactTime=datetime.now(UTC) - timedelta(seconds=session.idle_seconds(time.monotonic())),
            CurrentSubscriptionsCount=len(subscriptions),
            CurrentMonitoredItemsCount=sum(s.monitored_item_srv.item_count() for s in subscriptions),
            CurrentPublishRequestsInQueue=len(session.publish_queue),
            TotalRequestCount=ua.ServiceCounterDataType(_u32(stats.total), self._errors(stats)),
            UnauthorizedRequestCount=_u32(stats.unauthorized),
        )
        for service, name in SESSION_FIELD_OF_SERVICE.items():
            counter = stats.services.get(service)
            setattr(
                structure,
                name,
                ua.ServiceCounterDataType(_u32(counter[0]), _u32(counter[1]))
                if counter
                else ua.ServiceCounterDataType(),
            )
        return structure

    @staticmethod
    def _errors(stats: SessionStats) -> int:
        return _u32(sum(counter[1] for counter in stats.services.values()))

    def security_diagnostics(self, session: Session) -> ua.SessionSecurityDiagnosticsDataType:
        stats = self.sessions.get(session.id)
        history = list(stats.user_history) if stats else []
        return ua.SessionSecurityDiagnosticsDataType(
            SessionId=session.id,
            ClientUserIdOfSession=history[0] if history else "",
            ClientUserIdHistory=history,
            AuthenticationMechanism=stats.authentication_mechanism if stats else "",
            Encoding="UA Binary",
            TransportProtocol="opc.tcp",
            SecurityMode=session.channel_security.mode,
            SecurityPolicyUri=session.channel_security.policy_uri,
            ClientCertificate=session.client_certificate,
        )

    def subscription_diagnostics(self, session_id: ua.NodeId | None = None) -> list[ua.SubscriptionDiagnosticsDataType]:
        if not self._enabled:
            return []
        result = []
        for sub_id in sorted(self.iserver.subscription_service.subscriptions):
            sub = self.iserver.subscription_service.subscriptions[sub_id]
            if session_id is None or sub.session_id == session_id:
                result.append(self._subscription_structure(sub))
        return result

    def _subscription_structure(self, sub: InternalSubscription) -> ua.SubscriptionDiagnosticsDataType:
        c = sub.counters
        items = sub.monitored_item_srv
        return ua.SubscriptionDiagnosticsDataType(
            SessionId=sub.session_id,
            SubscriptionId=sub.data.SubscriptionId,
            Priority=sub.priority,
            PublishingInterval=sub.data.RevisedPublishingInterval,
            MaxKeepAliveCount=sub.data.RevisedMaxKeepAliveCount,
            MaxLifetimeCount=sub.data.RevisedLifetimeCount,
            MaxNotificationsPerPublish=sub.max_notifications_per_publish,
            PublishingEnabled=sub._publishing_enabled,
            ModifyCount=_u32(c.modify_count),
            EnableCount=_u32(c.enable_count),
            DisableCount=_u32(c.disable_count),
            RepublishRequestCount=_u32(c.republish_request_count),
            RepublishMessageRequestCount=_u32(c.republish_request_count),
            RepublishMessageCount=_u32(c.republish_message_count),
            TransferRequestCount=_u32(c.transfer_request_count),
            TransferredToAltClientCount=_u32(c.transferred_to_alt_client_count),
            TransferredToSameClientCount=_u32(c.transferred_to_same_client_count),
            PublishRequestCount=_u32(c.publish_request_count),
            DataChangeNotificationsCount=_u32(c.data_change_notifications_count),
            EventNotificationsCount=_u32(c.event_notifications_count),
            NotificationsCount=_u32(c.data_change_notifications_count + c.event_notifications_count),
            LatePublishRequestCount=_u32(c.late_publish_request_count),
            CurrentKeepAliveCount=_u32(c.keep_alive_entered_count),
            CurrentLifetimeCount=max(sub._lifetime_counter, 0),
            UnacknowledgedMessageCount=sub.unacknowledged_count,
            DiscardedMessageCount=_u32(c.discarded_message_count),
            MonitoredItemCount=items.item_count(),
            DisabledMonitoredItemCount=items.disabled_count(),
            MonitoringQueueOverflowCount=_u32(c.monitoring_queue_overflow_count),
            NextSequenceNumber=sub.next_sequence_number(),
            EventQueueOverflowCount=_u32(c.event_queue_overflow_count),
        )

    def may_read_security(self, owner: ua.NodeId | None) -> bool:
        reader = current_call_session.get()
        if reader is None:
            return True
        session = self.iserver.session_manager.session_by_id(reader.session_id)
        if session is None or session.channel_security.mode != ua.MessageSecurityMode.SignAndEncrypt:
            return False
        if ROLE_RANK.get(reader.user.role, -1) >= ROLE_RANK[UserRole.SecurityAdmin]:
            return True
        return owner is not None and owner == reader.session_id

    def may_switch(self) -> bool:
        reader = current_call_session.get()
        return reader is None or ROLE_RANK.get(reader.user.role, -1) >= ROLE_RANK[UserRole.Admin]

    @staticmethod
    def _value(content: Any) -> ua.DataValue:
        return ua.DataValue(ua.Variant(content, ua.VariantType.ExtensionObject))

    def _denied(self) -> ua.DataValue:
        return ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadUserAccessDenied))

    async def install(self) -> None:
        aspace = self.iserver.aspace
        ids = ua.ObjectIds
        with suppress_model_change():
            await self.iserver.node_mgt_service.delete_nodes(
                ua.DeleteNodesParameters(
                    NodesToDelete=[
                        ua.DeleteNodesItem(
                            ua.NodeId(ids.Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray), True
                        )
                    ]
                )
            )

        def summary_field(name: str) -> Any:
            return lambda node_id, attr: ua.DataValue(ua.Variant(getattr(self.summary(), name), ua.VariantType.UInt32))

        prefix = "Server_ServerDiagnostics_ServerDiagnosticsSummary_"
        for f in fields(ua.ServerDiagnosticsSummaryDataType):
            node_id = ua.NodeId(getattr(ids, prefix + f.name))
            aspace.set_attribute_value_callback(node_id, ua.AttributeIds.Value, summary_field(f.name))
        aspace.set_attribute_value_callback(
            ua.NodeId(ids.Server_ServerDiagnostics_ServerDiagnosticsSummary),
            ua.AttributeIds.Value,
            lambda n, a: self._value(self.summary()),
        )
        aspace.set_attribute_value_callback(
            ua.NodeId(ids.Server_ServerDiagnostics_SubscriptionDiagnosticsArray),
            ua.AttributeIds.Value,
            lambda n, a: self._value(self.subscription_diagnostics()),
        )
        sessions_base = ids.Server_ServerDiagnostics_SessionsDiagnosticsSummary
        aspace.set_attribute_value_callback(
            ua.NodeId(sessions_base + 1),
            ua.AttributeIds.Value,
            lambda n, a: self._value(self.session_diagnostics()),
        )
        aspace.set_attribute_value_callback(
            ua.NodeId(sessions_base + 2),
            ua.AttributeIds.Value,
            self._security_array,
        )
        flag = ua.NodeId(ids.Server_ServerDiagnostics_EnabledFlag)
        aspace.set_attribute_value_callback(
            flag, ua.AttributeIds.Value, lambda n, a: ua.DataValue(ua.Variant(self._enabled, ua.VariantType.Boolean))
        )
        aspace.set_attribute_value_setter(flag, ua.AttributeIds.Value, self._write_flag)
        for attribute in (ua.AttributeIds.AccessLevel, ua.AttributeIds.UserAccessLevel):
            await self.iserver.write_attribute_value(
                flag,
                ua.DataValue(
                    ua.Variant(ua.AccessLevel.CurrentRead.mask | ua.AccessLevel.CurrentWrite.mask, ua.VariantType.Byte)
                ),
                attribute,
            )
        self._installed = True
        if self._enabled:
            self._enabled = False
            self.enabled = True

    def _security_array(self, node_id: ua.NodeId, attr: ua.AttributeIds) -> ua.DataValue:
        if not self._enabled:
            return self._value([])
        if not self.may_read_security(None):
            return self._denied()
        manager = self.iserver.session_manager
        return self._value(
            [
                self.security_diagnostics(session)
                for session in sorted(manager.sessions.values(), key=lambda s: s.created_at)
                if session.is_activated()
            ]
        )

    def _write_flag(self, node: Any, attribute: ua.AttributeIds, value: ua.DataValue) -> ua.StatusCode | None:
        if value.Value is None or not isinstance(value.Value.Value, bool):
            return ua.StatusCode(ua.StatusCodes.BadTypeMismatch)
        if not self.may_switch():
            return ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
        self.enabled = value.Value.Value
        return None

    @staticmethod
    def _ident(session_id: ua.NodeId) -> str:
        return str(session_id.Identifier)

    def _node_id(self, session_id: ua.NodeId, *path: str) -> ua.NodeId:
        return ua.NodeId("/".join(("Diagnostics", "Session", self._ident(session_id), *path)), DIAGNOSTICS_NAMESPACE)

    def _create_session_nodes(self, session: Session) -> None:
        if session.id in self._objects or session.id not in self.sessions:
            return
        ids = ua.ObjectIds
        summary = ua.NodeId(ids.Server_ServerDiagnostics_SessionsDiagnosticsSummary)
        name = session.name or f"Session {self._ident(session.id)}"
        object_id = self._node_id(session.id)
        created = [object_id]
        with suppress_model_change():
            self._add(
                summary,
                object_id,
                ua.QualifiedName(name, DIAGNOSTICS_NAMESPACE),
                ua.NodeClass.Object,
                ua.NodeId(ids.SessionDiagnosticsObjectType),
            )
            for child, data_type, type_def, callback in (
                (
                    "SessionDiagnostics",
                    ids.SessionDiagnosticsDataType,
                    ids.SessionDiagnosticsVariableType,
                    lambda n, a, s=session.id: self._session_value(s),
                ),
                (
                    "SessionSecurityDiagnostics",
                    ids.SessionSecurityDiagnosticsDataType,
                    ids.SessionSecurityDiagnosticsType,
                    lambda n, a, s=session.id: self._session_security_value(s),
                ),
                (
                    "SubscriptionDiagnosticsArray",
                    ids.SubscriptionDiagnosticsDataType,
                    ids.SubscriptionDiagnosticsArrayType,
                    lambda n, a, s=session.id: self._value(self.subscription_diagnostics(s)),
                ),
            ):
                node_id = self._node_id(session.id, child)
                array = child.endswith("Array")
                self._add(
                    object_id,
                    node_id,
                    ua.QualifiedName(child, 0),
                    ua.NodeClass.Variable,
                    ua.NodeId(type_def),
                    ua.NodeId(data_type),
                    array,
                )
                self.iserver.aspace.set_attribute_value_callback(node_id, ua.AttributeIds.Value, callback)
                created.append(node_id)
        self._objects[session.id] = created

    def _session_value(self, session_id: ua.NodeId) -> ua.DataValue:
        session = self.iserver.session_manager.session_by_id(session_id)
        if session is None or session_id not in self.sessions:
            return ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown))
        return self._value(self._session_structure(session))

    def _session_security_value(self, session_id: ua.NodeId) -> ua.DataValue:
        session = self.iserver.session_manager.session_by_id(session_id)
        if session is None:
            return ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown))
        if not self.may_read_security(session_id):
            return self._denied()
        return self._value(self.security_diagnostics(session))

    def _add(
        self,
        parent: ua.NodeId,
        node_id: ua.NodeId,
        browse_name: ua.QualifiedName,
        node_class: ua.NodeClass,
        type_definition: ua.NodeId,
        data_type: ua.NodeId | None = None,
        array: bool = False,
    ) -> None:
        item = ua.AddNodesItem()
        item.ParentNodeId = parent
        item.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent)
        item.RequestedNewNodeId = node_id
        item.BrowseName = browse_name
        item.NodeClass = node_class
        item.TypeDefinition = type_definition
        attributes: Any
        if node_class == ua.NodeClass.Variable:
            attributes = ua.VariableAttributes()
            attributes.DisplayName = ua.LocalizedText(browse_name.Name)
            attributes.DataType = data_type or ua.NodeId(ua.ObjectIds.BaseDataType)
            attributes.ValueRank = 1 if array else -1
            attributes.ArrayDimensions = [0] if array else None
            attributes.AccessLevel = ua.AccessLevel.CurrentRead.mask
            attributes.UserAccessLevel = ua.AccessLevel.CurrentRead.mask
            attributes.Value = ua.Variant(None)
        else:
            attributes = ua.ObjectAttributes()
            attributes.DisplayName = ua.LocalizedText(browse_name.Name)
            attributes.EventNotifier = 0
        item.NodeAttributes = attributes
        [result] = self.iserver.node_mgt_service.add_nodes([item], trusted=True)
        result.StatusCode.check()

    def _delete_session_nodes(self, session_id: ua.NodeId) -> None:
        created = self._objects.pop(session_id, None)
        if not created:
            return
        task = asyncio.get_running_loop().create_task(self._delete(created))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _delete(self, created: list[ua.NodeId]) -> None:
        with suppress_model_change():
            await self.iserver.node_mgt_service.delete_nodes(
                ua.DeleteNodesParameters(
                    NodesToDelete=[ua.DeleteNodesItem(node_id, True) for node_id in reversed(created)]
                )
            )

    async def stop(self) -> None:
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

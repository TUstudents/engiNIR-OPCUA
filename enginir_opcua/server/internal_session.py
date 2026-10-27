from __future__ import annotations

import asyncio
import logging
import secrets
import time
import weakref
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession
from enginir_opcua.crypto.permission_rules import PermissionRuleset, User, UserRole

from ..common.callback import CallbackType, ServerItemCallback
from ..common.utils import ServiceError, create_nonce
from ..crypto import uacrypto
from ..crypto.uacrypto import x509
from ..crypto.validator import check_application_uri
from .address_space import AddressSpace
from .identity import COUNTED_FAILURES, match_token_policy, peer_key, user_name_credentials
from .subscription_service import SubscriptionService

if TYPE_CHECKING:
    from .internal_server import InternalServer

_logger = logging.getLogger(__name__)

CLIENT_NONCE_MIN_LENGTH = 32
CLIENT_NONCE_MAX_LENGTH = 128
SERVER_NONCE_LENGTH = 32
TOKEN_LENGTH = 32
SESSION_ID_NAMESPACE = 1


class SessionState(Enum):
    Created = 0
    Activated = 1
    Closed = 2


@dataclass(frozen=True)
class ChannelSecurity:
    certificate: bytes | None
    policy_uri: str
    mode: ua.MessageSecurityMode


class SessionChannel(Protocol):
    @property
    def channel_id(self) -> int: ...

    @property
    def security(self) -> ChannelSecurity: ...

    @property
    def peer_address(self) -> str | None: ...

    @property
    def max_request_message_size(self) -> int: ...

    @property
    def sockname(self) -> tuple[str, int] | None: ...

    @property
    def permissions(self) -> PermissionRuleset | None: ...

    @property
    def server_certificate(self) -> bytes | None: ...

    @property
    def signature_algorithm(self) -> str | None: ...

    def sign(self, data: bytes) -> bytes: ...

    def verify(self, data: bytes, signature: bytes | None) -> None: ...

    def send_response(
        self, requesthandle: int, seqhdr: Any, response: Any, msgtype: Any = ua.MessageType.SecureMessage
    ) -> None: ...


def is_empty_identity_token(params: ua.ActivateSessionParameters) -> bool:
    token = params.UserIdentityToken
    return isinstance(token, ua.ExtensionObject) and token.TypeId == ua.NodeId(ua.ObjectIds.Null)


def identity_token(params: ua.ActivateSessionParameters) -> Any:
    token = params.UserIdentityToken
    if isinstance(token, ua.ExtensionObject) and token.TypeId == ua.NodeId(ua.ObjectIds.Null):
        return ua.AnonymousIdentityToken()
    return token


class PublishRequestData:
    def __init__(
        self,
        requesthdr: ua.RequestHeader,
        seqhdr: Any,
        results: list[ua.StatusCode] | None = None,
        channel: SessionChannel | None = None,
    ) -> None:
        self.requesthdr = requesthdr
        self.seqhdr = seqhdr
        self.results = results
        self.channel = channel
        self.timestamp = time.monotonic()

    def has_timed_out(self, now: float) -> bool:
        return self.requesthdr.TimeoutHint != 0 and self.requesthdr.TimeoutHint / 1000 < now - self.timestamp

    def answer(self, status: int) -> None:
        if self.channel is None:
            return
        fault = ua.ServiceFault()
        fault.ResponseHeader.ServiceResult = ua.StatusCode(status)
        self.channel.send_response(self.requesthdr.RequestHandle, self.seqhdr, fault)


class Session:
    """The server side of one OPC UA Session: identity, binding to a channel, timeout and the Publish queue."""

    def __init__(
        self,
        manager: SessionManager,
        session_id: ua.NodeId,
        channel: SessionChannel,
        name: str,
        revised_timeout_ms: float,
    ) -> None:
        self.manager = manager
        self.iserver = manager.iserver
        self.id = session_id
        self.token = ua.NodeId(secrets.token_bytes(TOKEN_LENGTH), 0, ua.NodeIdType.ByteString)
        self.name = name
        self.state = SessionState.Created
        self.user: User = User(role=UserRole.Anonymous)
        self.nonce: bytes = create_nonce(SERVER_NONCE_LENGTH)
        self.channel_security: ChannelSecurity = channel.security
        self.client_certificate: bytes | None = None
        self.revised_timeout_ms = revised_timeout_ms
        self.created_at = time.monotonic()
        self.last_activity = self.created_at
        self.bound_channel_id: int | None = channel.channel_id
        self._channel: weakref.ref[SessionChannel] | None = weakref.ref(channel)
        self.publish_queue: deque[PublishRequestData] = deque()
        self.in_flight = 0
        self.services = InternalSession(
            self.iserver,
            self.iserver.aspace,
            self.iserver.subscription_service,
            name,
            user=self.user,
            external=True,
            session_id=session_id,
        )
        self.services.publish_callback = self.forward_publish_response
        self.services.publish_request_callback = self.get_publish_request

    def __str__(self) -> str:
        return f"Session(name:{self.name}, id:{self.id}, user:{self.user}, state:{self.state.name})"

    @property
    def bound_channel(self) -> SessionChannel | None:
        return self._channel() if self._channel is not None else None

    def is_activated(self) -> bool:
        return self.state == SessionState.Activated

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def enter_request(self) -> None:
        if self.in_flight >= self.manager.max_requests_in_flight_per_session:
            raise ServiceError(ua.StatusCodes.BadServerTooBusy)
        self.in_flight += 1

    def leave_request(self) -> None:
        self.in_flight -= 1

    def idle_seconds(self, now: float) -> float:
        return now - self.last_activity

    def bind(self, channel: SessionChannel) -> None:
        self.bound_channel_id = channel.channel_id
        self._channel = weakref.ref(channel)

    def unbind(self) -> None:
        self.bound_channel_id = None
        self._channel = None
        self.publish_queue.clear()

    def move_to(self, channel: SessionChannel) -> None:
        previous = self.bound_channel_id
        self.bind(channel)
        remaining: deque[PublishRequestData] = deque()
        for requestdata in self.publish_queue:
            if requestdata.channel is not None and requestdata.channel.channel_id == previous:
                requestdata.answer(ua.StatusCodes.BadSecureChannelClosed)
            else:
                remaining.append(requestdata)
        self.publish_queue = remaining

    def flush_publish_queue(self, status: int) -> None:
        queued, self.publish_queue = self.publish_queue, deque()
        for requestdata in queued:
            requestdata.answer(status)

    def cancel_publish_requests(self, request_handle: int) -> int:
        cancelled = [r for r in self.publish_queue if r.requesthdr.RequestHandle == request_handle]
        for requestdata in cancelled:
            self.publish_queue.remove(requestdata)
            requestdata.answer(ua.StatusCodes.BadRequestCancelledByClient)
        return len(cancelled)

    @property
    def publish_request_limit(self) -> int:
        return self.manager.max_publish_requests_per_session

    def trim_retransmission_queue(self) -> None:
        subscriptions = self.iserver.subscription_service.subscriptions
        owned = [subscriptions[sub_id] for sub_id in self.subscription_ids()]
        bound = 2 * self.publish_request_limit
        while sum(sub.unacknowledged_count for sub in owned) > bound:
            holders = [sub for sub in owned if sub.unacknowledged_count]
            oldest = min(holders, key=lambda sub: sub.republish(sub.available_sequence_numbers()[0]).PublishTime)
            oldest.drop_oldest_unacknowledged()

    def subscription_ids(self) -> list[int]:
        return [
            sub_id
            for sub_id, sub in self.iserver.subscription_service.subscriptions.items()
            if sub.session_id == self.id
        ]

    def validate_identity(self, params: ua.ActivateSessionParameters, security: ChannelSecurity) -> User:
        id_token = identity_token(params)
        matched = match_token_policy(self.iserver.endpoints, security, id_token, is_empty_identity_token(params))
        username: str | None = None
        password: str | None = None
        certificate: bytes | None = security.certificate
        try:
            if isinstance(id_token, ua.UserNameIdentityToken):
                username, password = user_name_credentials(
                    matched, security, id_token, self.iserver.private_key, self.nonce
                )
            elif isinstance(id_token, ua.X509IdentityToken):
                certificate = self.iserver.verify_x509_token(self, id_token, params.UserTokenSignature)
        except (ServiceError, ua.uaerrors.UaStatusCodeError):
            raise
        except Exception:
            raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid) from None
        user = self.iserver.user_manager.get_user(
            self.iserver, username=username, password=password, certificate=certificate
        )
        if user is None:
            raise ServiceError(ua.StatusCodes.BadUserAccessDenied)
        return user

    def get_publish_request(self, subscription_id: int) -> PublishRequestData | None:
        now = time.monotonic()
        while True:
            if not self.publish_queue:
                return None
            requestdata = self.publish_queue.popleft()
            if not requestdata.has_timed_out(now):
                return requestdata
            requestdata.answer(ua.StatusCodes.BadTimeout)

    async def forward_publish_response(self, result: ua.PublishResult, requestdata: PublishRequestData) -> None:
        response = ua.PublishResponse()
        response.Parameters = result
        result.Results = requestdata.results
        if requestdata.channel is not None:
            requestdata.channel.send_response(requestdata.requesthdr.RequestHandle, requestdata.seqhdr, response)
        self.trim_retransmission_queue()

    async def enqueue_publish(self, requestdata: PublishRequestData, subscription_count: int) -> None:
        if await self.iserver.subscription_service.on_publish_request(self.id, requestdata):
            return
        if len(self.publish_queue) >= max(self.publish_request_limit, subscription_count + 1):
            self._evict_publish_request()
        self.publish_queue.append(requestdata)

    def _evict_publish_request(self) -> None:
        now = time.monotonic()
        for i, requestdata in enumerate(self.publish_queue):
            if requestdata.has_timed_out(now):
                del self.publish_queue[i]
                requestdata.answer(ua.StatusCodes.BadTimeout)
                return
        if self.publish_queue:
            self.publish_queue.popleft().answer(ua.StatusCodes.BadTooManyPublishRequests)

    async def settle_publish_queue(self) -> None:
        service = self.iserver.subscription_service
        while self.publish_queue and service.has_pending_notice(self.id):
            requestdata = self.get_publish_request(0)
            if requestdata is None:
                break
            await service.on_publish_request(self.id, requestdata)
        if not self.subscription_ids() and not service.has_pending_notice(self.id):
            self.flush_publish_queue(ua.StatusCodes.BadNoSubscription)

    async def close(self, delete_subscriptions: bool) -> None:
        if self.state == SessionState.Closed:
            return
        _logger.info("close session %s", self.name)
        self.state = SessionState.Closed
        self.manager.forget(self)
        self.flush_publish_queue(ua.StatusCodes.BadSessionClosed)
        self.iserver.subscription_service.drop_pending_notices(self.id)
        if delete_subscriptions:
            await self.services.delete_subscriptions(self.subscription_ids())


class SessionManager:
    """All Sessions of one server, found by their AuthenticationToken."""

    def __init__(self, iserver: InternalServer) -> None:
        self.iserver = iserver
        self.sessions: dict[ua.NodeId, Session] = {}
        self.max_sessions: int = 100
        self.max_requests_in_flight_per_session: int = 100
        self.max_publish_requests_per_session: int = 10
        self._counter = 0
        self._sweep_task: asyncio.Task[None] | None = None

    def next_session_id(self) -> ua.NodeId:
        self._counter += 1
        return ua.NodeId(self._counter, SESSION_ID_NAMESPACE)

    def new_in_process_session(self, name: str = "Internal") -> InternalSession:
        return InternalSession(
            self.iserver,
            self.iserver.aspace,
            self.iserver.subscription_service,
            name,
            user=User(role=UserRole.Admin),
            session_id=self.next_session_id(),
        )

    def session_by_id(self, session_id: ua.NodeId) -> Session | None:
        return next((session for session in self.sessions.values() if session.id == session_id), None)

    def forget(self, session: Session) -> None:
        self.sessions.pop(session.token, None)

    def has_session(self, channel_id: int) -> bool:
        return any(s.bound_channel_id == channel_id for s in self.sessions.values())

    def has_activated_session(self, channel_id: int) -> bool:
        return any(s.bound_channel_id == channel_id and s.is_activated() for s in self.sessions.values())

    def resolve(self, channel: SessionChannel, token: ua.NodeId, requires_activated: bool = True) -> Session:
        session = self.sessions.get(token)
        if session is None:
            raise ServiceError(ua.StatusCodes.BadSessionIdInvalid)
        if session.bound_channel_id != channel.channel_id:
            raise ServiceError(ua.StatusCodes.BadSecureChannelIdInvalid)
        session.touch()
        if requires_activated and not session.is_activated():
            raise ServiceError(ua.StatusCodes.BadSessionNotActivated)
        return session

    def _revise_timeout(self, requested: float) -> float:
        revised = min(max(requested, self.iserver.min_session_timeout_ms), self.iserver.max_session_timeout_ms)
        if revised != requested:
            _logger.info("Clamping RequestedSessionTimeout %.0fms to %.0fms", requested, revised)
        return revised

    @staticmethod
    def _check_client_certificate(client_certificate: bytes | None, security: ChannelSecurity) -> None:
        if security.mode == ua.MessageSecurityMode.None_:
            return
        try:
            certificate = uacrypto.der_from_x509(uacrypto.x509_from_der(client_certificate))
        except Exception:
            raise ServiceError(ua.StatusCodes.BadCertificateInvalid) from None
        if certificate != security.certificate:
            _logger.warning("CreateSession certificate does not match the SecureChannel certificate")
            raise ServiceError(ua.StatusCodes.BadSecurityChecksFailed)

    @staticmethod
    def _check_client_application_uri(params: ua.CreateSessionParameters, security: ChannelSecurity) -> None:
        if security.mode == ua.MessageSecurityMode.None_:
            return
        certificate = uacrypto.x509_from_der(params.ClientCertificate)
        if certificate is None:
            return
        outcome = check_application_uri(certificate, params.ClientDescription.ApplicationUri)
        if not outcome.accepted:
            raise ServiceError(outcome.status)

    async def _make_room(self) -> None:
        if len(self.sessions) < self.max_sessions:
            return
        unactivated = [s for s in self.sessions.values() if s.state == SessionState.Created]
        if not unactivated:
            raise ServiceError(ua.StatusCodes.BadTooManySessions)
        oldest = min(unactivated, key=lambda s: s.created_at)
        _logger.warning("At max_sessions=%s, closing the oldest unactivated session %s", self.max_sessions, oldest)
        await oldest.close(False)

    async def create_session(
        self, channel: SessionChannel, params: ua.CreateSessionParameters, sockname: tuple[str, int] | None = None
    ) -> ua.CreateSessionResult:
        nonce = params.ClientNonce
        if nonce is None or not CLIENT_NONCE_MIN_LENGTH <= len(nonce) <= CLIENT_NONCE_MAX_LENGTH:
            raise ServiceError(ua.StatusCodes.BadNonceInvalid)
        security = channel.security
        self._check_client_certificate(params.ClientCertificate, security)
        self._check_client_application_uri(params, security)
        if self.iserver.application_hook and params.ClientCertificate:
            await self.iserver.application_hook(
                x509.load_der_x509_certificate(params.ClientCertificate), params.ClientDescription
            )
        ep_params = ua.GetEndpointsParameters()
        ep_params.EndpointUrl = params.EndpointUrl
        endpoints = await self.iserver.get_endpoints(params=ep_params, sockname=sockname)
        await self._make_room()
        session = Session(
            self,
            self.next_session_id(),
            channel,
            params.SessionName or "",
            self._revise_timeout(float(params.RequestedSessionTimeout or 0)),
        )
        session.client_certificate = params.ClientCertificate
        self.sessions[session.token] = session
        result = ua.CreateSessionResult()
        result.SessionId = session.id
        result.AuthenticationToken = session.token
        result.RevisedSessionTimeout = session.revised_timeout_ms
        result.MaxRequestMessageSize = channel.max_request_message_size
        result.ServerNonce = session.nonce
        result.ServerEndpoints = endpoints
        result.ServerCertificate = channel.server_certificate
        signed = (security.certificate or b"") + nonce
        result.ServerSignature.Signature = channel.sign(signed)
        result.ServerSignature.Algorithm = channel.signature_algorithm
        return result

    def _check_move(self, session: Session, channel: SessionChannel, params: ua.ActivateSessionParameters) -> None:
        security = channel.security
        if not session.is_activated() or session.channel_security != security:
            _logger.warning("Rejected moving session %s to a SecureChannel with different security", session.name)
            raise ServiceError(ua.StatusCodes.BadSecurityChecksFailed)
        if security.mode == ua.MessageSecurityMode.Sign and isinstance(
            identity_token(params), ua.AnonymousIdentityToken
        ):
            raise ServiceError(ua.StatusCodes.BadIdentityTokenRejected)

    async def activate_session(
        self, channel: SessionChannel, token: ua.NodeId, params: ua.ActivateSessionParameters
    ) -> ua.ActivateSessionResult:
        if token not in self.sessions:
            raise ServiceError(ua.StatusCodes.BadSessionIdInvalid)
        guard = self.iserver.identity_guard
        key = peer_key(channel.security, channel.peer_address)
        delay = guard.begin(key)
        try:
            if delay > 0:
                _logger.warning("Delaying ActivateSession of %s by %.0f s after repeated identity failures", key, delay)
                await guard.sleep(delay)
            return self._activate(channel, token, params, key)
        finally:
            guard.end(key)

    def _validated_user(
        self, session: Session, params: ua.ActivateSessionParameters, security: ChannelSecurity, key: str
    ) -> User:
        guard = self.iserver.identity_guard
        try:
            user = session.validate_identity(params, security)
        except (ServiceError, ua.uaerrors.UaStatusCodeError) as error:
            if error.code in COUNTED_FAILURES:
                guard.record_failure(key)
            raise
        except Exception:
            guard.record_failure(key)
            raise
        guard.record_success(key)
        return user

    def _activate(
        self, channel: SessionChannel, token: ua.NodeId, params: ua.ActivateSessionParameters, key: str
    ) -> ua.ActivateSessionResult:
        session = self.sessions.get(token)
        if session is None:
            raise ServiceError(ua.StatusCodes.BadSessionIdInvalid)
        moving = session.bound_channel_id != channel.channel_id
        if moving and session.state == SessionState.Created:
            raise ServiceError(ua.StatusCodes.BadSecureChannelIdInvalid)
        if moving:
            self._check_move(session, channel, params)
        security = channel.security
        server_certificate = channel.server_certificate
        challenge = session.nonce if server_certificate is None else server_certificate + session.nonce
        try:
            channel.verify(challenge, params.ClientSignature.Signature)
        except ua.uaerrors.SignatureError:
            raise ServiceError(ua.StatusCodes.BadApplicationSignatureInvalid) from None
        user = self._validated_user(session, params, security, key)
        if moving and user != session.user:
            _logger.warning("Rejected moving session %s to a new channel with a different user", session.name)
            raise ServiceError(ua.StatusCodes.BadIdentityTokenRejected)
        result = ua.ActivateSessionResult()
        for _ in params.ClientSoftwareCertificates:
            result.Results.append(ua.StatusCode())
        session.user = user
        session.services.user = user
        session.nonce = create_nonce(SERVER_NONCE_LENGTH)
        result.ServerNonce = session.nonce
        session.state = SessionState.Activated
        if moving:
            session.move_to(channel)
        session.touch()
        _logger.info("Activated session %s for user %s", session.name, user)
        return result

    async def close_session(self, channel: SessionChannel, token: ua.NodeId, delete_subscriptions: bool) -> None:
        session = self.resolve(channel, token, requires_activated=False)
        await session.close(delete_subscriptions)

    async def on_channel_closed(self, channel: SessionChannel) -> None:
        for session in list(self.sessions.values()):
            if session.bound_channel_id != channel.channel_id:
                continue
            if session.state == SessionState.Created:
                await session.close(False)
            else:
                session.unbind()

    async def sweep(self) -> float:
        now = time.monotonic()
        wait = 1.0
        pending_limit = self.iserver.max_pending_activation_seconds
        for session in list(self.sessions.values()):
            if session.state == SessionState.Created and pending_limit > 0:
                remaining = pending_limit - (now - session.created_at)
            else:
                remaining = session.revised_timeout_ms / 1000 - session.idle_seconds(now)
            if remaining <= 0:
                _logger.info("Session %s expired", session.name)
                await session.close(False)
            else:
                wait = min(wait, remaining)
        return max(wait, 0.05)

    def start(self) -> None:
        if self._sweep_task is None or self._sweep_task.done():
            self._sweep_task = asyncio.create_task(self._sweep_loop())

    async def _sweep_loop(self) -> None:
        while True:
            try:
                wait = await self.sweep()
            except Exception:
                _logger.exception("Session sweep failed")
                wait = 1.0
            await asyncio.sleep(wait)

    async def close_all(self) -> None:
        if self._sweep_task is not None:
            self._sweep_task.cancel()
            try:
                await self._sweep_task
            except asyncio.CancelledError:
                pass
            self._sweep_task = None
        for session in list(self.sessions.values()):
            await session.close(False)


class InternalSession(AbstractSession):
    """The service set of a Session (or of the server itself) for nodes, helpers and the dispatcher."""

    def __init__(
        self,
        internal_server: InternalServer,
        aspace: AddressSpace,
        submgr: SubscriptionService,
        name: str,
        user: User = User(role=UserRole.Anonymous),
        external: bool = False,
        session_id: ua.NodeId | None = None,
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self.iserver: InternalServer = internal_server
        self.external = external
        self.aspace: AddressSpace = aspace
        self.subscription_service: SubscriptionService = submgr
        self.name: str = name
        self.user: User = user
        self.session_id: ua.NodeId = (
            session_id if session_id is not None else internal_server.session_manager.next_session_id()
        )
        self.publish_callback: Callable[..., Any] | None = None
        self.publish_request_callback: Callable[..., Any] | None = None

    def __str__(self) -> str:
        return f"InternalSession(name:{self.name}, user:{self.user}, id:{self.session_id})"

    async def get_endpoints(
        self, params: ua.GetEndpointsParameters | None = None, sockname: tuple[str, int] | None = None
    ) -> list[ua.EndpointDescription]:
        return await self.iserver.get_endpoints(params, sockname)

    async def read(self, params: ua.ReadParameters) -> list[ua.DataValue]:
        if self.user is None:
            user = User()
        else:
            user = self.user
        await self.iserver.callback_service.dispatch(
            CallbackType.PreRead, ServerItemCallback(params, None, user, self.external)
        )
        results = self.iserver.attribute_service.read(params)
        await self.iserver.callback_service.dispatch(
            CallbackType.PostRead, ServerItemCallback(params, results, user, self.external)
        )
        return results

    async def history_read(self, params: ua.HistoryReadParameters) -> list[ua.HistoryReadResult]:
        return await self.iserver.history_manager.read_history(params)

    async def history_update(self, params: ua.HistoryUpdateParameters) -> list[ua.HistoryUpdateResult]:
        return self.iserver.history_manager.update_history(params)

    async def write(self, params: ua.WriteParameters) -> list[ua.StatusCode]:
        if self.user is None:
            user = User()
        else:
            user = self.user
        await self.iserver.callback_service.dispatch(
            CallbackType.PreWrite, ServerItemCallback(params, None, user, self.external)
        )
        write_result = await self.iserver.attribute_service.write(params, user=user)
        await self.iserver.callback_service.dispatch(
            CallbackType.PostWrite, ServerItemCallback(params, write_result, user, self.external)
        )
        return write_result

    async def browse(self, params: ua.BrowseParameters) -> list[ua.BrowseResult]:
        return self.iserver.view_service.browse(params)

    async def browse_next(self, parameters: ua.BrowseNextParameters) -> list[ua.BrowseResult]:
        # TODO
        # ContinuationPoint: https://reference.opcfoundation.org/v104/Core/docs/Part4/7.6/
        # Add "ContinuationPoints" and some form of management for them to current sessionimplementation
        # BrowseNext: https://reference.opcfoundation.org/Core/Part4/v104/5.8.3/
        raise NotImplementedError

    async def register_nodes(self, nodes: list[ua.NodeId]) -> list[ua.NodeId]:
        self.logger.info("Node registration not implemented")
        return nodes

    async def unregister_nodes(self, nodes: list[ua.NodeId]) -> None:
        self.logger.info("Node registration not implemented")

    async def translate_browsepaths_to_nodeids(self, params: list[ua.BrowsePath]) -> list[ua.BrowsePathResult]:
        return self.iserver.view_service.translate_browsepaths_to_nodeids(params)

    async def add_nodes(self, params: list[ua.AddNodesItem]) -> list[ua.AddNodesResult]:
        return self.iserver.node_mgt_service.add_nodes(params, self.user)

    async def delete_nodes(self, params: ua.DeleteNodesParameters) -> list[ua.StatusCode]:
        return self.iserver.node_mgt_service.delete_nodes(params, self.user)

    async def add_references(self, params: list[ua.AddReferencesItem]) -> list[ua.StatusCode]:
        return self.iserver.node_mgt_service.add_references(params, self.user)

    async def delete_references(self, params: list[ua.DeleteReferencesItem]) -> list[ua.StatusCode]:
        return self.iserver.node_mgt_service.delete_references(params, self.user)

    def add_method_callback(self, methodid: ua.NodeId, callback: Callable[..., Any]) -> ua.StatusCode:
        return self.aspace.add_method_callback(methodid, callback)

    async def call(self, params: list[ua.CallMethodRequest]) -> list[ua.CallMethodResult]:
        """COROUTINE"""
        return await self.iserver.method_service.call(params)

    async def create_subscription(
        self,
        params: ua.CreateSubscriptionParameters,
        callback: Callable[..., Any],
        request_callback: Callable[..., Any] | None = None,
    ) -> ua.CreateSubscriptionResult:
        result = await self.subscription_service.create_subscription(
            params, callback, self.session_id, request_callback=request_callback
        )
        return result

    async def create_monitored_items(
        self, params: ua.CreateMonitoredItemsParameters
    ) -> list[ua.MonitoredItemCreateResult]:
        """Returns Future"""
        subscription_result = await self.subscription_service.create_monitored_items(params, self.session_id)
        await self.iserver.callback_service.dispatch(
            CallbackType.ItemSubscriptionCreated, ServerItemCallback(params, subscription_result, None, self.external)
        )
        return subscription_result

    async def modify_monitored_items(
        self, params: ua.ModifyMonitoredItemsParameters
    ) -> list[ua.MonitoredItemModifyResult]:
        subscription_result = self.subscription_service.modify_monitored_items(params, self.session_id)
        await self.iserver.callback_service.dispatch(
            CallbackType.ItemSubscriptionModified, ServerItemCallback(params, subscription_result, None, self.external)
        )
        return subscription_result

    async def set_monitoring_mode(self, params: ua.SetMonitoringModeParameters) -> list[ua.StatusCode]:
        return await self.subscription_service.set_monitoring_mode(params, self.session_id)

    async def set_publishing_mode(self, params: ua.SetPublishingModeParameters) -> list[ua.StatusCode]:
        return await self.subscription_service.set_publishing_mode(params, self.session_id)

    def republish(self, params: ua.RepublishParameters) -> ua.NotificationMessage:
        return self.subscription_service.republish(params, self.session_id)

    async def delete_subscriptions(self, ids: list[int]) -> list[ua.StatusCode]:
        return await self.subscription_service.delete_subscriptions(ids, self.session_id)

    async def delete_monitored_items(self, params: ua.DeleteMonitoredItemsParameters) -> list[ua.StatusCode]:
        # This is an async method, dues to symmetry with client code
        subscription_result = self.subscription_service.delete_monitored_items(params, self.session_id)
        await self.iserver.callback_service.dispatch(
            CallbackType.ItemSubscriptionDeleted, ServerItemCallback(params, subscription_result, None, self.external)
        )

        return subscription_result

    def publish(self, acks: Iterable[ua.SubscriptionAcknowledgement] | None = None) -> tuple[int, list[ua.StatusCode]]:
        return self.subscription_service.publish(acks or [], self.session_id)

    def modify_subscription(self, params: ua.ModifySubscriptionParameters) -> ua.ModifySubscriptionResult:
        # Sync because the underlying service is sync; the client-side UaSession
        # is async (RPC). Not part of AbstractSession because the shapes diverge.
        return self.subscription_service.modify_subscription(params, self.session_id)

    async def transfer_subscriptions(self, params: ua.TransferSubscriptionsParameters) -> list[ua.TransferResult]:
        if self.publish_callback is None:
            raise ServiceError(ua.StatusCodes.BadServiceUnsupported)
        return await self.subscription_service.transfer_subscriptions(
            params, self.session_id, self.publish_callback, self.publish_request_callback
        )

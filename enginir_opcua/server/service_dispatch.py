"""The service dispatch table and the one place where a request meets its session, permission and limits."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua

from ..common.utils import Buffer, ServiceError
from ..crypto.permission_rules import ROLE_RANK, UserRole
from ..ua.ua_binary import nodeid_from_binary, struct_from_binary
from .internal_session import Session, SessionChannel, current_call_session

if TYPE_CHECKING:
    from .internal_server import InternalServer

_logger = logging.getLogger(__name__)


class Requires(Enum):
    NoSession = 0
    AnySession = 1
    ActivatedSession = 2


class Permission(Enum):
    Unchecked = 0
    Anonymous = 1
    User = 2
    Admin = 3


MINIMUM_RANK: dict[Permission, int] = {
    Permission.Anonymous: ROLE_RANK[UserRole.Anonymous],
    Permission.User: ROLE_RANK[UserRole.User],
    Permission.Admin: ROLE_RANK[UserRole.Admin],
}


@dataclass(frozen=True)
class OperationBound:
    array: str
    limit: str | None
    event_limit: str | None = None


@dataclass
class ServiceContext:
    iserver: InternalServer
    channel: SessionChannel
    session: Session | None
    header: ua.RequestHeader
    seqhdr: Any

    @property
    def active_session(self) -> Session:
        assert self.session is not None
        return self.session


ServiceHandler = Callable[[ServiceContext, Any], Awaitable[Any]]


@dataclass(frozen=True)
class ServiceEntry:
    name: str
    type_id: ua.NodeId
    decode: Callable[[Buffer], Any]
    handler: ServiceHandler
    permission: Permission
    requires: Requires = Requires.ActivatedSession
    operations: OperationBound | None = None


def entry(
    request_type: str,
    parameters: type | Callable[[Buffer], Any],
    handler: ServiceHandler,
    *,
    permission: Permission,
    requires: Requires = Requires.ActivatedSession,
    operations: OperationBound | None = None,
) -> ServiceEntry:
    type_id = ua.NodeId(getattr(ua.ObjectIds, f"{request_type}Request_Encoding_DefaultBinary"))
    if isinstance(parameters, type):
        parameter_type = parameters

        def decode(body: Buffer) -> Any:
            return struct_from_binary(parameter_type, body)

    else:
        decode = parameters
    return ServiceEntry(request_type, type_id, decode, handler, permission, requires, operations)


def status_of(error: Exception) -> int:
    if isinstance(error, ServiceError | ua.uaerrors.UaStatusCodeError):
        return error.code
    return ua.StatusCodes.BadInternalError


class Dispatcher:
    def __init__(self, iserver: InternalServer, entries: list[ServiceEntry]) -> None:
        self.iserver = iserver
        self.table: dict[ua.NodeId, ServiceEntry] = {}
        for service in entries:
            self.register(service)

    def register(self, service: ServiceEntry) -> None:
        if service.type_id in self.table:
            raise ValueError(f"duplicate service entry {service.name}")
        self.table[service.type_id] = service

    def _answer_fault(self, channel: SessionChannel, handle: int, seqhdr: Any, status: int) -> None:
        fault = ua.ServiceFault()
        fault.ResponseHeader.ServiceResult = ua.StatusCode(status)
        channel.send_response(handle, seqhdr, fault)

    def _check_permission(self, service: ServiceEntry, session: Session, channel: SessionChannel, body: Buffer) -> None:
        if service.permission is Permission.Unchecked:
            return
        permissions = channel.permissions
        if permissions is None:
            if ROLE_RANK.get(session.user.role, -1) < MINIMUM_RANK[service.permission]:
                raise ServiceError(ua.StatusCodes.BadUserAccessDenied)
            return
        if permissions.check_validity(session.user, service.type_id, body) is False:
            raise ServiceError(ua.StatusCodes.BadUserAccessDenied)

    def _check_operations(self, service: ServiceEntry, params: Any) -> None:
        bound = service.operations
        if bound is None:
            return
        count = len(getattr(params, bound.array))
        if count == 0:
            raise ServiceError(ua.StatusCodes.BadNothingToDo)
        limit_name = bound.limit
        if bound.event_limit is not None and isinstance(
            getattr(params, "HistoryReadDetails", None), ua.ReadEventDetails
        ):
            limit_name = bound.event_limit
        if limit_name is not None and count > getattr(self.iserver.operation_limits, limit_name):
            raise ServiceError(ua.StatusCodes.BadTooManyOperations)

    def _session_for(self, service: ServiceEntry, channel: SessionChannel, header: ua.RequestHeader) -> Session | None:
        if service.requires is Requires.NoSession:
            return None
        return self.iserver.session_manager.resolve(
            channel, header.AuthenticationToken, requires_activated=service.requires is Requires.ActivatedSession
        )

    async def dispatch(self, channel: SessionChannel, seqhdr: Any, body: Buffer) -> None:
        handle = 0
        try:
            type_id = nodeid_from_binary(body)
            header = struct_from_binary(ua.RequestHeader, body)
        except Exception:
            _logger.warning("Undecodable request header", exc_info=True)
            self._answer_fault(channel, handle, seqhdr, ua.StatusCodes.BadDecodingError)
            return
        handle = header.RequestHandle
        session: Session | None = None
        counted = False
        service_name: str | None = None
        reader_token = None
        try:
            service = self.table.get(type_id)
            if service is None:
                _logger.warning("Unsupported request %s", type_id)
                raise ServiceError(ua.StatusCodes.BadServiceUnsupported)
            service_name = service.name
            session = self._session_for(service, channel, header)
            if session is not None:
                reader_token = current_call_session.set(session.services)  # J: reader of the request (SRV-94)
                session.enter_request()
                counted = True
                self._check_permission(service, session, channel, body)
            try:
                params = service.decode(body)
            except Exception:
                _logger.warning("Undecodable %s body", service.name, exc_info=True)
                raise ServiceError(ua.StatusCodes.BadDecodingError) from None
            self._check_operations(service, params)
            context = ServiceContext(self.iserver, channel, session, header, seqhdr)
            response = await service.handler(context, params)
            self.iserver.diagnostics.request_done(session, service_name, ua.StatusCodes.Good)  # J: diagnostics (SRV-93)
            if response is not None:
                channel.send_response(handle, seqhdr, response)
        except Exception as error:
            status = status_of(error)
            self.iserver.diagnostics.request_done(session, service_name, status)  # J: diagnostics (SRV-93)
            if status == ua.StatusCodes.BadInternalError:
                _logger.exception("Error while processing a request")
            else:
                _logger.info("Request failed with %s", ua.StatusCode(status).name)
            self._answer_fault(channel, handle, seqhdr, status)
        finally:
            if reader_token is not None:
                current_call_session.reset(reader_token)
            if counted and session is not None:
                session.leave_request()

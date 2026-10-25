"""The service dispatch table and the one place where a request meets its session, permission and limits."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua

from ..common.utils import Buffer, ServiceError
from ..crypto.permission_rules import UserRole
from ..ua.ua_binary import nodeid_from_binary, struct_from_binary
from .internal_session import Session, SessionChannel

if TYPE_CHECKING:
    from .internal_server import InternalServer

_logger = logging.getLogger(__name__)


class Requires(Enum):
    NoSession = 0
    AnySession = 1
    ActivatedSession = 2


class Permission(Enum):
    Unchecked = 0
    User = 1
    Admin = 2


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
    requires: Requires = Requires.ActivatedSession
    permission: Permission = Permission.User
    operations: OperationBound | None = None


def entry(
    request_type: str,
    parameters: type | Callable[[Buffer], Any],
    handler: ServiceHandler,
    requires: Requires = Requires.ActivatedSession,
    permission: Permission = Permission.User,
    operations: OperationBound | None = None,
) -> ServiceEntry:
    type_id = ua.NodeId(getattr(ua.ObjectIds, f"{request_type}Request_Encoding_DefaultBinary"))
    if isinstance(parameters, type):
        parameter_type = parameters

        def decode(body: Buffer) -> Any:
            return struct_from_binary(parameter_type, body)

    else:
        decode = parameters
    return ServiceEntry(request_type, type_id, decode, handler, requires, permission, operations)


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
            if service.permission is Permission.Admin and session.user.role != UserRole.Admin:
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
        try:
            service = self.table.get(type_id)
            if service is None:
                _logger.warning("Unsupported request %s", type_id)
                raise ServiceError(ua.StatusCodes.BadServiceUnsupported)
            session = self._session_for(service, channel, header)
            if session is not None:
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
            if response is not None:
                channel.send_response(handle, seqhdr, response)
        except Exception as error:
            status = status_of(error)
            if status == ua.StatusCodes.BadInternalError:
                _logger.exception("Error while processing a request")
            else:
                _logger.info("Request failed with %s", ua.StatusCode(status).name)
            self._answer_fault(channel, handle, seqhdr, status)
        finally:
            if counted and session is not None:
                session.leave_request()

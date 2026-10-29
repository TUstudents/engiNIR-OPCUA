import asyncio
import copy
import logging
from collections.abc import Callable

from enginir_opcua import ua

from ..common.connection import (
    HELLO_MAX_CHUNK_SIZE,
    AbortedMessage,
    MessageAborted,
    MessageTooLarge,
    OpenRequestError,
    SecureChannel,
    TransportError,
    TransportLimits,
    error_message_to_binary,
)
from ..common.utils import Buffer, ServiceError
from ..crypto.permission_rules import PermissionRuleset
from ..crypto.security_policies import SecurityPolicyNone
from ..crypto.validator import PeerRole, ValidationContext
from ..ua.ua_binary import struct_from_binary, struct_to_binary, uatcp_to_binary
from .internal_server import InternalServer
from .internal_session import ChannelSecurity
from .internal_session import PublishRequestData as PublishRequestData

_logger = logging.getLogger(__name__)


class UaProcessor:
    """
    Processor for OPC UA messages. Implements the OPC UA protocol for the server side.
    """

    def __init__(self, internal_server: InternalServer, transport, limits: TransportLimits):
        self.iserver: InternalServer = internal_server
        self.name = transport.get_extra_info("peername")
        self.sockname: tuple[str, int] | None = transport.get_extra_info("sockname")
        self._transport = transport
        self._request_tasks: set[asyncio.Task[None]] = set()
        self._limits = copy.deepcopy(limits)  # Copy limits because they get overriden
        self._channel = SecureChannel(SecurityPolicyNone(), self._limits)
        self._channel.peer_certificate_check = self._check_client_certificate
        self._channel.types = internal_server.types
        self._hello_received: bool = False
        self._hello_protocol_version = 0
        self.on_token_window: Callable[[float], None] | None = None

    def _check_client_certificate(self, chain: bytes) -> None:
        validator = self.iserver.certificate_validator
        if validator is None:
            raise TransportError(
                ua.StatusCodes.BadSecurityChecksFailed,
                "No certificate validator is configured, so no client certificate is trusted; "
                "configure the trust store of the server (set_trust_store)",
            )
        context = ValidationContext(PeerRole.CLIENT, self._channel.security_policy.URI)
        outcome = validator.validate_application_certificate(chain, context)
        if not outcome.accepted:
            status = ua.StatusCode(outcome.status).name
            raise TransportError(
                ua.StatusCodes.BadSecurityChecksFailed, f"Client certificate rejected: {status}: {outcome.detail}"
            )

    @property
    def last_used(self) -> float:
        return self._channel.last_used

    def channel_expires_in(self) -> float:
        return self._channel.expires_in()

    @property
    def channel_id(self) -> int:
        return self._channel.channel_id

    @property
    def security(self) -> ChannelSecurity:
        policy = self._channel.security_policy
        return ChannelSecurity(policy.peer_certificate, policy.URI, policy.Mode)

    @property
    def peer_address(self) -> str | None:
        return self.name[0] if self.name else None

    @property
    def max_request_message_size(self) -> int:
        return self._limits.max_message_size

    @property
    def permissions(self) -> PermissionRuleset | None:
        return self._channel.security_policy.permissions

    @property
    def server_certificate(self) -> bytes | None:
        return self._channel.security_policy.host_certificate

    @property
    def signature_algorithm(self) -> str | None:
        return self._channel.security_policy.AsymmetricSignatureURI

    def sign(self, data: bytes) -> bytes:
        return self._channel.security_policy.asymmetric_cryptography.signature(data)

    def verify(self, data: bytes, signature: bytes | None) -> None:
        self._channel.security_policy.asymmetric_cryptography.verify(data, signature)

    @property
    def hello_received(self) -> bool:
        return self._hello_received

    def accept_hello(self, body: Buffer) -> bytes:
        try:
            hello = struct_from_binary(ua.Hello, body)
        except ua.UaError as e:
            raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Malformed Hello") from e
        ack = self._limits.create_acknowledge_and_set_limits(hello)
        self._hello_received = True
        self._hello_protocol_version = hello.ProtocolVersion
        return uatcp_to_binary(ua.MessageType.Acknowledge, ack)

    def max_receive_chunk_size(self) -> int:
        if self._hello_received:
            return self._limits.max_recv_buffer
        return HELLO_MAX_CHUNK_SIZE

    def set_policies(self, policies):
        self._channel.set_policy_factories(policies)

    def send_response(self, requesthandle, seqhdr, response, msgtype=ua.MessageType.SecureMessage):
        response.ResponseHeader.RequestHandle = requesthandle
        try:
            with self.iserver.types.encoding():
                body = struct_to_binary(response)
            data = self._channel.message_to_binary(body, message_type=msgtype, request_id=seqhdr.RequestId)
        except MessageTooLarge:
            _logger.warning(
                "Response %s to request %s is above the limits of the client", type(response), requesthandle
            )
            fault = ua.ServiceFault()
            fault.ResponseHeader.RequestHandle = requesthandle
            fault.ResponseHeader.ServiceResult = ua.StatusCode(ua.StatusCodes.BadResponseTooLarge)
            data = self._channel.message_to_binary(
                struct_to_binary(fault), message_type=msgtype, request_id=seqhdr.RequestId
            )
        except MessageAborted as e:
            _logger.warning("Response to request %s was aborted", requesthandle)
            data = e.written
        self._transport.write(data)

    def open_secure_channel(self, message: ua.Message) -> bool:
        algohdr = message.security_header()
        assert isinstance(algohdr, ua.AsymmetricAlgorithmHeader)
        seqhdr = message.sequence_header()
        request = struct_from_binary(ua.OpenSecureChannelRequest, message.body())
        handle = request.RequestHeader.RequestHandle
        try:
            if not self._channel.is_open():
                self._channel.select_policy(
                    algohdr.SecurityPolicyURI, algohdr.SenderCertificate, request.Parameters.SecurityMode
                )
            self._channel.validate_open_request(
                message.channel_id(), algohdr, request.Parameters, self._hello_protocol_version
            )
        except TransportError as e:
            _logger.warning("Closing connection from %s: %s", self.name, e.reason)
            self._send_error(e.status)
            return False
        except OpenRequestError as e:
            _logger.warning("Rejecting OpenSecureChannel from %s: %s", self.name, e.reason)
            fault = ua.ServiceFault()
            fault.ResponseHeader.ServiceResult = ua.StatusCode(e.status)
            self.send_response(handle, seqhdr, fault, ua.MessageType.SecureOpen)
            return False
        channel = self._channel.open(request.Parameters, self.iserver, self.iserver.channel_settings)
        response = ua.OpenSecureChannelResponse()
        response.Parameters = channel
        self.send_response(handle, seqhdr, response, ua.MessageType.SecureOpen)
        if self.on_token_window is not None:
            self.on_token_window(self._channel.expires_in())
        return True

    def _send_error(self, status: int) -> None:
        self._transport.write(error_message_to_binary(status))

    async def process(self, header, body):
        try:
            msg = self._channel.receive_from_header_and_body(header, body)
        except ua.uaerrors.BadUserAccessDenied:
            _logger.warning("Unauthenticated user attempted to connect")
            return False
        except TransportError as e:
            _logger.warning("Closing connection from %s: %s", self.name, e.reason)
            self.iserver.diagnostics.channel_rejected(e.status)  # J: diagnostics (SRV-93)
            self._send_error(e.status)
            return False
        except Exception as e:
            _logger.warning("Closing connection from %s: channel failure", self.name, exc_info=True)
            status = e.code if isinstance(e, ua.UaStatusCodeError) else ua.StatusCodes.BadSecurityChecksFailed
            self.iserver.diagnostics.channel_rejected(status)  # J: diagnostics (SRV-93)
            self._send_error(status)
            return False
        if isinstance(msg, ua.Message):
            if header.MessageType == ua.MessageType.SecureOpen:
                return self.open_secure_channel(msg)
            if header.MessageType == ua.MessageType.SecureClose:
                self._channel.close()
                return False
            if header.MessageType == ua.MessageType.SecureMessage:
                return await self.process_message(msg.sequence_header(), msg.body())
        elif isinstance(msg, AbortedMessage):
            _logger.warning("Request %s was aborted by the client", msg.request_id)
        elif isinstance(msg, ua.ErrorMessage):
            _logger.warning("Received an error message type")
        elif msg is None:
            pass  # msg is a ChunkType.Intermediate of an ua.MessageType.SecureMessage
        else:
            _logger.warning("Unsupported message type: %s", header.MessageType)
            raise ServiceError(ua.StatusCodes.BadTcpMessageTypeInvalid)
        return True

    async def process_message(self, seqhdr: ua.SequenceHeader, body: Buffer) -> bool:
        task = asyncio.create_task(self.iserver.dispatcher.dispatch(self, seqhdr, body))
        self._request_tasks.add(task)
        task.add_done_callback(self._request_tasks.discard)
        return True

    async def close(self):
        _logger.info("Cleanup client connection: %s", self.name)
        for task in list(self._request_tasks):
            task.cancel()
        await self.iserver.session_manager.on_channel_closed(self)

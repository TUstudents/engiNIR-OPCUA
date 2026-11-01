"""
The secure channel of one server connection: Hello, OpenSecureChannel and the decoding of messages, which it hands
to the dispatcher.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

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
from ..common.utils import Buffer
from ..crypto.permission_rules import PermissionRuleset
from ..crypto.security_policies import SecurityPolicyFactory, SecurityPolicyNone
from ..crypto.validator import PeerRole, ValidationContext, untrusted_hint
from ..ua.ua_binary import struct_from_binary, struct_to_binary, uatcp_to_binary
from .internal_server import InternalServer
from .internal_session import ChannelSecurity

_logger = logging.getLogger(__name__)


def peer_label(peer: Any) -> str:
    """A peer address from get_extra_info("peername") as host:port, [host]:port for IPv6."""
    if not isinstance(peer, tuple) or len(peer) < 2:
        return "unknown peer"
    host, port = peer[0], peer[1]
    return f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"


class UaProcessor:
    """
    The server side of one connection's secure channel. It is the SessionChannel the sessions are bound to: it holds
    the channel's security, signs and verifies with its keys and sends the responses.
    """

    def __init__(self, internal_server: InternalServer, transport: asyncio.Transport, limits: TransportLimits) -> None:
        self.iserver: InternalServer = internal_server
        self.name: Any = transport.get_extra_info("peername")
        self.peer = peer_label(self.name)
        self.close_reason: str | None = None
        self.close_warned = False
        self.sockname: tuple[str, int] | None = transport.get_extra_info("sockname")
        self._transport = transport
        self._request_tasks: set[asyncio.Task[None]] = set()
        self._limits = copy.deepcopy(limits)
        self._channel = SecureChannel(SecurityPolicyNone(), self._limits)
        self._channel.peer_certificate_check = self._check_client_certificate
        self._channel.max_message_size_before_activation = internal_server.max_message_size_before_activation
        self._channel.is_activated = self._has_activated_session
        self._channel.types = internal_server.types
        self._hello_received: bool = False
        self._hello_protocol_version = 0
        self.on_token_window: Callable[[float], None] | None = None

    def _has_activated_session(self) -> bool:
        return self.iserver.session_manager.has_activated_session(self._channel.channel_id)

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
            validator.keep_rejected(outcome, self.peer_address)
            hint = untrusted_hint("client", outcome, validator.trust_store)
            status = ua.StatusCode(outcome.status).name
            reason = hint or f"client certificate {outcome.subject} rejected: {status}: {outcome.detail}"
            raise TransportError(ua.StatusCodes.BadSecurityChecksFailed, reason)

    def _warn_close(self, message: str) -> None:
        self.close_warned = True
        _logger.warning("%s %s", self.peer, message)

    @property
    def last_used(self) -> float:
        """The monotonic time of the last chunk received."""
        return self._channel.last_used

    def channel_expires_in(self) -> float:
        """Seconds until the channel has no valid security token."""
        return self._channel.expires_in()

    @property
    def channel_id(self) -> int:
        """The SecureChannelId."""
        return self._channel.channel_id

    @property
    def security(self) -> ChannelSecurity:
        """The client certificate, policy and mode of the channel."""
        policy = self._channel.security_policy
        return ChannelSecurity(policy.peer_certificate, policy.URI, policy.Mode)

    @property
    def peer_address(self) -> str | None:
        """The IP address of the client."""
        return self.name[0] if self.name else None

    @property
    def max_request_message_size(self) -> int:
        """The largest request this side accepts, in bytes."""
        return self._limits.max_message_size

    @property
    def permissions(self) -> PermissionRuleset | None:
        """The permission rules of the endpoint the channel uses."""
        return self._channel.security_policy.permissions

    @property
    def server_certificate(self) -> bytes | None:
        """The server certificate of the channel's policy, DER."""
        return self._channel.security_policy.host_certificate

    @property
    def signature_algorithm(self) -> str | None:
        """The asymmetric signature algorithm URI of the channel's policy."""
        return self._channel.security_policy.AsymmetricSignatureURI

    def sign(self, data: bytes) -> bytes:
        """Sign with the server's private key under the channel's policy."""
        return self._channel.security_policy.asymmetric_cryptography.signature(data)

    def verify(self, data: bytes, signature: bytes | None) -> None:
        """Verify a signature of the client; a missing one fails like a wrong one (SignatureError)."""
        self._channel.security_policy.asymmetric_cryptography.verify(data, signature or b"")

    @property
    def hello_received(self) -> bool:
        """Whether the Hello was accepted."""
        return self._hello_received

    def accept_hello(self, body: Buffer) -> bytes:
        """Check the Hello, revise the limits and return the Acknowledge message to send."""
        try:
            hello = struct_from_binary(ua.Hello, body)
        except ua.UaError as e:
            raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Malformed Hello") from e
        ack = self._limits.create_acknowledge_and_set_limits(hello)
        self._hello_received = True
        self._hello_protocol_version = hello.ProtocolVersion
        return uatcp_to_binary(ua.MessageType.Acknowledge, ack)

    def max_receive_chunk_size(self) -> int:
        """The largest chunk accepted: the negotiated receive buffer, or 8192 bytes before the Hello."""
        if self._hello_received:
            return self._limits.max_recv_buffer
        return HELLO_MAX_CHUNK_SIZE

    def set_policies(self, policies: list[SecurityPolicyFactory]) -> None:
        """The security policies of the server's endpoints."""
        self._channel.set_policy_factories(policies)

    def send_response(
        self,
        requesthandle: int,
        seqhdr: ua.SequenceHeader,
        response: Any,
        msgtype: bytes = ua.MessageType.SecureMessage,
    ) -> None:
        """
        Encode and send a response; one above the client's limits becomes a ServiceFault Bad_ResponseTooLarge, and
        one that fails after its first chunk is aborted (OPC 10000-6 v1.05, 6.7.3).
        """
        response.ResponseHeader.RequestHandle = requesthandle
        response.ResponseHeader.Timestamp = datetime.now(UTC)
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
            fault.ResponseHeader.Timestamp = response.ResponseHeader.Timestamp
            data = self._channel.message_to_binary(
                struct_to_binary(fault), message_type=msgtype, request_id=seqhdr.RequestId
            )
        except MessageAborted as e:
            _logger.warning("Response to request %s was aborted", requesthandle)
            data = e.written
        self._transport.write(data)

    def open_secure_channel(self, message: ua.Message) -> bool:
        """
        Answer an OpenSecureChannel request; False when the connection is to be closed. A request that fails a
        transport check gets an Error message, one with a bad parameter a ServiceFault.
        """
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
            self._warn_close(f"refused: {e.reason}")
            self._send_error(e.status)
            return False
        except OpenRequestError as e:
            self._warn_close(f"refused: OpenSecureChannel: {e.reason}")
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

    async def process(self, header: ua.Header, body: Buffer) -> bool:
        """
        Process one secure message (OPN, MSG or CLO; the connection handles the others). False when the connection
        is to be closed: after a channel failure, which the client is told with an Error message, or a CLO.
        """
        try:
            msg = self._channel.receive_from_header_and_body(header, body)
        except TransportError as e:
            self._warn_close(f"{'closed' if self._channel.is_open() else 'refused'}: {e.reason}")
            self.iserver.diagnostics.channel_rejected(e.status)
            self._send_error(e.status)
            return False
        except Exception as e:
            self.close_warned = True
            _logger.warning("%s closed: secure channel failure", self.peer, exc_info=True)
            status = e.code if isinstance(e, ua.UaStatusCodeError) else ua.StatusCodes.BadSecurityChecksFailed
            self.iserver.diagnostics.channel_rejected(status)
            self._send_error(status)
            return False
        if isinstance(msg, AbortedMessage):
            _logger.warning("Request %s was aborted by the client", msg.request_id)
        elif isinstance(msg, ua.Message):
            if header.MessageType == ua.MessageType.SecureOpen:
                return self.open_secure_channel(msg)
            if header.MessageType == ua.MessageType.SecureClose:
                self.close_reason = "client closed the secure channel"
                self._channel.close()
                return False
            return await self.process_message(msg.sequence_header(), msg.body())
        return True

    async def process_message(self, seqhdr: ua.SequenceHeader, body: Buffer) -> bool:
        """Hand a request to the dispatcher in a task of its own, so that requests of a channel run concurrently."""
        task = asyncio.create_task(self.iserver.dispatcher.dispatch(self, seqhdr, body))
        self._request_tasks.add(task)
        task.add_done_callback(self._request_tasks.discard)
        return True

    async def close(self) -> None:
        """Cancel the running requests and unbind the sessions of the channel."""
        _logger.debug("%s: releasing the requests and sessions of the connection", self.peer)
        for task in list(self._request_tasks):
            task.cancel()
        await self.iserver.session_manager.on_channel_closed(self)

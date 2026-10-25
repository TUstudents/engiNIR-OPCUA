from __future__ import annotations

import copy
import hashlib
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.ua.uaerrors import UaError, UaInvalidParameterError, UaStatusCodeError

from ..ua.ua_binary import header_from_binary, header_to_binary, struct_from_binary, struct_to_binary, uatcp_to_binary
from .utils import Buffer, NotEnoughData

if TYPE_CHECKING:
    from ..crypto.security_policies import CryptographyNone, SecurityPolicy

_logger = logging.getLogger("enginir_opcua.uaprotocol")

HELLO_MAX_CHUNK_SIZE = 8192
MIN_BUFFER_SIZE = 8192
MAX_ENDPOINT_URL_BYTES = 4096
MAX_ERROR_REASON_BYTES = 4096
KNOWN_MESSAGE_TYPES = frozenset(
    {
        ua.MessageType.Hello,
        ua.MessageType.Acknowledge,
        ua.MessageType.Error,
        ua.MessageType.SecureOpen,
        ua.MessageType.SecureMessage,
        ua.MessageType.SecureClose,
    }
)


class TransportError(UaError):
    """A failure that ends the connection and is reported to the peer as an Error message."""

    def __init__(self, status: int, reason: str = "") -> None:
        super().__init__(status, reason)
        self.status = status
        self.reason = reason


class MessageSizeExceeded(TransportError):
    """A Message above the MaxMessageSize or MaxChunkCount this side announced."""

    def __init__(self, reason: str) -> None:
        super().__init__(ua.StatusCodes.BadTcpMessageTooLarge, reason)


@dataclass
class AbortedMessage:
    """An Abort chunk (Part 6, 6.7.3): the Message of request_id is discarded and the channel stays open."""

    request_id: int
    error: ua.ErrorMessage

    @staticmethod
    def from_chunk(chunk: MessageChunk) -> AbortedMessage:
        try:
            error = struct_from_binary(ua.ErrorMessage, Buffer(chunk.Body))
            if len((error.Reason or "").encode()) > MAX_ERROR_REASON_BYTES:
                raise UaError("Reason is too long")
        except Exception:
            error = ua.ErrorMessage(ua.StatusCode(ua.StatusCodes.BadUnexpectedError), "")
        return AbortedMessage(chunk.SequenceHeader.RequestId, error)


class MessageTooLarge(UaError):
    """A Message above the MaxMessageSize or MaxChunkCount the peer announced; nothing was written."""


class MessageAborted(UaError):
    """Encoding failed after the first chunk; written holds the chunks encoded so far and the Abort chunk."""

    def __init__(self, written: bytes) -> None:
        super().__init__("Message aborted")
        self.written = written


def error_message_to_binary(status: int, reason: str = "") -> bytes:
    reason = reason.encode()[:MAX_ERROR_REASON_BYTES].decode(errors="ignore")
    return uatcp_to_binary(ua.MessageType.Error, ua.ErrorMessage(ua.StatusCode(status), reason))


class FrameReader:
    """
    Cuts the byte stream of a UA-TCP connection into whole messages (Part 6, 7.1.2.2).
    The size of a message is checked against the limit before any of its body is waited for.
    """

    def __init__(self, max_frame_size: Callable[[], int]) -> None:
        self.buffer = bytearray()
        self._max_frame_size = max_frame_size

    def feed(self, data: bytes) -> None:
        self.buffer += data

    def frames(self) -> Iterator[tuple[ua.Header, Buffer]]:
        pos = 0
        try:
            while True:
                if len(self.buffer) - pos < 3:
                    return
                if bytes(self.buffer[pos : pos + 3]) not in KNOWN_MESSAGE_TYPES:
                    raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Unknown message type")
                try:
                    header = header_from_binary(Buffer(bytes(self.buffer[pos : pos + ua.Header.max_size()])))
                except NotEnoughData:
                    return
                except UaStatusCodeError as e:
                    raise TransportError(e.code, "Malformed message header") from e
                limit = self._max_frame_size()
                if header.packet_size > limit:
                    raise TransportError(
                        ua.StatusCodes.BadTcpMessageTooLarge, f"Message size {header.packet_size} exceeds {limit}"
                    )
                end = pos + header.packet_size
                if len(self.buffer) < end:
                    return
                yield header, Buffer(bytes(self.buffer[pos + header.header_size : end]))
                pos = end
        except TransportError:
            pos = len(self.buffer)
            raise
        finally:
            del self.buffer[:pos]


DEFAULT_MAX_MESSAGE_SIZE = 100 * 1024 * 1024
DEFAULT_MAX_CHUNK_COUNT = DEFAULT_MAX_MESSAGE_SIZE // 65535 + 1


@dataclass
class TransportLimits:
    """
    Limits of the tcp transport layer to prevent excessive resource usage.

    max_recv_buffer, max_message_size and max_chunk_count are what this side enforces on incoming data and
    tells the peer. max_send_buffer, send_max_message_size and send_max_chunk_count are what the peer
    told us and what this side obeys when sending (0 means the peer has no limit).
    """

    max_recv_buffer: int = 65535
    max_send_buffer: int = 65535
    max_chunk_count: int = DEFAULT_MAX_CHUNK_COUNT
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE
    send_max_message_size: int = 0
    send_max_chunk_count: int = 0

    def __post_init__(self) -> None:
        if self.max_message_size == 0:
            self.max_message_size = DEFAULT_MAX_MESSAGE_SIZE
        if self.max_chunk_count == 0:
            self.max_chunk_count = DEFAULT_MAX_CHUNK_COUNT

    def is_msg_size_within_limit(self, sz: int) -> bool:
        if self.max_message_size == 0:
            return True
        within_limit = sz <= self.max_message_size
        if not within_limit:
            _logger.error("Message size: %s is > configured max message size: %s", sz, self.max_message_size)
        return within_limit

    def is_chunk_count_within_limit(self, sz: int) -> bool:
        if self.max_chunk_count == 0:
            return True
        within_limit = sz <= self.max_chunk_count
        if not within_limit:
            _logger.error("Number of message chunks: %s is > configured max chunk count: %s", sz, self.max_chunk_count)
        return within_limit

    @staticmethod
    def check_hello(msg: ua.Hello) -> None:
        for name in ("ReceiveBufferSize", "SendBufferSize"):
            size = getattr(msg, name)
            if size < MIN_BUFFER_SIZE:
                raise TransportError(
                    ua.StatusCodes.BadInvalidArgument, f"{name} {size} is below the minimum of {MIN_BUFFER_SIZE}"
                )
        if len((msg.EndpointUrl or "").encode()) > MAX_ENDPOINT_URL_BYTES:
            raise TransportError(ua.StatusCodes.BadTcpEndpointUrlInvalid, "EndpointUrl is too long")

    def create_acknowledge_and_set_limits(self, msg: ua.Hello) -> ua.Acknowledge:
        self.check_hello(msg)
        ack = ua.Acknowledge()
        ack.ReceiveBufferSize = min(msg.SendBufferSize, self.max_recv_buffer)
        ack.SendBufferSize = min(msg.ReceiveBufferSize, self.max_send_buffer)
        ack.MaxChunkCount = self.max_chunk_count
        ack.MaxMessageSize = self.max_message_size
        self.max_recv_buffer = ack.ReceiveBufferSize
        self.max_send_buffer = ack.SendBufferSize
        self.send_max_message_size = msg.MaxMessageSize
        self.send_max_chunk_count = msg.MaxChunkCount
        _logger.info("updated server limits to: %s", self)
        return ack

    def create_hello_limits(self, msg: ua.Hello) -> ua.Hello:
        msg.ReceiveBufferSize = self.max_recv_buffer
        msg.SendBufferSize = self.max_send_buffer
        msg.MaxChunkCount = self.max_chunk_count
        msg.MaxMessageSize = self.max_message_size
        return msg

    def update_client_limits(self, msg: ua.Acknowledge) -> None:
        if msg.ProtocolVersion > 0:
            raise TransportError(ua.StatusCodes.BadProtocolVersionUnsupported, "Acknowledge version is too high")
        for name, size, sent in (
            ("ReceiveBufferSize", msg.ReceiveBufferSize, self.max_send_buffer),
            ("SendBufferSize", msg.SendBufferSize, self.max_recv_buffer),
        ):
            if size < MIN_BUFFER_SIZE or size > sent:
                raise TransportError(
                    ua.StatusCodes.BadInvalidArgument, f"Acknowledge {name} {size} is outside {MIN_BUFFER_SIZE}..{sent}"
                )
        self.max_send_buffer = msg.ReceiveBufferSize
        self.max_recv_buffer = msg.SendBufferSize
        self.send_max_message_size = msg.MaxMessageSize
        self.send_max_chunk_count = msg.MaxChunkCount
        _logger.info("updated client limits to: %s", self)


class MessageChunk:
    """
    Message Chunk, as described in OPC UA specs Part 6, 6.7.2.
    """

    def __init__(
        self,
        crypto: CryptographyNone,
        body: bytes = b"",
        msg_type: ua.MessageType = ua.MessageType.SecureMessage,
        chunk_type: ua.ChunkType = ua.ChunkType.Single,
    ) -> None:
        self.MessageHeader = ua.Header(msg_type, chunk_type)
        self.SecurityHeader: ua.SymmetricAlgorithmHeader | ua.AsymmetricAlgorithmHeader
        if msg_type in (ua.MessageType.SecureMessage, ua.MessageType.SecureClose):
            self.SecurityHeader = ua.SymmetricAlgorithmHeader()
        elif msg_type == ua.MessageType.SecureOpen:
            self.SecurityHeader = ua.AsymmetricAlgorithmHeader()
        else:
            raise ua.UaError(f"Unsupported message type: {msg_type}")
        self.SequenceHeader = ua.SequenceHeader()
        self.Body = body
        self.crypto = crypto

    @staticmethod
    def from_binary(security_policy: SecurityPolicy, data: Buffer) -> MessageChunk:
        h = header_from_binary(data)
        try:
            return MessageChunk.from_header_and_body(security_policy, h, data)
        except ua.uaerrors.SignatureError:
            return MessageChunk.from_header_and_body(security_policy, h, data, use_prev_key=True)

    @staticmethod
    def from_header_and_body(
        security_policy: SecurityPolicy, header: ua.Header, buf: Buffer, use_prev_key: bool = False
    ) -> MessageChunk:
        if not len(buf) >= header.body_size:
            raise ValueError("Full body expected here")
        data = buf.copy(header.body_size)
        buf.skip(header.body_size)
        if header.MessageType in (ua.MessageType.SecureMessage, ua.MessageType.SecureClose):
            security_header = struct_from_binary(ua.SymmetricAlgorithmHeader, data)
            crypto = security_policy.symmetric_cryptography
        elif header.MessageType == ua.MessageType.SecureOpen:
            security_header = struct_from_binary(ua.AsymmetricAlgorithmHeader, data)
            crypto = security_policy.asymmetric_cryptography
        else:
            raise ua.UaError(f"Unsupported message type: {header.MessageType!r}")
        crypto.use_prev_key = use_prev_key  # type: ignore[attr-defined]
        obj = MessageChunk(crypto)
        obj.MessageHeader = header
        obj.SecurityHeader = security_header
        decrypted = crypto.decrypt(data.read(len(data)))
        signature_size = crypto.vsignature_size()
        if signature_size > 0:
            signature = decrypted[-signature_size:]
            decrypted = decrypted[:-signature_size]
            crypto.verify(
                header_to_binary(obj.MessageHeader) + struct_to_binary(obj.SecurityHeader) + decrypted, signature
            )
        data = ua.utils.Buffer(crypto.remove_padding(decrypted))
        obj.SequenceHeader = struct_from_binary(ua.SequenceHeader, data)
        obj.Body = data.read(len(data))
        return obj

    def encrypted_size(self, plain_size: int) -> int:
        size = plain_size + self.crypto.signature_size()
        pbs = self.crypto.plain_block_size()
        if size % pbs != 0:
            raise ua.UaError("Encryption error")
        return size // pbs * self.crypto.encrypted_block_size()

    def to_binary(self) -> bytes:
        security = struct_to_binary(self.SecurityHeader)
        encrypted_part = struct_to_binary(self.SequenceHeader) + self.Body
        encrypted_part += self.crypto.padding(len(encrypted_part))
        self.MessageHeader.body_size = len(security) + self.encrypted_size(len(encrypted_part))
        header = header_to_binary(self.MessageHeader)
        encrypted_part += self.crypto.signature(header + security + encrypted_part)
        return header + security + self.crypto.encrypt(encrypted_part)

    @staticmethod
    def max_body_size(crypto: CryptographyNone, max_chunk_size: int) -> int:
        max_encrypted_size = max_chunk_size - ua.Header.max_size() - ua.SymmetricAlgorithmHeader.max_size()
        max_plain_size = (max_encrypted_size // crypto.encrypted_block_size()) * crypto.plain_block_size()
        return max_plain_size - ua.SequenceHeader.max_size() - crypto.signature_size() - crypto.min_padding_size()

    @staticmethod
    def message_to_chunks(
        security_policy: SecurityPolicy,
        body: bytes,
        max_chunk_size: int,
        message_type: ua.MessageType = ua.MessageType.SecureMessage,
        channel_id: int = 1,
        request_id: int = 1,
        token_id: int = 1,
    ) -> list[MessageChunk]:
        """
        Pack message body (as binary string) into one or more chunks.
        Size of each chunk will not exceed max_chunk_size.
        Returns a list of MessageChunks. SequenceNumber is not initialized here,
        it must be set by Secure Channel driver.
        """
        if message_type == ua.MessageType.SecureOpen:
            # SecureOpen message must be in a single chunk (specs, Part 6, 6.7.2)
            chunk = MessageChunk(security_policy.asymmetric_cryptography, body, message_type, ua.ChunkType.Single)
            assert isinstance(chunk.SecurityHeader, ua.AsymmetricAlgorithmHeader)
            chunk.SecurityHeader.SecurityPolicyURI = security_policy.URI
            if security_policy.host_certificate and security_policy.Mode != ua.MessageSecurityMode.None_:
                chunk.SecurityHeader.SenderCertificate = security_policy.host_certificate
                for cert in security_policy.host_certificate_chain:
                    chunk.SecurityHeader.SenderCertificate += cert
            if security_policy.peer_certificate:
                chunk.SecurityHeader.ReceiverCertificateThumbPrint = hashlib.sha1(
                    security_policy.peer_certificate
                ).digest()
            chunk.MessageHeader.ChannelId = channel_id
            chunk.SequenceHeader.RequestId = request_id
            return [chunk]

        crypto = security_policy.symmetric_cryptography
        max_size = MessageChunk.max_body_size(crypto, max_chunk_size)
        if max_size < 1:
            raise ua.UaError(f"A chunk of {max_chunk_size} bytes cannot carry any data")

        chunks = []
        for i in range(0, len(body), max_size):
            part = body[i : i + max_size]
            if i + max_size >= len(body):
                chunk_type = ua.ChunkType.Single
            else:
                chunk_type = ua.ChunkType.Intermediate
            chunk = MessageChunk(crypto, part, message_type, chunk_type)
            assert isinstance(chunk.SecurityHeader, ua.SymmetricAlgorithmHeader)
            chunk.SecurityHeader.TokenId = token_id
            chunk.MessageHeader.ChannelId = channel_id
            chunk.SequenceHeader.RequestId = request_id
            chunks.append(chunk)
        return chunks

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.MessageHeader}, {self.SequenceHeader},"
            f" {self.SecurityHeader}, {len(self.Body)} bytes)"
        )

    __repr__ = __str__


class SecureConnection:
    """
    Common logic for client and server
    """

    def __init__(self, security_policy: SecurityPolicy, limits: TransportLimits) -> None:
        self._sequence_number = 0
        self._peer_sequence_number: int | None = None
        self._incoming_parts: list[MessageChunk] = []
        self._incoming_size = 0
        self.security_policy = security_policy
        self._policies: list[Any] = []
        self._open = False
        self.security_token = ua.ChannelSecurityToken()
        self.next_security_token = ua.ChannelSecurityToken()
        self.prev_security_token = ua.ChannelSecurityToken()
        self.local_nonce: int | bytes = 0
        self.remote_nonce: int | bytes = 0
        self._allow_prev_token = False
        self._limits = limits

    @property
    def limits(self) -> TransportLimits:
        return self._limits

    def set_channel(self, params: Any, request_type: ua.SecurityTokenRequestType, client_nonce: bytes) -> None:
        """
        Called on client side when getting secure channel data from server.
        """
        if request_type == ua.SecurityTokenRequestType.Issue:
            self.security_token = params.SecurityToken
            self.local_nonce = client_nonce
            self.remote_nonce = params.ServerNonce
            self.security_policy.make_local_symmetric_key(self.remote_nonce, self.local_nonce)
            self.security_policy.make_remote_symmetric_key(
                self.local_nonce, self.remote_nonce, self.security_token.RevisedLifetime
            )
            self._open = True
        else:
            self.next_security_token = params.SecurityToken
            self.local_nonce = client_nonce
            self.remote_nonce = params.ServerNonce

        self._allow_prev_token = True

    def open(self, params: Any, server: Any) -> ua.OpenSecureChannelResult:
        """
        Called on server side to open secure channel.
        """

        self.local_nonce = ua.utils.create_nonce(self.security_policy.secure_channel_nonce_length)
        self.remote_nonce = params.ClientNonce
        response = ua.OpenSecureChannelResult()
        response.ServerNonce = self.local_nonce

        if not self._open or params.RequestType == ua.SecurityTokenRequestType.Issue:
            self._open = True
            self.security_token.TokenId = 13  # random value
            self.security_token.ChannelId = server.get_new_channel_id()
            self.security_token.RevisedLifetime = params.RequestedLifetime
            self.security_token.CreatedAt = datetime.now(UTC)

            response.SecurityToken = self.security_token

            self.security_policy.make_local_symmetric_key(self.remote_nonce, self.local_nonce)
            self.security_policy.make_remote_symmetric_key(
                self.local_nonce, self.remote_nonce, self.security_token.RevisedLifetime
            )
        else:
            self.next_security_token = copy.deepcopy(self.security_token)
            self.next_security_token.TokenId += 1
            self.next_security_token.RevisedLifetime = params.RequestedLifetime
            self.next_security_token.CreatedAt = datetime.now(UTC)

            response.SecurityToken = self.next_security_token

        return response

    def close(self) -> None:
        self._open = False

    def is_open(self) -> bool:
        return self._open

    def set_policy_factories(self, policies: list[Any]) -> None:
        """
        Set a list of available security policies.
        Use this in servers with multiple endpoints with different security.
        """
        self._policies = policies

    @staticmethod
    def _policy_matches(policy: Any, uri: str, mode: ua.MessageSecurityMode | None = None) -> bool:
        return policy.URI == uri and (mode is None or policy.Mode == mode)

    def select_policy(
        self, uri: str, peer_certificate: bytes | None, mode: ua.MessageSecurityMode | None = None
    ) -> None:
        for policy in self._policies:
            if policy.matches(uri, mode):
                self.security_policy = policy.create(peer_certificate)
                return
        if self.security_policy.URI != uri or (mode is not None and self.security_policy.Mode != mode):
            raise ua.UaError(f"No matching policy: {uri}, {mode}")

    def revolve_tokens(self) -> None:
        """
        Revolve security tokens of the security channel. Start using the
        next security token negotiated during the renewal of the channel and
        remember the previous token until the other communication party
        """
        self.prev_security_token = self.security_token
        self.security_token = self.next_security_token
        self.next_security_token = ua.ChannelSecurityToken()
        self.security_policy.make_local_symmetric_key(self.remote_nonce, self.local_nonce)
        self.security_policy.make_remote_symmetric_key(
            self.local_nonce, self.remote_nonce, self.security_token.RevisedLifetime
        )

    def message_to_binary(
        self, message: bytes, message_type: ua.MessageType = ua.MessageType.SecureMessage, request_id: int = 0
    ) -> bytes:
        """
        Convert OPC UA secure message to binary.
        The only supported types are SecureOpen, SecureMessage, SecureClose.
        If message_type is SecureMessage, the AlgorithmHeader should be passed as arg.
        """
        if message_type == ua.MessageType.SecureMessage:
            self._check_send_limits(message)
        chunks = MessageChunk.message_to_chunks(
            self.security_policy,
            message,
            self._limits.max_send_buffer,
            message_type=message_type,
            channel_id=self.security_token.ChannelId,
            request_id=request_id,
            token_id=self.security_token.TokenId,
        )
        encoded: list[bytes] = []
        first_sequence_number = self._sequence_number
        for chunk in chunks:
            chunk.SequenceHeader.SequenceNumber = self._next_sequence_number()
            try:
                encoded.append(chunk.to_binary())
            except Exception:
                if not encoded:
                    self._sequence_number = first_sequence_number
                    raise
                self._sequence_number -= 1
                encoded.append(self._abort_chunk(chunk))
                raise MessageAborted(b"".join(encoded)) from None
        return b"".join(encoded)

    def _next_sequence_number(self) -> int:
        self._sequence_number += 1
        if self._sequence_number >= (1 << 32):
            _logger.debug("Wrapping sequence number: %d -> 1", self._sequence_number)
            self._sequence_number = 1
        return self._sequence_number

    def _check_send_limits(self, message: bytes) -> None:
        capacity = MessageChunk.max_body_size(self.security_policy.symmetric_cryptography, self._limits.max_send_buffer)
        if capacity < 1:
            raise ua.UaError(f"A chunk of {self._limits.max_send_buffer} bytes cannot carry any data")
        chunk_count = -(-len(message) // capacity)
        if self._limits.send_max_message_size and len(message) > self._limits.send_max_message_size:
            raise MessageTooLarge(f"Message of {len(message)} bytes exceeds {self._limits.send_max_message_size}")
        if self._limits.send_max_chunk_count and chunk_count > self._limits.send_max_chunk_count:
            raise MessageTooLarge(f"Message of {chunk_count} chunks exceeds {self._limits.send_max_chunk_count}")

    def _abort_chunk(self, failed: MessageChunk) -> bytes:
        error = ua.ErrorMessage(ua.StatusCode(ua.StatusCodes.BadUnexpectedError), "")
        abort = MessageChunk(
            failed.crypto, struct_to_binary(error), failed.MessageHeader.MessageType, ua.ChunkType.Abort
        )
        abort.SecurityHeader = failed.SecurityHeader
        abort.MessageHeader.ChannelId = failed.MessageHeader.ChannelId
        abort.SequenceHeader.RequestId = failed.SequenceHeader.RequestId
        abort.SequenceHeader.SequenceNumber = self._next_sequence_number()
        return abort.to_binary()

    def _check_sym_header(self, security_hdr: ua.SymmetricAlgorithmHeader) -> None:
        """
        Validates the symmetric header of the message chunk and revolves the
        security token if needed.
        """
        if not isinstance(security_hdr, ua.SymmetricAlgorithmHeader):
            raise UaInvalidParameterError(f"Expected SymAlgHeader, got: {type(security_hdr)}")

        if security_hdr.TokenId == self.security_token.TokenId:
            return

        if security_hdr.TokenId == self.next_security_token.TokenId:
            self.revolve_tokens()
            return

        if self._allow_prev_token and security_hdr.TokenId == self.prev_security_token.TokenId:
            # From spec, part 4, section 5.5.2.1: Clients should accept Messages secured by an
            # expired SecurityToken for up to 25 % of the token lifetime. This should ensure that
            # Messages sent by the Server before the token expired are not rejected because of
            # network delays.
            timeout = self.prev_security_token.CreatedAt + timedelta(
                milliseconds=self.prev_security_token.RevisedLifetime * 1.25
            )
            if timeout < datetime.now(UTC):
                raise ua.UaError(
                    f"Security token id {security_hdr.TokenId} has timed out ({timeout} < {datetime.now(UTC)})"
                )
            return

        expected_tokens = [self.security_token.TokenId, self.next_security_token.TokenId]
        if self._allow_prev_token:
            expected_tokens.insert(0, self.prev_security_token.TokenId)
        raise ua.UaError(f"Invalid security token id {security_hdr.TokenId}, expected one of: {expected_tokens}")

    def _check_incoming_chunk(self, chunk: MessageChunk) -> None:
        if not isinstance(chunk, MessageChunk):
            raise ValueError(f"Expected chunk, got: {chunk}")
        if chunk.MessageHeader.MessageType != ua.MessageType.SecureOpen:
            if chunk.MessageHeader.ChannelId != self.security_token.ChannelId:
                raise ua.UaError(
                    f"Wrong channel id {chunk.MessageHeader.ChannelId}, expected {self.security_token.ChannelId}"
                )
        if self._incoming_parts:
            if self._incoming_parts[0].SequenceHeader.RequestId != chunk.SequenceHeader.RequestId:
                raise self._reject_chunk(
                    ua.StatusCodes.BadSecurityChecksFailed,
                    f"Wrong request id {chunk.SequenceHeader.RequestId},"
                    f" expected {self._incoming_parts[0].SequenceHeader.RequestId}",
                )
        # The sequence number must monotonically increase (but it can wrap around)
        seq_num = chunk.SequenceHeader.SequenceNumber
        if self._peer_sequence_number is not None:
            if seq_num != self._peer_sequence_number + 1:
                wrap_limit = (1 << 32) - 1024
                if seq_num < 1024 and self._peer_sequence_number >= wrap_limit:
                    # The sequence number has wrapped around. See spec. part 6, 6.7.2
                    _logger.debug("Sequence number wrapped: %d -> %d", self._peer_sequence_number, seq_num)
                else:
                    # Condition for monotonically increase is not met
                    raise ua.UaError(
                        f"Received chunk: {chunk} with wrong sequence expecting:"
                        f" {self._peer_sequence_number}, received: {seq_num},"
                        f" spec says to close connection"
                    )
        self._peer_sequence_number = seq_num

    def receive_from_header_and_body(self, header: ua.Header, body: Buffer) -> Any:
        """
        Convert MessageHeader and binary body to OPC UA TCP message (see OPC UA
        specs Part 6, 7.1: Hello, Acknowledge or ErrorMessage), or a Message
        object, or None (if intermediate chunk is received)
        """
        if header.MessageType == ua.MessageType.SecureOpen:
            data = body.copy(header.body_size)
            security_header = struct_from_binary(ua.AsymmetricAlgorithmHeader, data)

            if not self.is_open():
                # Only call select_policy if the channel isn't open. Otherwise
                # it will break the Secure channel renewal.
                self.select_policy(security_header.SecurityPolicyURI, security_header.SenderCertificate)

        elif header.MessageType in (ua.MessageType.SecureMessage, ua.MessageType.SecureClose):
            data = body.copy(header.body_size)
            security_header = struct_from_binary(ua.SymmetricAlgorithmHeader, data)
            self._check_sym_header(security_header)

        if header.MessageType in (ua.MessageType.SecureMessage, ua.MessageType.SecureOpen, ua.MessageType.SecureClose):
            try:
                pos = body.cur_pos
                chunk = MessageChunk.from_header_and_body(self.security_policy, header, body, use_prev_key=False)
            except ua.uaerrors.SignatureError:
                body.rewind(cur_pos=pos)
                chunk = MessageChunk.from_header_and_body(self.security_policy, header, body, use_prev_key=True)
            return self._receive(chunk)
        if header.MessageType == ua.MessageType.Hello:
            msg = struct_from_binary(ua.Hello, body)
            return msg
        if header.MessageType == ua.MessageType.Acknowledge:
            msg = struct_from_binary(ua.Acknowledge, body)
            self._limits.update_client_limits(msg)
            return msg
        if header.MessageType == ua.MessageType.Error:
            error = struct_from_binary(ua.ErrorMessage, body)
            if len((error.Reason or "").encode()) > MAX_ERROR_REASON_BYTES:
                error.Reason = ""
            _logger.warning("Received an error: %s", error)
            return error
        raise ua.UaError(f"Unsupported message type {header.MessageType!r}")

    def _drop_incoming_parts(self) -> None:
        self._incoming_parts = []
        self._incoming_size = 0

    def _reject_chunk(self, status: int, reason: str) -> TransportError:
        self._drop_incoming_parts()
        return TransportError(status, reason)

    def _receive(self, msg: MessageChunk) -> ua.Message | AbortedMessage | None:
        header = msg.MessageHeader
        self._check_incoming_chunk(msg)
        if header.ChunkType not in (ua.ChunkType.Single, ua.ChunkType.Intermediate, ua.ChunkType.Abort):
            raise self._reject_chunk(ua.StatusCodes.BadTcpMessageTypeInvalid, "Unsupported chunk type")
        if header.MessageType != ua.MessageType.SecureMessage and header.ChunkType != ua.ChunkType.Single:
            raise self._reject_chunk(ua.StatusCodes.BadSecurityChecksFailed, "Only MSG can have several chunks")
        if self._incoming_parts and self._incoming_parts[0].MessageHeader.MessageType != header.MessageType:
            raise self._reject_chunk(ua.StatusCodes.BadSecurityChecksFailed, "Chunks of different message types")
        if header.ChunkType == ua.ChunkType.Abort:
            aborted = AbortedMessage.from_chunk(msg)
            _logger.warning("Message %s aborted: %s", msg, aborted.error)
            self._drop_incoming_parts()
            return aborted
        if not self._limits.is_msg_size_within_limit(self._incoming_size + len(msg.Body)):
            self._drop_incoming_parts()
            raise MessageSizeExceeded("Message size exceeds the limit")
        self._incoming_parts.append(msg)
        self._incoming_size += len(msg.Body)
        if not self._limits.is_chunk_count_within_limit(len(self._incoming_parts)):
            self._drop_incoming_parts()
            raise MessageSizeExceeded("Chunk count exceeds the limit")
        if header.ChunkType == ua.ChunkType.Intermediate:
            return None
        message = ua.Message(self._incoming_parts)
        self._drop_incoming_parts()
        return message

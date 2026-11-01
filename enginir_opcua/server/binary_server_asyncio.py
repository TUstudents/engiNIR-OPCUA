"""
The TCP side of the server: one OPCUAProtocol per connection (Hello, the inbound queue, timers) and reverse connect.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import urlparse

from .. import ua
from ..common.connection import (
    HELLO_MAX_CHUNK_SIZE,
    FrameReader,
    TransportError,
    TransportLimits,
    error_message_to_binary,
    reverse_hello_to_binary,
)
from ..common.utils import Buffer
from ..crypto.security_policies import SecurityPolicyFactory
from ..ua.ua_binary import struct_from_binary
from ..ua.uaprotocol_hand import SECURE_MESSAGE_TYPES
from .internal_server import InternalServer
from .uaprocessor import UaProcessor, peer_label

_logger = logging.getLogger(__name__)

MAX_REVERSE_BACKOFF_SECONDS = 60.0
REVERSE_QUICK_CLOSE_SECONDS = 1.0


class OPCUAProtocol(asyncio.Protocol):
    """
    One client connection. Frames are checked here (Hello first, sizes, types); secure messages go through a bounded
    queue to the UaProcessor in order. A connection without Hello, without an activated session or without a valid
    security token in time is closed. A reverse connection waits for the client's Hello without these deadlines.
    """

    def __init__(
        self,
        iserver: InternalServer,
        policies: list[SecurityPolicyFactory],
        clients: list[OPCUAProtocol],
        closing_tasks: list[asyncio.Task[Any]],
        limits: TransportLimits,
        reverse: ReverseConnection | None = None,
    ) -> None:
        self.peer_name: Any = None
        self.peer: str = "unknown peer"
        self._close_warned = False
        self.transport: asyncio.Transport | None = None
        self.processor: UaProcessor | None = None
        self._reader = FrameReader(self._max_frame_size)
        self._closed = False
        self._hello_timer: asyncio.TimerHandle | None = None
        self._expiry_timer: asyncio.TimerHandle | None = None
        self.iserver: InternalServer = iserver
        self.policies = policies
        self.clients = clients
        self.closing_tasks = closing_tasks
        self.messages: asyncio.Queue[tuple[ua.Header | None, Buffer | None]] = asyncio.Queue(
            maxsize=iserver.max_pending_messages_per_connection
        )
        self.limits = limits
        self._task: asyncio.Task[Any] | None = None
        self._activation_watchdog_task: asyncio.Task[Any] | None = None
        self.reverse: ReverseConnection | None = reverse
        self.reverse_pending: bool = reverse is not None
        self.reverse_outcome: asyncio.Future[tuple[str, int]] | None = None

    def __str__(self) -> str:
        return f"OPCUAProtocol({self.peer_name})"

    __repr__ = __str__

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.peer_name = transport.get_extra_info("peername")
        self.peer = peer_label(self.peer_name)
        if len(self.clients) >= self.iserver.max_connections and not self._close_oldest_channel_without_session():
            _logger.warning("%s refused: the server has max_connections=%s", self.peer, self.iserver.max_connections)
            self._closed = True
            refused = cast(asyncio.Transport, transport)
            refused.write(error_message_to_binary(ua.StatusCodes.BadTcpNotEnoughResources, "Too many connections"))
            refused.close()
            return
        _logger.info("%s connected", self.peer)
        self.transport = cast(asyncio.Transport, transport)
        self.processor = UaProcessor(self.iserver, self.transport, self.limits)
        self.processor.set_policies(self.policies)
        self.processor.on_token_window = self._schedule_channel_expiry
        self.iserver.asyncio_transports.append(transport)
        self.clients.append(self)
        self._task = asyncio.create_task(self._process_received_message_loop())
        if self.reverse is not None:
            self.reverse_outcome = asyncio.get_running_loop().create_future()
            cast(asyncio.Transport, transport).write(self.reverse.reverse_hello())
            return
        self._hello_timer = asyncio.get_running_loop().call_later(
            self.iserver.hello_timeout_seconds, self._hello_deadline_expired
        )
        self._start_activation_watchdog()

    def _start_activation_watchdog(self) -> None:
        if self.iserver.max_pending_activation_seconds > 0:
            self._activation_watchdog_task = asyncio.create_task(self._activation_watchdog())

    def _close_oldest_channel_without_session(self) -> bool:
        sessions = self.iserver.session_manager
        idle = [
            c
            for c in self.clients
            if c.processor is not None and not c.reverse_pending and not sessions.has_session(c.processor.channel_id)
        ]
        if not idle:
            return False
        oldest = min(idle, key=lambda c: c.processor.last_used if c.processor is not None else 0.0)
        oldest._warn_close("closed to make room: the oldest connection without a session")
        oldest._close()
        return True

    def _schedule_channel_expiry(self, seconds: float) -> None:
        if self._expiry_timer is not None:
            self._expiry_timer.cancel()
        self._expiry_timer = asyncio.get_running_loop().call_later(seconds + 0.05, self._channel_expired)

    def _channel_expired(self) -> None:
        if self.processor is not None and self.processor.channel_expires_in() > 0:
            self._schedule_channel_expiry(self.processor.channel_expires_in())
            return
        self._warn_close("closed: the security token of the channel expired")
        self._close()

    def _hello_deadline_expired(self) -> None:
        if self.processor is not None and not self.processor.hello_received:
            self._warn_close(f"closed: no Hello within {self.iserver.hello_timeout_seconds:g} s")
            self._fail(ua.StatusCodes.BadTimeout, "No Hello received")

    def _warn_close(self, message: str) -> None:
        self._close_warned = True
        _logger.warning("%s %s", self.peer, message)

    def _log_closed(self, ex: BaseException | None) -> None:
        processor_reason = self.processor.close_reason if self.processor is not None else None
        if self._close_warned or (self.processor is not None and self.processor.close_warned):
            _logger.debug("%s closed", self.peer)
        elif processor_reason is not None:
            _logger.info("%s closed (%s)", self.peer, processor_reason)
        elif ex is not None:
            _logger.info("%s closed (connection lost: %s)", self.peer, ex)
        else:
            _logger.info("%s closed (by the client)", self.peer)

    def connection_lost(self, ex: BaseException | None) -> None:
        if self._hello_timer is not None:
            self._hello_timer.cancel()
        if self._expiry_timer is not None:
            self._expiry_timer.cancel()
        self._log_closed(ex)
        if self.reverse_outcome is not None and not self.reverse_outcome.done():
            self.reverse_outcome.set_result(("closed", 0))
        if self.transport is not None:
            self.transport.close()
            self.iserver.asyncio_transports.remove(self.transport)
        if self.processor is not None:
            closing_task = asyncio.create_task(self.processor.close())
            self.closing_tasks.append(closing_task)
        if self in self.clients:
            self.clients.remove(self)
        try:
            self.messages.put_nowait((None, None))
        except asyncio.QueueFull:
            _logger.debug("Inbound queue of %s is full; the message loop is cancelled instead", self.peer_name)
        if self._task is not None:
            self._task.cancel()
        if self._activation_watchdog_task is not None:
            self._activation_watchdog_task.cancel()

    async def _activation_watchdog(self) -> None:
        """Close the transport if the client never activates a session within the grace window."""
        try:
            await asyncio.sleep(self.iserver.max_pending_activation_seconds)
            if self.processor is not None and not self.iserver.session_manager.has_activated_session(
                self.processor.channel_id
            ):
                self._warn_close(
                    f"closed: no session activated within {self.iserver.max_pending_activation_seconds:g} s"
                )
                if self.transport is not None:
                    self.transport.close()
        except asyncio.CancelledError:
            pass
        except Exception:
            _logger.exception("activation watchdog crashed")

    def data_received(self, data: bytes) -> None:
        if self._closed:
            return
        self._reader.feed(data)
        try:
            for header, body in self._reader.frames():
                if not self._dispatch(header, body):
                    return
        except TransportError as e:
            self._warn_close(f"closed: {e.reason} ({ua.StatusCode(e.status).name})")
            self._fail(e.status, e.reason)
        except Exception:
            _logger.exception("Exception raised while parsing message from client")
            self._fail(ua.StatusCodes.BadTcpInternalError)

    def _max_frame_size(self) -> int:
        if self.processor is None:
            return HELLO_MAX_CHUNK_SIZE
        return self.processor.max_receive_chunk_size()

    def _dispatch(self, header: ua.Header, body: Buffer) -> bool:
        assert self.processor is not None and self.transport is not None
        if not self.processor.hello_received:
            if self.reverse_pending and header.MessageType == ua.MessageType.Error:
                self._reverse_refused(body)
                return False
            if header.MessageType != ua.MessageType.Hello:
                raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Hello expected first")
            self.transport.write(self.processor.accept_hello(body))
            self._reverse_used()
            return True
        if header.MessageType == ua.MessageType.Hello:
            raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Hello was already received")
        if header.MessageType == ua.MessageType.Error:
            self._warn_close("closed: the client sent an Error message")
            self._close()
            return False
        if header.MessageType not in SECURE_MESSAGE_TYPES:
            raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Unexpected message type")
        try:
            self.messages.put_nowait((header, body))
        except asyncio.QueueFull:
            self._warn_close(f"closed: more than {self.messages.maxsize} requests waiting")
            self._close()
            return False
        return True

    def _reverse_used(self) -> None:
        if not self.reverse_pending:
            return
        self.reverse_pending = False
        _logger.info(
            "Reverse connection to %s is used: Hello received", self.reverse.client_url if self.reverse else ""
        )
        if self.reverse_outcome is not None and not self.reverse_outcome.done():
            self.reverse_outcome.set_result(("used", 0))
        self._start_activation_watchdog()

    def _reverse_refused(self, body: Buffer) -> None:
        try:
            error = struct_from_binary(ua.ErrorMessage, body)
            status = error.Error.value if error.Error is not None else ua.StatusCodes.BadUnexpectedError
            reason = error.Reason
        except Exception:
            status, reason = ua.StatusCodes.BadUnexpectedError, ""
        _logger.warning(
            "The client %s refused the reverse connection: %s (%s)",
            self.reverse.client_url if self.reverse else "",
            reason,
            ua.StatusCode(status),
        )
        if self.reverse_outcome is not None and not self.reverse_outcome.done():
            self.reverse_outcome.set_result(("error", status))
        self._close()

    def _close(self) -> None:
        self._closed = True
        self._reader.buffer.clear()
        if self.transport is not None:
            self.transport.close()

    def _fail(self, status: int, reason: str = "") -> None:
        if self._closed:
            return
        if self.transport is not None:
            self.transport.write(error_message_to_binary(status, reason))
        self._close()

    async def _process_received_message_loop(self) -> None:
        """
        Take message from the queue and try to process it.
        """
        while True:
            header, buf = await self.messages.get()
            if header is None or buf is None:
                break
            try:
                if not await self._process_one_msg(header, buf):
                    break
            except Exception:
                _logger.exception("Exception raised while processing message from client")

    async def _process_one_msg(self, header: ua.Header, buf: Buffer) -> bool:
        _logger.debug("_process_received_message %s %s", header.body_size, len(buf))
        if self.processor is None:
            return True
        ret = await self.processor.process(header, buf)
        if not ret:
            _logger.debug("%s: the secure channel ended, closing the connection", self.peer)
            if self.transport is not None:
                self.transport.close()
            return False
        return True


class BinaryServer:
    """The listening socket of the server, its connections and its reverse connections."""

    def __init__(
        self,
        internal_server: InternalServer,
        hostname: str,
        port: int,
        limits: TransportLimits,
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self.hostname = hostname
        self.port = port
        self.iserver: InternalServer = internal_server
        self._server: asyncio.AbstractServer | None = None
        self._policies: list[SecurityPolicyFactory] = []
        self.clients: list[OPCUAProtocol] = []
        self.closing_tasks: list[asyncio.Task[Any]] = []
        self.cleanup_task: asyncio.Task[Any] | None = None
        self.limits = limits
        self.reverse_connections: list[ReverseConnection] = []
        self._started = False

    def set_policies(self, policies: list[SecurityPolicyFactory]) -> None:
        """The security policies of the endpoints, for the connections made from now on."""
        self._policies = policies

    def _make_protocol(self, reverse: ReverseConnection | None = None) -> OPCUAProtocol:
        """Protocol Factory"""
        return OPCUAProtocol(
            iserver=self.iserver,
            policies=self._policies,
            clients=self.clients,
            closing_tasks=self.closing_tasks,
            limits=self.limits,
            reverse=reverse,
        )

    def add_reverse_connection(self, connection: ReverseConnection) -> None:
        """Keep a reverse connection to a client open; it starts now if the server runs. ValueError for a duplicate."""
        if any(
            c.client_url == connection.client_url and c.endpoint_url == connection.endpoint_url
            for c in self.reverse_connections
        ):
            raise ValueError(f"Reverse connection to {connection.client_url} exists")
        connection.bserver = self
        self.reverse_connections.append(connection)
        if self._started:
            connection.start()

    def remove_reverse_connection(self, connection: ReverseConnection) -> None:
        """Stop a reverse connection; its open socket stays until it closes."""
        self.reverse_connections.remove(connection)
        connection.stop()

    async def start(self) -> None:
        """Listen; with port 0 the port the system picked (one socket) is stored in port and hostname."""
        self._server = await asyncio.get_running_loop().create_server(self._make_protocol, self.hostname, self.port)
        if self.port == 0 and len(self._server.sockets) == 1:
            sockname = self._server.sockets[0].getsockname()
            self.hostname = sockname[0]
            self.port = sockname[1]
        self.logger.info("Listening on %s:%s", self.hostname, self.port)
        self.cleanup_task = asyncio.create_task(self._close_task_loop())
        self._started = True
        for connection in self.reverse_connections:
            connection.start()

    async def stop(self) -> None:
        """Stop the reverse connections, close every connection, wait for their cleanup and stop listening."""
        self.logger.info("Closing asyncio socket server")
        self._started = False
        for connection in self.reverse_connections:
            connection.stop()
        for transport in self.iserver.asyncio_transports:
            transport.close()
        if self.cleanup_task is not None:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass

        await self._close_tasks()

        if self._server:
            asyncio.get_running_loop().call_soon(self._server.close)
            await self._server.wait_closed()

    async def _close_task_loop(self) -> None:
        while True:
            await self._close_tasks()
            await asyncio.sleep(10)

    async def _close_tasks(self) -> None:
        while self.closing_tasks:
            task = self.closing_tasks.pop()
            try:
                await task
            except Exception:
                _logger.exception("Unexpected crash in BinaryServer._close_tasks")


class ReverseConnection:
    """
    One target of reverse connect (OPC 10000-6 v1.05, 7.1.2.6 and 7.1.3): the server opens the TCP connection to a
    listening client, sends a ReverseHello and then serves the Hello of the client like on any other connection.
    One pending socket, which has not received a Hello, is kept at all times; when it is used the next one is opened.
    """

    def __init__(
        self,
        client_url: str,
        endpoint_url: str | Callable[[], str],
        server_uri: str | Callable[[], str],
        retry_interval: float = 5.0,
        connect_timeout: float = 5.0,
    ) -> None:
        parsed = urlparse(client_url)
        if parsed.scheme != "opc.tcp" or not parsed.hostname or not parsed.port:
            raise ValueError(f"The client URL must be opc.tcp://host:port, not {client_url!r}")
        if not 0.1 <= retry_interval <= 3600:
            raise ValueError("retry_interval must be between 0.1 and 3600 seconds")
        self.client_url = client_url
        self._host: str = parsed.hostname
        self._port: int = parsed.port
        self._endpoint_url = endpoint_url
        self._server_uri = server_uri
        self.retry_interval = retry_interval
        self.connect_timeout = connect_timeout
        self.bserver: BinaryServer | None = None
        self._task: asyncio.Task[None] | None = None
        reverse_hello_to_binary(self.server_uri, self.endpoint_url)

    @property
    def endpoint_url(self) -> str:
        """The EndpointUrl announced in the ReverseHello."""
        return self._endpoint_url() if callable(self._endpoint_url) else self._endpoint_url

    @property
    def server_uri(self) -> str:
        """The ServerUri announced in the ReverseHello."""
        return self._server_uri() if callable(self._server_uri) else self._server_uri

    def reverse_hello(self) -> bytes:
        """The ReverseHello message to send on a new socket."""
        return reverse_hello_to_binary(self.server_uri, self.endpoint_url)

    def start(self) -> None:
        """Start keeping a socket open to the client."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    def stop(self) -> None:
        """Stop opening sockets to the client."""
        if self._task is not None:
            self._task.cancel()
            self._task = None

    def _delay(self, base: float, failures: int) -> float:
        delay = min(base * 2 ** max(failures - 1, 0), MAX_REVERSE_BACKOFF_SECONDS)
        return delay * random.uniform(0.8, 1.2)

    async def _run(self) -> None:
        assert self.bserver is not None
        bserver = self.bserver
        loop = asyncio.get_running_loop()
        failures = 0
        while True:
            if len(bserver.clients) >= bserver.iserver.max_connections:
                await asyncio.sleep(self.retry_interval)
                continue
            started = time.monotonic()
            try:
                _, protocol = await asyncio.wait_for(
                    loop.create_connection(lambda: bserver._make_protocol(self), self._host, self._port),
                    self.connect_timeout,
                )
            except (OSError, TimeoutError) as error:
                failures += 1
                _logger.warning("Reverse connection to %s failed: %s", self.client_url, error)
                await asyncio.sleep(self._delay(self.retry_interval, failures))
                continue
            assert protocol.reverse_outcome is not None
            outcome, status = await protocol.reverse_outcome
            if outcome == "used":
                failures = 0
            elif outcome == "error":
                wait = self.retry_interval * (2 if status == ua.StatusCodes.BadServerTooBusy else 1)
                await asyncio.sleep(wait)
            elif time.monotonic() - started < REVERSE_QUICK_CLOSE_SECONDS:
                await asyncio.sleep(self.retry_interval)

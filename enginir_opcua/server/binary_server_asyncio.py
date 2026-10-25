"""
Socket server forwarding request to internal server
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, cast

from .. import ua
from ..common.connection import (
    HELLO_MAX_CHUNK_SIZE,
    FrameReader,
    TransportError,
    TransportLimits,
    error_message_to_binary,
)
from ..common.utils import Buffer
from ..ua.uaprotocol_hand import SECURE_MESSAGE_TYPES
from .internal_server import InternalServer
from .uaprocessor import UaProcessor

_logger = logging.getLogger(__name__)


class OPCUAProtocol(asyncio.Protocol):
    """
    Instantiated for every connection.
    """

    def __init__(
        self,
        iserver: InternalServer,
        policies: list[Any],
        clients: list[OPCUAProtocol],
        closing_tasks: list[asyncio.Task[Any]],
        limits: TransportLimits,
    ) -> None:
        self.peer_name: Any = None
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
        self.messages: asyncio.Queue[tuple[Any, Any]] = asyncio.Queue(
            maxsize=iserver.max_pending_messages_per_connection
        )
        self.limits = limits
        self._task: asyncio.Task[Any] | None = None
        self._activation_watchdog_task: asyncio.Task[Any] | None = None

    def __str__(self) -> str:
        return f"OPCUAProtocol({self.peer_name}, {self.processor.session})"  # type: ignore[union-attr]

    __repr__ = __str__

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.peer_name = transport.get_extra_info("peername")
        if len(self.clients) >= self.iserver.max_connections:
            _logger.warning(
                "Refusing connection from %s: at max_connections=%s",
                self.peer_name,
                self.iserver.max_connections,
            )
            self._closed = True
            refused = cast(asyncio.Transport, transport)
            refused.write(error_message_to_binary(ua.StatusCodes.BadTcpNotEnoughResources, "Too many connections"))
            refused.close()
            return
        _logger.info("New connection from %s", self.peer_name)
        self.transport = transport  # type: ignore[assignment]
        self.processor = UaProcessor(self.iserver, self.transport, self.limits)
        self.processor.set_policies(self.policies)
        self.processor.on_token_window = self._schedule_channel_expiry
        self.iserver.asyncio_transports.append(transport)
        self.clients.append(self)
        self._task = asyncio.create_task(self._process_received_message_loop())
        self._hello_timer = asyncio.get_running_loop().call_later(
            self.iserver.hello_timeout_seconds, self._hello_deadline_expired
        )
        if self.iserver.max_pending_activation_seconds > 0:
            self._activation_watchdog_task = asyncio.create_task(self._activation_watchdog())

    def _schedule_channel_expiry(self, seconds: float) -> None:
        if self._expiry_timer is not None:
            self._expiry_timer.cancel()
        self._expiry_timer = asyncio.get_running_loop().call_later(seconds + 0.05, self._channel_expired)

    def _channel_expired(self) -> None:
        if self.processor is not None and self.processor.channel_expires_in() > 0:
            self._schedule_channel_expiry(self.processor.channel_expires_in())
            return
        _logger.warning("Closing connection from %s: no valid security token", self.peer_name)
        self._close()

    def _hello_deadline_expired(self) -> None:
        if self.processor is not None and not self.processor.hello_received:
            _logger.warning("Closing connection from %s: no Hello received", self.peer_name)
            self._fail(ua.StatusCodes.BadTimeout, "No Hello received")

    def connection_lost(self, ex: BaseException | None) -> None:
        if self._hello_timer is not None:
            self._hello_timer.cancel()
        if self._expiry_timer is not None:
            self._expiry_timer.cancel()
        _logger.info("Lost connection from %s, %s", self.peer_name, ex)
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
            # Queue is already saturated; the cancel below will tear the loop down.
            pass
        if self._task is not None:
            self._task.cancel()
        if self._activation_watchdog_task is not None:
            self._activation_watchdog_task.cancel()

    async def _activation_watchdog(self) -> None:
        """Close the transport if the client never activates a session within the grace window."""
        try:
            await asyncio.sleep(self.iserver.max_pending_activation_seconds)
            if self.processor is not None and (
                self.processor.session is None or not self.processor.session.is_activated()
            ):
                _logger.warning(
                    "Closing idle connection from %s: no ActivateSession within %.1fs",
                    self.peer_name,
                    self.iserver.max_pending_activation_seconds,
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
            _logger.warning("Closing connection from %s: %s (%s)", self.peer_name, e.reason, ua.StatusCode(e.status))
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
            if header.MessageType != ua.MessageType.Hello:
                raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Hello expected first")
            self.transport.write(self.processor.accept_hello(body))
            return True
        if header.MessageType == ua.MessageType.Hello:
            raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Hello was already received")
        if header.MessageType == ua.MessageType.Error:
            _logger.warning("Received an Error message from %s, closing", self.peer_name)
            self._close()
            return False
        if header.MessageType not in SECURE_MESSAGE_TYPES:
            raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Unexpected message type")
        try:
            self.messages.put_nowait((header, body))
        except asyncio.QueueFull:
            _logger.warning(
                "Inbound queue full for %s (max=%s); closing connection", self.peer_name, self.messages.maxsize
            )
            self._close()
            return False
        return True

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
            if header is None and buf is None:
                # Connection was closed, end task
                break
            try:
                if not await self._process_one_msg(header, buf):
                    break
            except Exception:
                _logger.exception("Exception raised while processing message from client")

    async def _process_one_msg(self, header: Any, buf: Buffer) -> bool:
        _logger.debug("_process_received_message %s %s", header.body_size, len(buf))
        if self.processor is None:
            return True
        ret = await self.processor.process(header, buf)
        if not ret:
            _logger.info("processor returned False, we close connection from %s", self.peer_name)
            if self.transport is not None:
                self.transport.close()
            return False
        return True


class BinaryServer:
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
        self._policies: list[Any] = []
        self.clients: list[OPCUAProtocol] = []
        self.closing_tasks: list[asyncio.Task[Any]] = []
        self.cleanup_task: asyncio.Task[Any] | None = None
        self.limits = limits

    def set_policies(self, policies: list[Any]) -> None:
        self._policies = policies

    def _make_protocol(self) -> OPCUAProtocol:
        """Protocol Factory"""
        return OPCUAProtocol(
            iserver=self.iserver,
            policies=self._policies,
            clients=self.clients,
            closing_tasks=self.closing_tasks,
            limits=self.limits,
        )

    async def start(self) -> None:
        self._server = await asyncio.get_running_loop().create_server(self._make_protocol, self.hostname, self.port)
        # get the port and the hostname from the created server socket
        # only relevant for dynamic port asignment (when self.port == 0)
        if self.port == 0 and len(self._server.sockets) == 1:
            # will work for AF_INET and AF_INET6 socket names
            # these are to only families supported by the create_server call
            sockname = self._server.sockets[0].getsockname()
            self.hostname = sockname[0]
            self.port = sockname[1]
        self.logger.info("Listening on %s:%s", self.hostname, self.port)
        self.cleanup_task = asyncio.create_task(self._close_task_loop())

    async def stop(self) -> None:
        self.logger.info("Closing asyncio socket server")
        for transport in self.iserver.asyncio_transports:
            transport.close()

        # stop cleanup process and run it a last time
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

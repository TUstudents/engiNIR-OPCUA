"""Building blocks for tests that act as a misbehaving peer.

The fixtures that use them are in conftest.py: raw_peer, tampered_responses and two_sessions.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.server.internal_server import InternalServer
from enginir_opcua.ua.ua_binary import struct_from_binary, uatcp_to_binary

CONNECTION_PROTOCOL_HEADER = struct.Struct("<3scI")
EXAMPLES = Path(__file__).parent.parent / "examples"


class RawPeer:
    """A UA-TCP peer that sends hand-made bytes and reads raw replies (Part 6, 7.1)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    @classmethod
    async def connect(cls, host: str, port: int) -> RawPeer:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer)

    async def send(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def send_hello(self, hello: ua.Hello) -> None:
        await self.send(uatcp_to_binary(ua.MessageType.Hello, hello))

    async def send_message(
        self, message_type: bytes, body: bytes, chunk_type: bytes = b"F", size: int | None = None
    ) -> None:
        announced = CONNECTION_PROTOCOL_HEADER.size + len(body) if size is None else size
        await self.send(CONNECTION_PROTOCOL_HEADER.pack(message_type, chunk_type, announced) + body)

    async def receive(self, timeout: float = 5.0) -> tuple[bytes, bytes]:
        header = await asyncio.wait_for(self._reader.readexactly(CONNECTION_PROTOCOL_HEADER.size), timeout)
        message_type, _, message_size = CONNECTION_PROTOCOL_HEADER.unpack(header)
        body = await asyncio.wait_for(self._reader.readexactly(message_size - CONNECTION_PROTOCOL_HEADER.size), timeout)
        return message_type, body

    async def receive_acknowledge(self, timeout: float = 5.0) -> ua.Acknowledge:
        message_type, body = await self.receive(timeout)
        if message_type != ua.MessageType.Acknowledge:
            raise AssertionError(f"expected an Acknowledge, got {message_type!r}")
        return struct_from_binary(ua.Acknowledge, Buffer(body))

    async def receive_error(self, timeout: float = 5.0) -> ua.ErrorMessage:
        message_type, body = await self.receive(timeout)
        if message_type != ua.MessageType.Error:
            raise AssertionError(f"expected an Error, got {message_type!r}")
        return struct_from_binary(ua.ErrorMessage, Buffer(body))

    async def receive_hello(self, timeout: float = 5.0) -> ua.Hello:
        message_type, body = await self.receive(timeout)
        if message_type != ua.MessageType.Hello:
            raise AssertionError(f"expected a Hello, got {message_type!r}")
        return struct_from_binary(ua.Hello, Buffer(body))

    async def send_acknowledge(self, acknowledge: ua.Acknowledge) -> None:
        await self.send(uatcp_to_binary(ua.MessageType.Acknowledge, acknowledge))

    async def is_closed_by_peer(self, timeout: float = 5.0) -> bool:
        try:
            return await asyncio.wait_for(self._reader.read(1), timeout) == b""
        except (ConnectionResetError, TimeoutError):
            return False

    async def close(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except ConnectionResetError:
            pass


class RawServer:
    """A listening socket that hands the first connection of a client under test to the test as a RawPeer."""

    def __init__(self, server: asyncio.Server, connected: asyncio.Future[RawPeer], port: int) -> None:
        self._server = server
        self._connected = connected
        self.host = "127.0.0.1"
        self.port = port

    @classmethod
    async def start(cls) -> RawServer:
        connected: asyncio.Future[RawPeer] = asyncio.get_running_loop().create_future()

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if not connected.done():
                connected.set_result(RawPeer(reader, writer))

        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        return cls(server, connected, server.sockets[0].getsockname()[1])

    @property
    def url(self) -> str:
        return f"opc.tcp://{self.host}:{self.port}"

    async def accept(self, timeout: float = 5.0) -> RawPeer:
        return await asyncio.wait_for(self._connected, timeout)

    async def close(self) -> None:
        if self._connected.done():
            await self._connected.result().close()
        self._server.close()


async def connect_client(raw_server: RawServer, acknowledge: ua.Acknowledge | None = None) -> tuple[UaClient, RawPeer]:
    """Connects a UaClient to the raw_server and completes the handshake with the given Acknowledge."""
    uaclient = UaClient(timeout=1)
    await uaclient.connect_socket(raw_server.host, raw_server.port)
    hello_task = asyncio.create_task(uaclient.send_hello(raw_server.url))
    peer = await raw_server.accept()
    await peer.receive_hello()
    await peer.send_acknowledge(acknowledge or ua.Acknowledge(ReceiveBufferSize=65535, SendBufferSize=65535))
    await hello_task
    return uaclient, peer


ResponseTamper = Callable[[Any], None]


class ResponseTampering:
    """Changes server responses of a given type just before they are encoded."""

    def __init__(self) -> None:
        self._tampers: dict[type, ResponseTamper] = {}

    def on(self, response_type: type, tamper: ResponseTamper) -> None:
        self._tampers[response_type] = tamper

    def apply(self, response: Any) -> None:
        tamper = self._tampers.get(type(response))
        if tamper is not None:
            tamper(response)


TWO_SESSION_USERS = {"alice": "alice-password", "bob": "bob-password"}


class TwoUserManager:
    def get_user(
        self,
        iserver: InternalServer,
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        if username is not None and TWO_SESSION_USERS.get(username) == password:
            return User(role=UserRole.User, name=username)
        return None


@dataclass
class TwoSessions:
    server: Server
    alice: Client
    bob: Client


async def signing_client(server: Server, user: str = "alice") -> Client:
    """A client for the signing_server fixture: Basic256Sha256, Sign, logged in as one of TWO_SESSION_USERS."""
    client = Client(server.endpoint.geturl())
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        str(EXAMPLES / "certificates" / "peer-certificate-example-1.der"),
        str(EXAMPLES / "certificates" / "peer-private-key-example-1.pem"),
        None,
        str(EXAMPLES / "certificate-example.der"),
        ua.MessageSecurityMode.Sign,
    )
    client.set_user(user)
    client.set_password(TWO_SESSION_USERS[user])
    return client

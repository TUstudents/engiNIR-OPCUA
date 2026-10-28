"""
UDP transport of PubSub (OPC 10000-14 v1.05, 7.3.2): unicast, multicast and broadcast datagrams carrying UADP
NetworkMessages. Not implemented: DTLS, discovery addresses.
"""

import asyncio
import contextlib
import logging
import socket
import struct
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import InitVar, dataclass
from ipaddress import ip_address
from typing import Any, Self
from urllib.parse import urlparse

from ..common.utils import Buffer
from ..ua import KeyValuePair
from ..ua.uaerrors import UaError
from ..ua.uaprotocol_auto import (
    NetworkAddressUrlDataType,
    PubSubConnectionDataType,
)
from ..ua.uatypes import (
    QualifiedName,
    TypeRegistry,
    Variant,
    VariantType,
)
from .protocols import PubSubReceiver
from .uadp import (
    PublisherIdValue,
    UadpNetworkMessage,
    UadpSkip,
    decode_network_message,
    has_security_header,
    publisher_id_from_variant,
)
from .utils import RateLimitedLog

logger = logging.getLogger(__name__)

DEFAULT_PORT = 4840
DEFAULT_QUEUE_SIZE = 256
BROADCAST = "255.255.255.255"
_ANY = socket.inet_aton("0.0.0.0")


def _get_address_adapter(address: NetworkAddressUrlDataType) -> tuple[tuple[str | None, int], str | None]:
    addr = None
    if address.NetworkInterface is not None:
        addr = address.NetworkInterface
    url = urlparse(str(address.Url))
    return (url.hostname, url.port if url.port is not None else DEFAULT_PORT), addr


def parse_url(url: str) -> tuple[str, int]:
    """Host and port of an opc.udp URL; IPv6 hosts are written in brackets"""
    parsed = urlparse(url)
    if parsed.hostname is None:
        raise UaError(f"No host in the PubSub address {url!r}")
    return parsed.hostname, parsed.port if parsed.port is not None else DEFAULT_PORT


def format_url(host: str, port: int) -> str:
    return f"opc.udp://[{host}]:{port}" if ":" in host else f"opc.udp://{host}:{port}"


def _is_ip(text: str | None) -> bool:
    if not text:
        return False
    try:
        ip_address(text)
    except ValueError:
        return False
    return True


def resolve_interface(interface: str | None, family: int) -> tuple[str | None, int]:
    """The IP address and the interface index a NetworkInterface names (6.2.7.5.3): an IP address of the socket's
    family, or an interface name. An empty value means the system default."""
    if not interface:
        return None, 0
    if _is_ip(interface):
        version = ip_address(interface).version
        if (family == socket.AF_INET6) != (version == 6):
            raise UaError(f"NetworkInterface {interface} is an IPv{version} address and the connection address isn't")
        return interface, 0
    try:
        return None, socket.if_nametoindex(interface)
    except OSError as e:
        raise UaError(f"NetworkInterface {interface} is neither an IP address nor an interface name") from e


@dataclass
class UdpSettings:
    """
    settings for the udp layer
    """

    Addr: tuple[str, int] = None  # Address, Port
    Reuse: bool = True  # Reuse Port
    TTL: int | None = None  # Sets the time to live for UDP
    Loopback: bool = True  # Sends Messages to loopback
    Adapter: tuple[str | None, int] = None  # NetworkInterface (IP address or name) and the receive port
    Url: InitVar[str] = None  # Url to generate the addr

    def __post_init__(self, Url: str) -> None:
        if Url is not None:
            self.Addr = parse_url(Url)
        if self.Adapter is None:
            self.Adapter = (None, self.Addr[1])

    @classmethod
    def from_cfg(cls, cfg: PubSubConnectionDataType) -> Self:
        addr, adpater = _get_address_adapter(cfg.Address)
        s = cls(addr, Adapter=(adpater, addr[1]))
        s.set_key_value(cfg.ConnectionProperties)
        return s

    def get_address(self) -> NetworkAddressUrlDataType:
        adapter = "" if self.Adapter[0] is None else self.Adapter[0]
        return NetworkAddressUrlDataType(adapter, format_url(self.Addr[0], self.Addr[1]))

    def set_key_value(self, kvs: list[KeyValuePair] | None) -> None:
        if kvs is not None:
            for kv in kvs:
                key = kv.Key.Name
                value = kv.Value
                if key == "ttl":
                    self.TTL = value.Value
                if key == "loopback" and value.VariantType == VariantType.Boolean:
                    self.Loopback = value.Value
                if key == "reuse" and value.VariantType == VariantType.Boolean:
                    self.Reuse = value.Value

    def get_key_value(self) -> list[KeyValuePair]:
        kvs = []
        if self.TTL is not None:
            kvs.append(KeyValuePair(QualifiedName("ttl"), Variant(self.TTL)))
        kvs.append(KeyValuePair(QualifiedName("reuse"), Variant(self.Reuse)))
        kvs.append(KeyValuePair(QualifiedName("loopback"), Variant(self.Loopback)))
        return kvs

    def is_multicast(self) -> bool:
        host = self.Addr[0]
        return _is_ip(host) and ip_address(host).is_multicast

    def _resolve(self) -> tuple[int, int, int, tuple[Any, ...]]:
        host, port = self.Addr
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
        wanted = socket.AF_INET6 if ":" in host else socket.AF_INET
        family, typ, proto, _, addr = next((i for i in infos if i[0] == wanted), infos[0])
        return family, typ, proto, addr

    def _local_address(self, family: int, addr: tuple[Any, ...], interface_ip: str | None, ifindex: int) -> tuple:
        port = self.Adapter[1]
        any_address = "::" if family == socket.AF_INET6 else "0.0.0.0"
        if self.is_multicast():
            if sys.platform == "win32":
                return (any_address, port)
            return (addr[0], port, 0, ifindex) if family == socket.AF_INET6 else (addr[0], port)
        if addr[0] == BROADCAST:
            return (any_address, port)
        if interface_ip is not None:
            return (interface_ip, port)
        if self.Adapter[0]:
            raise UaError(f"A unicast subscriber needs an IP address as NetworkInterface, not {self.Adapter[0]!r}")
        if _is_ip(self.Addr[0]):
            return (addr[0], port)
        return ("::1", port) if family == socket.AF_INET6 else ("127.0.0.1", port)

    def create_socket(self, receive: bool = True) -> tuple[socket.socket, tuple[Any, ...], tuple[Any, ...] | None]:
        """
        Creates the datagram socket: its destination address, and the address it is bound to when it receives. A
        multicast receiver joins the group on the configured NetworkInterface and binds to the group address; a
        unicast receiver binds to the NetworkInterface, or the address of the URL, or loopback for a host name.
        All interfaces are used only when 0.0.0.0 or :: is configured explicitly (7.3.2.2, 7.3.2.3).
        """
        family, typ, proto, addr = self._resolve()
        interface_ip, ifindex = resolve_interface(self.Adapter[0], family)
        sock = socket.socket(family, typ, proto)
        try:
            if self.Reuse:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET:
                self._configure_ipv4(sock, addr, interface_ip, ifindex, receive)
            else:
                self._configure_ipv6(sock, addr, ifindex, receive)
            sock.setblocking(False)
            local = None
            if receive:
                local = self._local_address(family, addr, interface_ip, ifindex)
                try:
                    sock.bind(local)
                except OSError as e:
                    raise UaError(f"Can't bind the PubSub receive address {local[0]}:{local[1]}: {e}") from e
        except BaseException:
            sock.close()
            raise
        return sock, addr, local

    def _configure_ipv4(
        self, sock: socket.socket, addr: tuple[Any, ...], interface_ip: str | None, ifindex: int, receive: bool
    ) -> None:
        if addr[0] == BROADCAST:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, int(self.Loopback))
        if self.TTL is not None:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.TTL)
        if not self.is_multicast():
            return
        group = socket.inet_aton(addr[0])
        if interface_ip is not None:
            interface = socket.inet_aton(interface_ip)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface)
            membership = struct.pack("=4s4s", group, interface)
        elif ifindex:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, struct.pack("=4s4si", _ANY, _ANY, ifindex))
            membership = struct.pack("=4s4si", group, _ANY, ifindex)
        else:
            membership = struct.pack("=4s4s", group, _ANY)
        if receive:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)

    def _configure_ipv6(self, sock: socket.socket, addr: tuple[Any, ...], ifindex: int, receive: bool) -> None:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, int(self.Loopback))
        if self.TTL is not None:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, self.TTL)
        if not self.is_multicast():
            return
        if ifindex:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
        if receive:
            membership = struct.pack("=16si", socket.inet_pton(socket.AF_INET6, addr[0]), ifindex)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)


class OpcUdp(asyncio.DatagramProtocol):
    """
    The datagram protocol of a connection. Received datagrams go through one bounded queue and one task that decodes
    them and calls the receiver in arrival order; datagrams that don't fit are dropped and counted.
    """

    def __init__(
        self,
        cfg: UdpSettings,
        receiver: PubSubReceiver | None,
        publisher_id: Variant,
        types: TypeRegistry | None = None,
        queue_size: int = DEFAULT_QUEUE_SIZE,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self.receiver = receiver
        self.publisher_id = publisher_id_from_variant(publisher_id)
        self.types = types
        self.counters: Counter[str] = Counter()
        self.destination: tuple[Any, ...] = cfg.Addr
        self._queue: asyncio.Queue[tuple[bytes, Any]] = asyncio.Queue(maxsize=queue_size)
        self._task: asyncio.Task[None] | None = None
        self._log = RateLimitedLog(logger)

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        self.transport: asyncio.transports.DatagramTransport = transport  # type: ignore[assignment]
        self._ensure_consumer()

    def _ensure_consumer(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._consume())

    def datagram_received(self, data: bytes, source: tuple[str, int]) -> None:
        self.counters["received"] += 1
        if self.receiver is None:
            self._log.warning("no-receiver", "No receiver set, dropping UADP message")
            return
        self._ensure_consumer()
        try:
            self._queue.put_nowait((data, source))
        except asyncio.QueueFull:
            self.counters["queue_full"] += 1
            self._log.warning("queue-full", "The PubSub receive queue is full, dropping datagram from %s", source)

    async def _consume(self) -> None:
        while True:
            data, source = await self._queue.get()
            try:
                await self._dispatch(data, source)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.counters["receiver_errors"] += 1
                self._log.warning("receiver", "A PubSub receiver failed for a message from %s: %r", source, e)
                logger.debug("PubSub receiver failure", exc_info=True)

    async def _dispatch(self, data: bytes, source: Any) -> None:
        if has_security_header(data):
            self.counters["skipped: SecurityHeader"] += 1
            logger.debug(
                "Dropping UADP message with a SecurityHeader from %s: PubSub security is not supported", source
            )
            return
        logger.debug("Received Datagram from %s - %s", source, data)
        try:
            msg = decode_network_message(Buffer(data, types=self.types))
        except Exception as e:
            self.counters["malformed"] += 1
            self._log.warning("malformed", "Dropping a malformed UADP datagram from %s: %s", source, e)
            logger.debug("Malformed UADP datagram", exc_info=True)
            return
        if isinstance(msg, UadpSkip):
            self.counters[f"skipped: {msg.reason}"] += 1
            logger.debug("Skipping UADP message from %s: %s", source, msg.reason)
            return
        if self.receiver is not None:
            await self.receiver.got_uadp(msg)

    async def close(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    @contextlib.contextmanager
    def _encoding(self) -> Iterator[None]:
        if self.types is None:
            yield
        else:
            with self.types.encoding():
                yield

    def send_uadp(
        self, msgs: list[UadpNetworkMessage], destination: tuple[Any, ...] | None = None, max_size: int = 0
    ) -> list[int]:
        """Sends the messages and returns the sizes of those that were left out because they are larger than
        `max_size` (6.2.5.5); 0 means no limit"""
        target = destination if destination is not None else self.destination
        oversize: list[int] = []
        for msg in msgs:
            logger.debug("Sending UadpMsg %s", msg)
            with self._encoding():
                data = msg.to_binary()
            if max_size and len(data) > max_size:
                self.counters["oversize"] += 1
                oversize.append(len(data))
                continue
            self.transport.sendto(data, target)
            self.counters["sent"] += 1
        return oversize

    async def resolve_destination(self, url: str) -> tuple[Any, ...]:
        """The socket address of an opc.udp URL, resolved once so that sending never waits for a name server"""
        host, port = parse_url(url)
        wanted = socket.AF_INET6 if ":" in host else socket.AF_INET
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        return next((i for i in infos if i[0] == wanted), infos[0])[4]

    def set_destination(self, destination: tuple[Any, ...]) -> None:
        self.destination = destination

    def set_receiver(self, receiver: PubSubReceiver) -> None:
        self.receiver = receiver

    def get_publisher_id(self) -> PublisherIdValue | None:
        """
        Returns the publisher id for creating messages
        """
        return self.publisher_id

import asyncio
import logging
import socket
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.pubsub import udp as udp_module
from enginir_opcua.pubsub.uadp import UadpDataSetMessageHeader, UadpDataSetVariant, UadpHeader, UadpNetworkMessage
from enginir_opcua.pubsub.udp import OpcUdp, UdpSettings
from enginir_opcua.ua.uatypes import Int32, UInt16, Variant


def _message(value: int = 1) -> bytes:
    payload = UadpDataSetVariant(UadpDataSetMessageHeader(), [Variant(Int32(value))])
    return UadpNetworkMessage(UadpHeader(UInt16(1)), DataSetPayloadHeader=[UInt16(5)], Payload=[payload]).to_binary()


class _Transport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, Any]] = []

    def sendto(self, data: bytes, addr: Any) -> None:
        self.sent.append((data, addr))

    def close(self) -> None:
        pass


class _Receiver:
    def __init__(self, delay: float = 0.0, fail: bool = False) -> None:
        self.values: list[int] = []
        self.delay = delay
        self.fail = fail

    async def got_uadp(self, msg: UadpNetworkMessage) -> None:
        await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("receiver failed")
        assert isinstance(msg.Payload, list)
        self.values.append(msg.Payload[0].Data[0].Value)  # type: ignore[attr-defined]


def _protocol(receiver: _Receiver, **kwargs: Any) -> OpcUdp:
    protocol = OpcUdp(
        UdpSettings(Url="opc.udp://127.0.0.1:4840"), receiver, Variant(UInt16(1), ua.VariantType.UInt16), **kwargs
    )
    protocol.connection_made(_Transport())
    return protocol


def _option(sock: socket.socket, level: int, name: int) -> int:
    return sock.getsockopt(level, name)


def test_pub7_loopback_option_is_applied_both_ways() -> None:
    for loopback in (True, False):
        sock, _, _ = UdpSettings(Url="opc.udp://239.255.0.77:48555", Loopback=loopback).create_socket(receive=False)
        try:
            assert _option(sock, socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP) == int(loopback)
        finally:
            sock.close()


def test_pub7_multicast_receiver_binds_to_the_group_not_to_the_interface() -> None:
    sock, _, local = UdpSettings(Url="opc.udp://239.255.0.77:48556").create_socket(receive=True)
    sock.close()
    assert local is not None
    assert local[0] == "239.255.0.77"


def test_pub7_network_interface_names_resolve_to_an_interface_index() -> None:
    names = [name for _, name in socket.if_nameindex()]
    assert udp_module.resolve_interface(names[0], socket.AF_INET)[1] > 0
    with pytest.raises(ua.UaError, match="no-such-interface"):
        udp_module.resolve_interface("no-such-interface", socket.AF_INET)


def test_pub7_multicast_sender_uses_the_configured_interface_address() -> None:
    settings = UdpSettings(Url="opc.udp://239.255.0.77:48557", Adapter=("127.0.0.1", 48557))
    sock, _, _ = settings.create_socket(receive=False)
    try:
        assert socket.inet_ntoa(sock.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 4)) == "127.0.0.1"
    finally:
        sock.close()


def test_pub9_unicast_localhost_binds_to_loopback_only() -> None:
    sock, _, local = UdpSettings(Url="opc.udp://localhost:48558").create_socket(receive=True)
    sock.close()
    assert local is not None
    assert local[0] == "127.0.0.1"


def test_pub9_unicast_ip_url_binds_to_that_address() -> None:
    sock, _, local = UdpSettings(Url="opc.udp://127.0.0.2:48559").create_socket(receive=True)
    sock.close()
    assert local is not None
    assert local[0] == "127.0.0.2"


def test_pub9_all_interfaces_only_when_written_out() -> None:
    sock, _, local = UdpSettings(Url="opc.udp://localhost:48560", Adapter=("0.0.0.0", 48560)).create_socket(
        receive=True
    )
    sock.close()
    assert local is not None
    assert local[0] == "0.0.0.0"


def test_pub9_a_sender_does_not_bind_a_receive_address() -> None:
    sock, _, local = UdpSettings(Url="opc.udp://127.0.0.1:48561").create_socket(receive=False)
    try:
        assert local is None
        assert sock.getsockname()[1] == 0
    finally:
        sock.close()


def test_pub24_ipv6_url_keeps_its_brackets() -> None:
    settings = UdpSettings(Url="opc.udp://[ff02::1]:4840")
    assert settings.Addr == ("ff02::1", 4840)
    assert settings.get_address().Url == "opc.udp://[ff02::1]:4840"
    assert UdpSettings(Url=settings.get_address().Url).Addr == ("ff02::1", 4840)


def test_pub24_a_unicast_interface_that_is_a_name_is_a_clear_error() -> None:
    settings = UdpSettings(Url="opc.udp://127.0.0.1:48562", Adapter=("lo", 48562))
    with pytest.raises(ua.UaError, match="IP address"):
        settings.create_socket(receive=True)


async def test_pub7_datagrams_reach_the_receiver_in_arrival_order() -> None:
    receiver = _Receiver(delay=0.001)
    protocol = _protocol(receiver)
    for i in range(20):
        protocol.datagram_received(_message(i), ("127.0.0.1", 1))
    await asyncio.sleep(0.2)
    await protocol.close()
    assert receiver.values == list(range(20))


async def test_pub7_the_receive_queue_is_bounded_and_counts_drops() -> None:
    receiver = _Receiver(delay=0.05)
    protocol = _protocol(receiver, queue_size=2)
    for i in range(10):
        protocol.datagram_received(_message(i), ("127.0.0.1", 1))
    await asyncio.sleep(0.3)
    await protocol.close()
    assert protocol.counters["queue_full"] >= 5
    assert len(receiver.values) <= 4


async def test_pub7_malformed_datagrams_warn_once_on_the_module_logger(caplog: pytest.LogCaptureFixture) -> None:
    receiver = _Receiver()
    protocol = _protocol(receiver)
    with caplog.at_level(logging.DEBUG):
        for _ in range(100):
            protocol.datagram_received(b"\x71\xff", ("127.0.0.1", 1))
        await asyncio.sleep(0.05)
    await protocol.close()
    assert protocol.counters["malformed"] == 100
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert 1 <= len(warnings) <= 2
    assert all(r.name == "enginir_opcua.pubsub.udp" for r in warnings)
    assert all(r.exc_info is None for r in warnings)


async def test_pub7_skipped_messages_are_counted_by_reason() -> None:
    receiver = _Receiver()
    protocol = _protocol(receiver)
    reserved = bytearray(_message())
    reserved[0] = (reserved[0] & 0xF0) | 2
    protocol.datagram_received(bytes(reserved), ("127.0.0.1", 1))
    await asyncio.sleep(0.05)
    await protocol.close()
    assert protocol.counters["skipped: UADP version 2"] == 1
    assert receiver.values == []


async def test_pub7_a_failing_receiver_does_not_stop_the_receive_task(caplog: pytest.LogCaptureFixture) -> None:
    receiver = _Receiver(fail=True)
    protocol = _protocol(receiver)
    protocol.datagram_received(_message(1), ("127.0.0.1", 1))
    protocol.datagram_received(_message(2), ("127.0.0.1", 1))
    await asyncio.sleep(0.05)
    await protocol.close()
    assert protocol.counters["receiver_errors"] == 2


async def test_pub25_send_goes_to_the_given_destination() -> None:
    protocol = _protocol(_Receiver())
    protocol.send_uadp([UadpNetworkMessage(UadpHeader(UInt16(1)), Payload=[])], ("10.0.0.9", 4841))
    protocol.send_uadp([UadpNetworkMessage(UadpHeader(UInt16(1)), Payload=[])])
    await protocol.close()
    assert [addr for _, addr in protocol.transport.sent] == [("10.0.0.9", 4841), ("127.0.0.1", 4840)]  # type: ignore[attr-defined]


async def test_pub25_destination_urls_resolve_to_address_tuples() -> None:
    protocol = _protocol(_Receiver())
    assert await protocol.resolve_destination("opc.udp://127.0.0.1:4850") == ("127.0.0.1", 4850)
    assert await protocol.resolve_destination("opc.udp://127.0.0.1") == ("127.0.0.1", 4840)
    await protocol.close()

import asyncio
from datetime import timezone

import pytest

from enginir_opcua import pubsub, ua
from enginir_opcua.pubsub.connection import PubSubConnection
from enginir_opcua.pubsub.reader import DataSetReader, ReaderGroup
from enginir_opcua.pubsub.uadp import UadpDataSetMessageHeader, UadpDataSetVariant, UadpHeader, UadpNetworkMessage
from enginir_opcua.pubsub.udp import OpcUdp, UdpSettings
from enginir_opcua.ua.uatypes import DateTime, UInt16, Variant

SETTINGS = UdpSettings(Url="opc.udp://127.0.0.1:4840")
SECURITY_HEADER_FLAG = 0x10


class _Receiver:
    def __init__(self) -> None:
        self.messages: list[UadpNetworkMessage] = []

    async def got_uadp(self, msg: UadpNetworkMessage) -> None:
        self.messages.append(msg)


def _message() -> bytes:
    header = UadpDataSetMessageHeader(True, UInt16(5), DateTime.now(timezone.utc), None, UInt16(0))
    message = UadpNetworkMessage(UadpHeader(UInt16(16)), Payload=[UadpDataSetVariant(Header=header, Data=[Variant(1)])])
    return message.to_binary()


async def test_pub1_writer_group_with_message_security_does_not_start() -> None:
    """Part 14, 5.4.3: Sign and SignAndEncrypt need message security, which isn't implemented; refuse them."""
    group = pubsub.WriterGroup.new_uadp(name=ua.String("SecuredGroup"), writer_group_id=UInt16(1))
    group._cfg.SecurityMode = ua.MessageSecurityMode.Sign
    connection = PubSubConnection.udp_uadp("secured", UInt16(1), SETTINGS, writer_groups=[group])
    with pytest.raises(ua.UaError, match="SecuredGroup"):
        await connection.start()


async def test_pub1_dataset_reader_with_message_security_does_not_start() -> None:
    """Part 14, 5.4.3: Sign and SignAndEncrypt need message security, which isn't implemented; refuse them."""
    reader = DataSetReader(
        ua.DataSetReaderDataType(Name="SecuredReader", SecurityMode=ua.MessageSecurityMode.SignAndEncrypt)
    )
    connection = PubSubConnection.udp_uadp(
        "secured", UInt16(1), SETTINGS, reader_groups=[ReaderGroup.new(reader=[reader])]
    )
    with pytest.raises(ua.UaError, match="SecuredReader"):
        await connection.start()


async def test_pub1_message_with_security_header_is_dropped() -> None:
    """Part 14, 7.2.4.4.3: messages with a SecurityHeader can't be verified, so they are dropped unread."""
    receiver = _Receiver()
    protocol = OpcUdp(SETTINGS, receiver, Variant(UInt16(1)))
    plain = _message()
    protocol.datagram_received(plain, ("127.0.0.1", 4840))
    secured = bytearray(plain)
    secured[1] |= SECURITY_HEADER_FLAG
    protocol.datagram_received(bytes(secured), ("127.0.0.1", 4840))
    await asyncio.sleep(0.01)
    assert len(receiver.messages) == 1

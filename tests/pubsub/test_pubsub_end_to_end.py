import asyncio
import logging
from datetime import UTC
from typing import ClassVar

import pytest

from enginir_opcua import pubsub
from enginir_opcua.common.node import Node
from enginir_opcua.pubsub.connection import PubSubConnection
from enginir_opcua.pubsub.dataset import DataSetMeta, PublishedDataSet
from enginir_opcua.pubsub.reader import DataSetReader, ReaderGroup
from enginir_opcua.pubsub.uadp import (
    UadpDataSetDataValue,
    UadpDataSetMessageHeader,
    UadpDataSetVariant,
    UadpGroupHeader,
    UadpHeader,
    UadpNetworkMessage,
)
from enginir_opcua.pubsub.udp import UdpSettings
from enginir_opcua.server.server import Server
from enginir_opcua.ua.object_ids import ObjectIds
from enginir_opcua.ua.status_codes import StatusCodes
from enginir_opcua.ua.uatypes import (
    Byte,
    DataValue,
    DateTime,
    Int16,
    Int32,
    NodeId,
    StatusCode,
    String,
    UInt16,
    UInt32,
    UInt64,
    Variant,
    VariantType,
)
from tests.conftest import find_free_port
from tests.waiting import wait_until

_logger = logging.getLogger(__name__)


def _get_test_msg() -> UadpNetworkMessage:
    gp_header = UadpGroupHeader(UInt16(2), NetworkMessageNo=UInt16(3), SequenceNo=UInt16(5))
    datasets = [
        UadpDataSetVariant(
            Header=UadpDataSetMessageHeader(True, UInt16(5), DateTime.now(UTC), None, UInt16(StatusCodes.Good)),
            Data=[Variant(123), Variant(True), Variant("1234565456")],
        ),
        UadpDataSetDataValue(
            Header=UadpDataSetMessageHeader(True, UInt16(5), DateTime.now(UTC), None, UInt16(StatusCodes.Good)),
            Data=[
                DataValue(Variant(123), StatusCode(UInt32(StatusCodes.Good)), None, DateTime.now(UTC)),
                DataValue(Variant(True), StatusCode(UInt32(StatusCodes.Good)), None, DateTime.now(UTC)),
                DataValue(Variant("1234565456"), StatusCode(UInt32(StatusCodes.Good)), None, DateTime.now(UTC)),
                DataValue(None, StatusCode(UInt32(StatusCodes.BadNodeIdUnknown)), None, DateTime.now(UTC)),
            ],
        ),
    ]
    return UadpNetworkMessage(
        UadpHeader(UInt16(16)),
        GroupHeader=gp_header,
        Timestamp=DateTime.now(UTC),
        DataSetPayloadHeader=[UInt16(5), UInt16(4)],
        Payload=datasets,
    )


class _Receiver:
    msgs: list[UadpNetworkMessage]

    def __init__(self) -> None:
        self.msgs = []

    async def got_uadp(self, msg: UadpNetworkMessage):
        # Called when a msg is received
        self.msgs.append(msg)


@pytest.mark.parametrize("publisher_id", [Byte(5), UInt16(13), UInt32(55), UInt64(33), "TestPub"], ids=repr)
async def test_connection(publisher_id: Byte | UInt16 | UInt32 | UInt64 | str) -> None:
    con = PubSubConnection.udp_uadp("test", publisher_id, UdpSettings(Url=f"opc.udp://127.0.0.1:{find_free_port()}"))
    recv = _Receiver()
    con.set_receiver(recv)
    msg = _get_test_msg()
    try:
        await con.start()
        await con.send_uadp_msg(msg)
        await wait_until(lambda: bool(recv.msgs))
        assert msg == recv.msgs[0]
    finally:
        await con.stop()


CFG = {
    "PublisherId": UInt16(1),
    "WriterGroupId": UInt16(1),
    "DataSetWriterId": UInt16(32),
    "url": f"opc.udp://224.0.0.22:{find_free_port()}",
    "PdsName": "SimpleDataSet",
}


async def create_published_dataset() -> PublishedDataSet:
    dataset = DataSetMeta.Create(String("Simple"))
    dataset.add_field(pubsub.DataSetField.CreateScalar(String("Int32"), VariantType.Int32))
    dataset.add_field(pubsub.DataSetField.CreateScalar(String("String"), VariantType.String))
    dataset.add_field(pubsub.DataSetField.CreateScalar(String("Bool"), ObjectIds.Boolean))
    dataset.add_field(pubsub.DataSetField.CreateArray(String("ArrayInt16"), ObjectIds.Double))
    return pubsub.PublishedDataSet.Create(CFG["PdsName"], dataset)


class OnDataReceived:
    values: ClassVar = {}

    async def on_dataset_received(self, meta: pubsub.DataSetMeta, fields: list[pubsub.DataSetValue]):
        _logger.info("Got Dataset %s", meta.Name)
        if meta.Name not in self.values:
            self.values[meta.Name] = {}
        for f in fields:
            self.values[meta.Name][f.Meta.Name] = f.Value

    async def on_state_change(self, meta: pubsub.DataSetMeta, state):
        _logger.info("State changed %s - %s", meta.Name, state.name)


async def test_full_simple():
    pds = await create_published_dataset()
    source = pds.get_source()
    source.datasources["Simple"] = {
        "Int32": DataValue(Variant(Int32(1))),
        "String": DataValue(Variant("0")),
        "Bool": DataValue(Variant(True)),
        "ArrayInt16": DataValue(Variant([UInt16(123), UInt16(234)])),
    }
    sink = OnDataReceived()
    pub_writer = pubsub.WriterGroup.new_uadp(
        name=String("WriterGroup1"),
        writer_group_id=CFG["WriterGroupId"],
        publishing_interval=100,
        writer=[
            pubsub.DataSetWriter.new_uadp(
                name=String("Writer1"),
                dataset_writer_id=CFG["DataSetWriterId"],
                dataset_name=CFG["PdsName"],
                datavalue=True,
            )
        ],
    )
    pub_reader = ReaderGroup.new(
        name="ReaderGroup1",
        reader=[
            DataSetReader.new(
                name="SimpleDataSetReader",
                publisherId=Variant(CFG["PublisherId"]),
                writer_group_id=CFG["WriterGroupId"],
                dataset_writer_id=CFG["DataSetWriterId"],
                meta=await pds.get_meta(),
                subscribed=sink,
                enabled=True,
            )
        ],
        enable=True,
    )
    con = pubsub.PubSubConnection.udp_uadp(
        "Publisher Connection1 UDP UADP", CFG["PublisherId"], UdpSettings(Url=CFG["url"])
    )
    await con.add_writer_group(pub_writer)
    await con.add_reader_group(pub_reader)
    ps = pubsub.PubSub()
    await ps.add_connection(con)
    await ps.add_published_dataset(pds)
    async with ps:
        for x in range(10):
            i32 = Int32(x)
            source.datasources["Simple"]["Int32"] = DataValue(Variant(i32))
            source.datasources["Simple"]["String"] = DataValue(Variant(str(i32)))
            source.datasources["Simple"]["Bool"] = DataValue(Variant((i32 % 2) > 0))
            source.datasources["Simple"]["ArrayInt16"] = DataValue(Variant([UInt16(1), UInt16(2), UInt16(3)]))
            await wait_until(lambda: all(sink.values.get(key) == source.datasources[key] for key in source.datasources))
            for key in source.datasources:
                assert source.datasources[key] == sink.values[key]


@pytest.fixture
async def pusbsub_src_nodes(server) -> list[NodeId]:
    node = server.nodes.objects
    ns = 1
    folder = await node.add_folder(NodeId(String("SrcTestNodes"), Int16(ns)), "TestNodes")
    nodes = [
        await folder.add_variable(NodeId(String("PubInt32"), Int16(ns)), "Int32", 1, VariantType.Int32),
        await folder.add_variable(NodeId(String("PubString"), Int16(ns)), "String", "DemoString"),
        await folder.add_variable(NodeId(String("PubBool"), Int16(ns)), "Bool", True, VariantType.Boolean),
        await folder.add_variable(
            NodeId(String("PubArrayInt16"), Int16(ns)), "ArrayInt16", [1, 2, 3], VariantType.Int16
        ),
    ]
    for n in nodes:
        await n.set_writable()
    return nodes


@pytest.fixture
async def pubsub_dest_nodes(server) -> list[NodeId]:
    node = server.nodes.objects
    ns = 1
    dest_folder = await node.add_folder(NodeId(String("DestTestNodes"), Int16(ns)), "DestNodes")
    dest_nodes = [
        await dest_folder.add_variable(NodeId(String("DestPubInt32"), Int16(ns)), "Int32", 1, VariantType.Int32),
        await dest_folder.add_variable(NodeId(String("DestPubString"), Int16(ns)), "String", "DemoString"),
        await dest_folder.add_variable(NodeId(String("DestPubBool"), Int16(ns)), "Bool", True, VariantType.Boolean),
        await dest_folder.add_variable(
            NodeId(String("DestPubArrayInt16"), Int16(ns)), "ArrayInt16", [1, 2, 3], VariantType.Int16
        ),
    ]
    for n in dest_nodes:
        await n.set_writable()
    return dest_nodes


async def test_datasource_and_subscribed_dataset(
    server: Server, pubsub_dest_nodes: list[Node], pusbsub_src_nodes: list[Node]
):
    ps = await server.get_pubsub()
    pubid = Variant(UInt32(1))
    writer_group_id = UInt16(2)
    datasetwriter_id = UInt16(32)
    dataset = pubsub.DataSetMeta.Create(String("Simple"))
    dataset.add_scalar(String("Int32"), VariantType.Int32)
    dataset.add_scalar(String("String"), VariantType.String)
    dataset.add_scalar(String("Bool"), ObjectIds.Boolean)
    dataset.add_array(String("ArrayInt16"), ObjectIds.Int16)
    subscribed_ds = pubsub.SubScribedTargetVariables(
        server,
        [
            pubsub.FieldTargets.createTarget(dataset.get_field((await n.read_browse_name()).Name), n.nodeid)
            for n in pubsub_dest_nodes
        ],
    )
    variables = []
    for node in pusbsub_src_nodes:
        name = await node.read_display_name()
        variables.append(pubsub.TargetVariable(name.Text, node.nodeid))

    await ps.add_published_dataset(await pubsub.PublishedDataItems.Create(String("Simple"), server, variables))
    con = PubSubConnection.udp_uadp(
        "Publisher Connection1 UDP UADP",
        pubid,
        UdpSettings(Url=f"opc.udp://127.0.0.1:{find_free_port()}"),
        reader_groups=[
            pubsub.ReaderGroup.new(
                name="ReaderGroup1",
                enable=True,
                reader=[
                    pubsub.DataSetReader.new(
                        pubid,
                        writer_group_id,
                        datasetwriter_id,
                        dataset,
                        name="SimpleDataSetReader",
                        subscribed=subscribed_ds,
                        enabled=True,
                    )
                ],
            )
        ],
        writer_groups=[
            pubsub.WriterGroup.new_uadp(
                name=String("WriterGroup1"),
                writer_group_id=writer_group_id,
                publishing_interval=100,
                writer=[
                    pubsub.DataSetWriter.new_uadp(
                        name=String("Writer1"),
                        dataset_writer_id=datasetwriter_id,
                        dataset_name=String("Simple"),
                        datavalue=True,
                    )
                ],
            )
        ],
    )
    await ps.add_connection(con)
    async with ps:
        for i in range(20):
            await pusbsub_src_nodes[0].write_value(Int32(i))
            await pusbsub_src_nodes[1].write_value(str(i))
            await pusbsub_src_nodes[2].write_value(i % 2 == 0)
            await pusbsub_src_nodes[3].write_value([Int16(x) for x in range(i, i + 3)])

            async def mirrored() -> bool:
                for dest, src in zip(pubsub_dest_nodes, pusbsub_src_nodes):
                    if await dest.read_value() != await src.read_value():
                        return False
                return True

            async with asyncio.timeout(5):
                while not await mirrored():
                    await asyncio.sleep(0.01)

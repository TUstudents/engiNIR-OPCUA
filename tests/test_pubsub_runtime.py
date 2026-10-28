import asyncio
import logging
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.pubsub import PubSub
from enginir_opcua.pubsub.connection import PubSubConnection
from enginir_opcua.pubsub.dataset import DataSetMeta, DataSetValue, PublishedDataSet, PubSubDataSourceDict
from enginir_opcua.pubsub.reader import DataSetReader, ReaderGroup
from enginir_opcua.pubsub.udp import UdpSettings
from enginir_opcua.pubsub.writer import DataSetWriter, WriterGroup
from enginir_opcua.server.server import Server
from enginir_opcua.ua.object_ids import ObjectIds
from enginir_opcua.ua.ua_binary import extensionobject_to_binary
from enginir_opcua.ua.uaerrors import UaStatusCodeError
from enginir_opcua.ua.uaprotocol_auto import Duration, PubSubState
from enginir_opcua.ua.uatypes import (
    DataValue,
    Int32,
    NodeId,
    String,
    UInt16,
    Variant,
    VariantType,
)

PUBLISHER = Variant(UInt16(1), VariantType.UInt16)


class _Sink:
    def __init__(self) -> None:
        self.values: list[Any] = []

    async def on_dataset_received(self, meta: DataSetMeta, fields: list[DataSetValue]) -> None:
        value = fields[0].Value.Value
        assert value is not None
        self.values.append(value.Value)

    async def on_state_change(self, meta: DataSetMeta, state: PubSubState) -> None:
        pass

    def get_subscribed_dataset(self) -> None:
        return None


def _dataset(name: str = "DS") -> PublishedDataSet:
    meta = DataSetMeta.Create(String(name))
    meta.add_scalar(String("a"), VariantType.Int32)
    pds = PublishedDataSet.Create(String(name), meta)
    source = pds.get_source()
    assert isinstance(source, PubSubDataSourceDict)
    source.datasources[String(name)] = {String("a"): DataValue(Variant(Int32(3)))}
    return pds


def _writer_group(name: str = "WG", group_id: int = 1, **kwargs: Any) -> WriterGroup:
    writer = DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1), datavalue=True)
    return WriterGroup.new_uadp(
        String(name), UInt16(group_id), publishing_interval=Duration(20), writer=[writer], **kwargs
    )


def _connection(name: str, port: int, **kwargs: Any) -> PubSubConnection:
    return PubSubConnection.udp_uadp(name, PUBLISHER, UdpSettings(Url=f"opc.udp://127.0.0.1:{port}"), **kwargs)


def _reader_group(sink: _Sink, name: str = "RG", group_id: int = 1) -> ReaderGroup:
    meta = _dataset().dataset
    reader = DataSetReader.new(PUBLISHER, UInt16(group_id), UInt16(1), meta, name + "R", True, sink)
    return ReaderGroup.new(name, [reader], True)


async def test_pub5_start_raises_the_first_startup_error_and_leaves_nothing_running() -> None:
    good = _connection("Pub5Good", 48620, reader_groups=[_reader_group(_Sink())])
    bad = PubSubConnection.udp_uadp(
        "Pub5Bad",
        PUBLISHER,
        UdpSettings(Url="opc.udp://192.0.2.1:48621"),
        reader_groups=[_reader_group(_Sink(), "RG2")],
    )
    ps = PubSub.new([good, bad], [])
    with pytest.raises(ua.UaError):
        await ps.start()
    assert good._protocol is None
    assert good._transport is None
    assert bad._protocol is None
    assert ps._running is False
    await ps.stop()


async def test_pub5_a_group_with_message_security_stops_start_of_the_whole_pubsub() -> None:
    group = _writer_group()
    group._cfg.SecurityMode = ua.MessageSecurityMode.Sign
    ps = PubSub.new([_connection("Pub5Secured", 48622, writer_groups=[group])], [_dataset()])
    with pytest.raises(ua.UaError, match="WG"):
        await ps.start()
    assert ps._running is False


async def test_pub5_a_pubsub_without_connections_starts_and_stops() -> None:
    ps = PubSub()
    await ps.start()
    assert ps._running
    await ps.stop()
    assert not ps._running


async def test_pub5_connections_given_to_the_constructor_run_with_the_pubsub_as_registry() -> None:
    sink = _Sink()
    connection = _connection("Pub5Ctor", 48623, writer_groups=[_writer_group()], reader_groups=[_reader_group(sink)])
    ps = PubSub.new([connection], [_dataset()])
    async with ps:
        await asyncio.sleep(0.2)
    assert connection._app is ps
    assert sink.values
    assert set(sink.values) == {3}


async def test_pub5_every_connection_and_dataset_appears_once_in_the_address_space(server: Server) -> None:
    ps = PubSub(None, server)
    await ps.add_published_dataset(_dataset("Pub5DsOne"))
    await ps.add_published_dataset(_dataset("Pub5DsTwo"))
    await ps.add_connection(_connection("Pub5ConOne", 48624))
    await ps.add_connection(_connection("Pub5ConTwo", 48625))
    await ps.init_information_model()
    root = server.get_node(NodeId(ObjectIds.PublishSubscribe))
    connections = await root.get_children(ObjectIds.HasPubSubConnection)
    names = [(await c.read_browse_name()).Name for c in connections]
    assert names.count("Pub5ConOne") == 1
    assert names.count("Pub5ConTwo") == 1
    datasets = await (await root.get_child("0:PublishedDataSets")).get_children()
    dataset_names = [(await d.read_browse_name()).Name for d in datasets]
    assert dataset_names.count("Pub5DsOne") == 1
    assert dataset_names.count("Pub5DsTwo") == 1


async def test_pub5_connections_appear_without_any_dataset(server: Server) -> None:
    ps = PubSub(None, server)
    await ps.add_connection(_connection("Pub5NoDatasets", 48626))
    await ps.init_information_model()
    root = server.get_node(NodeId(ObjectIds.PublishSubscribe))
    names = [(await c.read_browse_name()).Name for c in await root.get_children(ObjectIds.HasPubSubConnection)]
    assert names.count("Pub5NoDatasets") == 1


async def test_pub5_removing_elements_deletes_their_nodes_and_stops_them(server: Server) -> None:
    ps = PubSub(None, server)
    pds = _dataset("Pub5RemoveDs")
    await ps.add_published_dataset(pds)
    connection = _connection("Pub5Remove", 48627, writer_groups=[_writer_group("Pub5RemoveWG")])
    await ps.add_connection(connection)
    await ps.init_information_model()
    group = connection._writer_groups[0]
    group_node = group._node
    connection_node = connection._node
    pds_node = pds._node
    assert group_node is not None
    assert connection_node is not None
    assert pds_node is not None
    await ps.start()
    await connection.remove_writer_group(String("Pub5RemoveWG"))
    assert connection._writer_groups == []
    assert connection.get_config().WriterGroups == []
    assert await group.get_state() == PubSubState.Disabled
    with pytest.raises(UaStatusCodeError):
        await group_node.read_browse_name()
    await ps.remove_published_dataset(String("Pub5RemoveDs"))
    assert ps.get_published_dataset(String("Pub5RemoveDs")) is None
    with pytest.raises(UaStatusCodeError):
        await pds_node.read_browse_name()
    await ps.remove_connection(String("Pub5Remove"))
    assert ps.get_connection(String("Pub5Remove")) is None
    assert connection._protocol is None
    with pytest.raises(UaStatusCodeError):
        await connection_node.read_browse_name()
    with pytest.raises(ValueError, match="Unknown"):
        await ps.remove_connection(String("Pub5Remove"))
    await ps.stop()


async def test_pub5_removing_a_reader_group_stops_it_and_forgets_it() -> None:
    sink = _Sink()
    connection = _connection("Pub5RemoveReader", 48628, reader_groups=[_reader_group(sink)])
    ps = PubSub.new([connection], [])
    await ps.start()
    reader = connection._reader_groups[0]._reader[0]
    await connection.remove_reader_group(String("RG"))
    assert connection._reader_groups == []
    assert connection.get_config().ReaderGroups == []
    assert reader.get_reader_state() == PubSubState.Disabled
    await ps.stop()


async def test_pub5_loading_a_file_of_another_type_raises_a_status_code(tmp_path) -> None:
    path = tmp_path / "wrong.bin"
    path.write_bytes(extensionobject_to_binary(ua.Argument()))
    with pytest.raises(UaStatusCodeError) as error:
        await PubSub().load_binary_file(path)
    assert error.value.code == ua.StatusCodes.BadInvalidArgument


async def test_pub16_stop_never_raises_cancelled_error_and_can_be_repeated() -> None:
    connection = _connection("Pub16Stop", 48629, writer_groups=[_writer_group()])
    PubSub.new([connection], [_dataset()])
    await connection.start()
    await asyncio.sleep(0.05)
    await connection.stop()
    await connection.stop()
    assert await connection.get_state() == PubSubState.Disabled
    assert await connection._writer_groups[0].get_state() == PubSubState.Disabled


async def test_pub16_a_failed_start_closes_the_socket() -> None:
    group = _writer_group()
    group._cfg.PublishingInterval = Duration(0)
    connection = _connection("Pub16Fail", 48630, writer_groups=[group])
    PubSub.new([connection], [_dataset()])
    with pytest.raises(ua.UaError, match="PublishingInterval"):
        await connection.start()
    assert connection._transport is None
    assert connection._protocol is None
    assert await connection.get_state() == PubSubState.Error


async def test_pub17_groups_given_to_udp_uadp_are_part_of_the_configuration() -> None:
    writer_group = _writer_group()
    reader_group = _reader_group(_Sink())
    connection = _connection("Pub17Config", 48631, writer_groups=[writer_group], reader_groups=[reader_group])
    config = connection.get_config()
    assert config.WriterGroups == [writer_group._cfg]
    assert config.ReaderGroups == [reader_group._cfg]


async def test_pub17_a_connection_with_writers_but_no_pubsub_fails_with_a_clear_error() -> None:
    connection = _connection("Pub17NoApp", 48632, writer_groups=[_writer_group()])
    with pytest.raises(ua.UaError, match="PubSub"):
        await connection.start()


async def test_pub18_the_group_methods_are_not_implemented(server: Server) -> None:
    ps = PubSub(None, server)
    connection = _connection("Pub18Methods", 48633)
    await ps.add_connection(connection)
    await ps.init_information_model()
    assert connection._node is not None
    for method, argument in (
        ("0:AddReaderGroup", ua.ReaderGroupDataType()),
        ("0:AddWriterGroup", ua.WriterGroupDataType()),
        ("0:RemoveGroup", NodeId(ObjectIds.PublishSubscribe)),
    ):
        with pytest.raises(UaStatusCodeError) as error:
            await connection._node.call_method(method, argument)
        assert error.value.code == ua.StatusCodes.BadNotImplemented


async def test_pub25_a_unicast_group_sends_to_its_address() -> None:
    sink = _Sink()
    subscriber = _connection("Pub25Sub", 48634, reader_groups=[_reader_group(sink)])
    publisher = _connection("Pub25Pub", 48635, writer_groups=[_writer_group(address="opc.udp://127.0.0.1:48634")])
    ps = PubSub.new([subscriber, publisher], [_dataset()])
    async with ps:
        await asyncio.sleep(0.2)
    assert sink.values


async def test_pub25_a_multicast_connection_refuses_a_group_with_an_address() -> None:
    group = _writer_group(address="opc.udp://127.0.0.1:48636")
    connection = PubSubConnection.udp_uadp(
        "Pub25Multicast", PUBLISHER, UdpSettings(Url="opc.udp://239.255.0.78:48637"), writer_groups=[group]
    )
    ps = PubSub.new([connection], [_dataset()])
    async with ps:
        await asyncio.sleep(0.05)
        assert await group.get_state() == PubSubState.Error
    assert group.counters["published"] == 0


async def test_pub4_writer_groups_start_in_priority_order() -> None:
    order: list[str] = []

    class Spy(WriterGroup):
        async def prepare(self, sender: Any) -> None:
            order.append(str(self._cfg.Name))
            await super().prepare(sender)

    groups = []
    for name, priority in (("low", 1), ("high", 9), ("mid", 5)):
        group = _writer_group(name, 1 + len(groups), priority=priority)
        spy = Spy(group._cfg)
        groups.append(spy)
    connection = _connection("Pub4Priority", 48638, writer_groups=groups)
    ps = PubSub.new([connection], [_dataset()])
    async with ps:
        await asyncio.sleep(0.05)
    assert order == ["high", "mid", "low"]


async def test_pub4_disabled_connection_does_not_start() -> None:
    connection = _connection("Pub4Disabled", 48639, writer_groups=[_writer_group()])
    connection._cfg.Enabled = False
    ps = PubSub.new([connection], [_dataset()])
    async with ps:
        assert connection._protocol is None
    assert await connection.get_state() == PubSubState.Disabled


async def test_pub30_pubsub_logs_on_its_own_loggers(caplog: pytest.LogCaptureFixture) -> None:
    connection = _connection("Pub30Log", 48640, writer_groups=[_writer_group()])
    ps = PubSub.new([connection], [_dataset()])
    with caplog.at_level(logging.DEBUG):
        async with ps:
            await asyncio.sleep(0.05)
    assert caplog.records
    assert all(r.name.startswith("enginir_opcua") for r in caplog.records)

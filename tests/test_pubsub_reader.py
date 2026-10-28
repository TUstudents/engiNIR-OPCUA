import asyncio
from typing import Any

from enginir_opcua import pubsub, ua
from enginir_opcua.pubsub import uadp
from enginir_opcua.pubsub.dataset import DataSetMeta, DataSetValue
from enginir_opcua.pubsub.reader import DataSetReader, ReaderGroup
from enginir_opcua.pubsub.subscribed_dataset import SubScribedTargetVariables
from enginir_opcua.pubsub.uadp import (
    DeltaVariant,
    UadpChunk,
    UadpDataSetDeltaVariant,
    UadpDataSetEvent,
    UadpDataSetHeartbeat,
    UadpDataSetKeepAlive,
    UadpDataSetMessageHeader,
    UadpDataSetSkipped,
    UadpDataSetVariant,
    UadpGroupHeader,
    UadpHeader,
    UadpNetworkMessage,
)
from enginir_opcua.server.server import Server
from enginir_opcua.ua.status_codes import StatusCodes
from enginir_opcua.ua.uaprotocol_auto import PubSubState, ReaderGroupDataType, TargetVariablesDataType
from enginir_opcua.ua.uatypes import (
    DataValue,
    Int32,
    NodeId,
    StatusCode,
    String,
    UInt16,
    UInt32,
    Variant,
    VariantType,
)

PUBLISHER = Variant(UInt16(1), VariantType.UInt16)


class _Sink:
    def __init__(self, fail: bool = False) -> None:
        self.received: list[list[DataSetValue]] = []
        self.states: list[PubSubState] = []
        self.fail = fail

    async def on_dataset_received(self, meta: DataSetMeta, fields: list[DataSetValue]) -> None:
        if self.fail:
            raise RuntimeError("sink failed")
        self.received.append(fields)

    async def on_state_change(self, meta: DataSetMeta, state: PubSubState) -> None:
        self.states.append(state)

    def get_subscribed_dataset(self) -> Any:
        return None


def _meta(*names: str) -> DataSetMeta:
    meta = DataSetMeta.Create(String("DS"))
    for name in names or ("a", "b"):
        meta.add_scalar(String(name), VariantType.Int32)
    meta.get_config().ConfigurationVersion.MajorVersion = UInt32(10)
    meta.get_config().ConfigurationVersion.MinorVersion = UInt32(10)
    return meta


def _reader(
    sink: _Sink, meta: DataSetMeta | None = None, publisher: Variant = PUBLISHER, writer: int = 5, group_id: int = 2
) -> DataSetReader:
    return DataSetReader.new(
        publisher, UInt16(group_id), UInt16(writer), meta or _meta(), name="R", enabled=True, subscribed=sink
    )


def _group(*readers: DataSetReader, enabled: bool = True) -> ReaderGroup:
    return ReaderGroup.new(name="G", reader=list(readers), enable=enabled)


def _message(
    values: list[int] | None = None,
    *,
    payload: list[Any] | None = None,
    publisher: Any = UInt16(1),
    writer_id: int = 5,
    group_id: int | None = 2,
    **header: Any,
) -> UadpNetworkMessage:
    if payload is None:
        data = [Variant(Int32(v)) for v in (values if values is not None else [1, 2])]
        payload = [UadpDataSetVariant(UadpDataSetMessageHeader(**header), data)]
    return UadpNetworkMessage(
        UadpHeader(publisher),
        UadpGroupHeader(UInt16(group_id)) if group_id is not None else None,
        [UInt16(writer_id)],
        Payload=payload,
    )


async def test_pub3_message_receive_timeout_is_in_milliseconds_and_reset_by_messages() -> None:
    """Part 14, 6.2.9.6: the timeout is a Duration in milliseconds and restarts with each DataSetMessage."""
    sink = _Sink()
    reader = _reader(sink)
    reader._cfg.MessageReceiveTimeout = 150
    group = _group(reader)
    await group.start()
    for _ in range(6):
        await group.handle_msg(_message())
        await asyncio.sleep(0.05)
    assert PubSubState.Error not in sink.states
    assert sink.states[-1] == PubSubState.Operational
    await asyncio.sleep(0.4)
    assert sink.states[-1] == PubSubState.Error
    await group.handle_msg(_message())
    assert sink.states[-1] == PubSubState.Operational
    await group.stop()
    assert sink.states[-1] == PubSubState.Disabled


async def test_pub3_a_reader_is_operational_after_its_first_key_frame() -> None:
    sink = _Sink()
    reader = _reader(sink)
    group = _group(reader)
    await group.start()
    assert PubSubState.Operational not in sink.states
    await group.handle_msg(_message())
    assert sink.states == [PubSubState.PreOperational, PubSubState.Operational]
    assert len(sink.received) == 1
    await group.stop()


async def test_pub3_a_different_major_version_drops_the_message_a_different_minor_version_does_not() -> None:
    """Part 14, 6.2.9.4, 6.2.3.2.6: the major version has to match; appended fields only change the minor version."""
    sink = _Sink()
    reader = _reader(sink)
    group = _group(reader)
    await group.handle_msg(_message(CfgMajorVersion=UInt32(11), CfgMinorVersion=UInt32(10)))
    assert sink.received == []
    assert reader.counters["dropped: configuration version"] == 1
    await group.handle_msg(_message(CfgMajorVersion=UInt32(10), CfgMinorVersion=UInt32(10)))
    await group.handle_msg(_message([1, 2, 3], CfgMajorVersion=UInt32(10), CfgMinorVersion=UInt32(11)))
    assert [[f.Name for f in r] for r in sink.received] == [["a", "b"], ["a", "b"]]


async def test_pub3_a_field_count_that_does_not_match_the_metadata_drops_the_message() -> None:
    sink = _Sink()
    reader = _reader(sink)
    group = _group(reader)
    await group.handle_msg(_message([1]))
    await group.handle_msg(_message([1, 2, 3]))
    assert sink.received == []
    assert reader.counters["dropped: field count"] == 2


async def test_pub3_a_delta_frame_index_outside_the_metadata_drops_the_message() -> None:
    sink = _Sink()
    reader = _reader(sink)
    group = _group(reader)
    delta = UadpDataSetDeltaVariant(UadpDataSetMessageHeader(), [DeltaVariant(UInt16(7), Variant(Int32(1)))])
    await group.handle_msg(_message(payload=[delta]))
    assert sink.received == []
    ok = UadpDataSetDeltaVariant(UadpDataSetMessageHeader(), [DeltaVariant(UInt16(1), Variant(Int32(9)))])
    await group.handle_msg(_message(payload=[ok]))
    assert [f.Name for f in sink.received[0]] == ["b"]


async def test_pub3_a_reader_group_keeps_its_configuration() -> None:
    cfg = ReaderGroupDataType(Name="Loaded", Enabled=True, MaxNetworkMessageSize=UInt32(900))
    cfg.DataSetReaders = [ua.DataSetReaderDataType(Name="LoadedReader", Enabled=True)]
    group = ReaderGroup(cfg)
    assert group.get_name() == "Loaded"
    assert group._cfg is cfg
    assert group._cfg.MaxNetworkMessageSize == 900
    assert group._reader[0]._cfg is cfg.DataSetReaders[0]
    await group.set_name(String("Renamed"))
    assert group.get_name() == "Renamed"


async def test_pub3_a_new_reader_group_has_its_readers_in_the_configuration() -> None:
    reader = _reader(_Sink())
    group = _group(reader)
    assert group._cfg.DataSetReaders == [reader._cfg]


async def test_pub3_messages_that_are_not_dataset_messages_are_ignored() -> None:
    """Part 14, 7.2.4.4.4, 7.2.4.6: chunk and discovery messages carry no DataSetMessages."""
    sink = _Sink()
    group = _group(_reader(sink))
    for payload in (
        UadpChunk(UInt16(5)),
        uadp.UadpDiscoveryProbe(ua.Byte(1)),
        uadp.UadpDiscoveryAnnouncement(ua.Byte(2)),
    ):
        msg = UadpNetworkMessage(UadpHeader(UInt16(1)), UadpGroupHeader(UInt16(2)), Payload=payload)
        await group.handle_msg(msg)
    assert sink.received == []
    assert group.counters["ignored: not a DataSetMessage"] == 3


async def test_pub13_keep_alive_heartbeat_event_and_skipped_messages_do_not_raise() -> None:
    sink = _Sink()
    reader = _reader(sink)
    group = _group(reader)
    await group.start()
    payload = [
        UadpDataSetKeepAlive(UadpDataSetMessageHeader()),
        UadpDataSetHeartbeat(UadpDataSetMessageHeader()),
        UadpDataSetSkipped("reserved"),
        UadpDataSetEvent(UadpDataSetMessageHeader(), [Variant(Int32(1)), Variant(Int32(2))]),
    ]
    for item in payload:
        await group.handle_msg(_message(payload=[item]))
    assert len(sink.received) == 1
    assert sink.states == [PubSubState.PreOperational, PubSubState.Operational]
    await group.stop()


async def test_pub13_a_failing_reader_does_not_stop_the_other_readers() -> None:
    failing = _Sink(fail=True)
    working = _Sink()
    group = _group(_reader(failing), _reader(working))
    await group.handle_msg(_message())
    assert len(working.received) == 1


async def test_pub28_a_null_publisher_id_matches_every_publisher() -> None:
    """Part 14, 6.2.9.1: a null PublisherId passes every NetworkMessage."""
    sink = _Sink()
    group = _group(_reader(sink, publisher=Variant()))
    await group.handle_msg(_message(publisher=UInt16(9)))
    await group.handle_msg(_message(publisher=UInt32(1)))
    assert len(sink.received) == 2


async def test_pub28_publisher_ids_of_another_type_do_not_match() -> None:
    sink = _Sink()
    group = _group(_reader(sink))
    await group.handle_msg(_message(publisher=UInt32(1)))
    await group.handle_msg(_message(publisher=UInt16(2)))
    assert sink.received == []


async def test_pub28_duplicate_and_older_messages_are_ignored_and_the_sequence_rolls_over() -> None:
    """Part 14, 7.2.3: a message is new when (received - 1 - last) mod 65536 is below 16384."""
    sink = _Sink()
    reader = _reader(sink)
    group = _group(reader)
    for number in (65534, 65535, 65535, 0, 65535, 1):
        await group.handle_msg(_message(SequenceNo=UInt16(number)))
    assert len(sink.received) == 4
    assert reader.counters["ignored: duplicate or older"] == 2


async def test_pub28_messages_without_a_sequence_number_are_all_new() -> None:
    sink = _Sink()
    group = _group(_reader(sink))
    for _ in range(3):
        await group.handle_msg(_message())
    assert len(sink.received) == 3


async def test_pub28_a_dataset_message_that_is_not_valid_is_ignored() -> None:
    sink = _Sink()
    group = _group(_reader(sink))
    await group.handle_msg(_message(Valid=False))
    assert sink.received == []


async def test_pub28_a_disabled_group_or_reader_receives_nothing() -> None:
    sink = _Sink()
    disabled_group = _group(_reader(sink), enabled=False)
    await disabled_group.handle_msg(_message())
    reader = _reader(sink)
    reader._cfg.Enabled = False
    await _group(reader).handle_msg(_message())
    assert sink.received == []


async def test_pub28_writer_group_and_dataset_writer_filters() -> None:
    """Part 14, 6.2.9.2, 6.2.9.3: 0 passes everything, other values have to match."""
    sink = _Sink()
    any_group = _reader(sink, group_id=0, writer=0)
    group = _group(any_group)
    await group.handle_msg(_message(group_id=77, writer_id=9))
    await group.handle_msg(_message(group_id=None, writer_id=9))
    assert len(sink.received) == 2
    sink2 = _Sink()
    exact = _group(_reader(sink2))
    await exact.handle_msg(_message(group_id=3))
    await exact.handle_msg(_message(writer_id=6))
    await exact.handle_msg(_message(group_id=None))
    assert sink2.received == []


async def test_pub27_status_and_data_value_variants_become_data_values() -> None:
    """Part 14, 7.2.4.5.4: a Bad field arrives as a Variant with a StatusCode, an Uncertain one with a DataValue."""
    sink = _Sink()
    group = _group(_reader(sink))
    bad = Variant(StatusCode(StatusCodes.BadNoCommunication), VariantType.StatusCode)
    uncertain = Variant(
        DataValue(Variant(Int32(3)), StatusCode(StatusCodes.UncertainSubstituteValue)), VariantType.DataValue
    )
    message = UadpDataSetVariant(UadpDataSetMessageHeader(), [bad, uncertain])
    await group.handle_msg(_message(payload=[message]))
    first, second = sink.received[0]
    assert first.Value.StatusCode is not None
    assert second.Value.StatusCode is not None
    assert first.Value.Value is not None
    assert first.Value.StatusCode.value == StatusCodes.BadNoCommunication
    assert first.Value.Value.Value is None
    assert second.Value.StatusCode.value == StatusCodes.UncertainSubstituteValue
    assert second.Value.Value == Variant(Int32(3))


async def test_pub19_readers_from_a_configuration_get_a_subscribed_dataset(server: Server) -> None:
    """Part 14, 6.2.10.2: a reader configured with TargetVariables writes to them without further code."""
    node = await server.nodes.objects.add_variable(
        NodeId(String("Pub19Var"), ua.Int16(1)), "Pub19Var", 0, VariantType.Int32
    )
    await node.set_writable()
    meta = _meta("a")
    field = meta.get_field("a")
    assert field is not None
    target = ua.FieldTargetDataType(
        DataSetFieldId=field.DataSetFieldId, TargetNodeId=node.nodeid, AttributeId=ua.AttributeIds.Value
    )
    reader_cfg = ua.DataSetReaderDataType(
        Name="Pub19Reader",
        Enabled=True,
        PublisherId=PUBLISHER,
        WriterGroupId=UInt16(2),
        DataSetWriterId=UInt16(5),
        DataSetMetaData=meta.get_config(),
        SubscribedDataSet=TargetVariablesDataType(TargetVariables=[target]),
    )
    group_cfg = ReaderGroupDataType(Name="Pub19Group", Enabled=True, DataSetReaders=[reader_cfg])
    connection_cfg = ua.PubSubConnectionDataType(
        Name="Pub19",
        Enabled=True,
        PublisherId=PUBLISHER,
        TransportProfileUri=pubsub.connection.UDP_UADP_PROFILE,
        Address=ua.NetworkAddressUrlDataType("", "opc.udp://127.0.0.1:48611"),
        ReaderGroups=[group_cfg],
    )
    ps = pubsub.PubSub(ua.PubSubConfigurationDataType(Connections=[connection_cfg]), server)
    reader = ps._con[0]._reader_groups[0]._reader[0]
    assert isinstance(reader._subscribed, SubScribedTargetVariables)
    await ps._con[0]._reader_groups[0].start()
    await ps._con[0]._reader_groups[0].handle_msg(_message([5], payload=None))
    assert await node.read_value() == 5
    await ps._con[0]._reader_groups[0].stop()

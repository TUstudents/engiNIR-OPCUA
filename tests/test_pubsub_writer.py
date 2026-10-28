import asyncio
import logging
import uuid
from typing import Any

import pytest

from enginir_opcua import pubsub, ua
from enginir_opcua.pubsub import uadp
from enginir_opcua.pubsub.dataset import DataSetMeta, PubSubDataSourceDict
from enginir_opcua.pubsub.uadp import UadpNetworkMessage
from enginir_opcua.pubsub.udp import OpcUdp, UdpSettings
from enginir_opcua.pubsub.writer import DataSetWriter, WriterGroup
from enginir_opcua.server.server import Server
from enginir_opcua.ua.uaprotocol_auto import (
    DatagramWriterGroupTransport2DataType,
    DataSetFieldContentMask,
    Duration,
    PubSubState,
    UadpNetworkMessageContentMask,
)
from enginir_opcua.ua.uatypes import (
    DataValue,
    DateTime,
    Int32,
    StatusCode,
    String,
    UInt16,
    UInt32,
    Variant,
    VariantType,
)


class _Sender:
    def __init__(self, fail_times: int = 0) -> None:
        self.rounds: list[list[UadpNetworkMessage]] = []
        self.destinations: list[Any] = []
        self.max_sizes: list[int] = []
        self.fail_times = fail_times
        self.resolved: list[str] = []

    def send_uadp(self, msgs: list[UadpNetworkMessage], destination: Any = None, max_size: int = 0) -> list[int]:
        if self.fail_times:
            self.fail_times -= 1
            raise OSError("network is down")
        self.rounds.append(msgs)
        self.destinations.append(destination)
        self.max_sizes.append(max_size)
        return []

    async def resolve_destination(self, url: str) -> Any:
        self.resolved.append(url)
        return ("resolved", 1)

    def get_publisher_id(self) -> uadp.PublisherIdValue:
        return UInt16(1)


class _Registry:
    def __init__(self, *datasets: pubsub.PublishedDataSet) -> None:
        self._datasets = {str(d.get_name()): d for d in datasets}

    def get_published_dataset(self, name: String) -> pubsub.PublishedDataSet | None:
        return self._datasets.get(str(name))


def _dataset(name: str = "DS", **values: Any) -> pubsub.PublishedDataSet:
    meta = DataSetMeta.Create(String(name))
    for field_name in values or {"a": 1}:
        meta.add_scalar(String(field_name), VariantType.Int32)
    pds = pubsub.PublishedDataSet.Create(String(name), meta)
    source = pds.get_source()
    assert isinstance(source, PubSubDataSourceDict)
    source.datasources[String(name)] = {
        String(k): DataValue(Variant(Int32(v))) for k, v in (values or {"a": 1}).items()
    }
    return pds


def _group(interval: float = 20, writers: list[DataSetWriter] | None = None, **kwargs: Any) -> WriterGroup:
    writers = writers or [DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1))]
    return WriterGroup.new_uadp(
        String("G"), UInt16(1), publishing_interval=Duration(interval), writer=writers, **kwargs
    )


async def _run_for(group: WriterGroup, sender: _Sender, registry: _Registry, seconds: float) -> None:
    task = asyncio.create_task(group.run(sender, registry))
    await asyncio.sleep(seconds)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def _datasets(msg: UadpNetworkMessage) -> list[Any]:
    assert isinstance(msg.Payload, list)
    return msg.Payload


async def test_pub4_dataset_message_sequence_numbers_start_at_0_and_roll_over_at_65535() -> None:
    """Part 14, 7.2.3: a sequence number starts at 0 and rolls over from its maximum to 0."""
    writer = DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1))
    pds = _dataset()
    numbers = []
    writer._seq_no = 65534
    for _ in range(4):
        message = await writer.generate_uadp_dataset(pds)
        numbers.append(message.Header.SequenceNo)
    assert numbers == [65534, 65535, 0, 1]
    fresh = DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1))
    assert (await fresh.generate_uadp_dataset(pds)).Header.SequenceNo == 0


async def test_pub4_group_header_sequence_numbers_use_the_whole_range() -> None:
    """Part 14, 7.2.3: the NetworkMessage sequence number rolls over from 65535 to 0."""
    group = _group()
    group._sequence_number = 65535
    sender = _Sender()
    await _run_for(group, sender, _Registry(_dataset()), 0.07)
    numbers = [r[0].GroupHeader.SequenceNo for r in sender.rounds if r[0].GroupHeader]
    assert numbers[:3] == [65535, 0, 1]


async def test_pub4_priority_node_shows_the_configured_priority(server: Server) -> None:
    """Part 14, 6.2.6.4: the Priority node holds the Priority of the group, not its id."""
    ps = await server.get_pubsub()
    group = _group(priority=7)
    group._cfg.WriterGroupId = UInt16(1000)
    connection = pubsub.PubSubConnection.udp_uadp(
        "Pub4Priority", UInt16(4), UdpSettings(Url="opc.udp://127.0.0.1:48601"), writer_groups=[group]
    )
    await ps.add_connection(connection)
    assert group._node is not None
    assert await (await group._node.get_child("0:Priority")).read_value() == 7


async def test_pub4_disabled_group_and_writer_publish_nothing() -> None:
    """Part 14, 6.2.4, 6.2.6: a disabled group or DataSetWriter doesn't publish."""
    registry = _Registry(_dataset(), _dataset("DS2"))
    disabled = _group(enabled=False)
    sender = _Sender()
    await asyncio.wait_for(disabled.run(sender, registry), 1)
    assert sender.rounds == []
    assert await disabled.get_state() == PubSubState.Disabled
    off = DataSetWriter.new_uadp(String("Off"), String("DS2"), UInt16(2), enabled=False)
    on = DataSetWriter.new_uadp(String("On"), String("DS"), UInt16(1))
    group = _group(writers=[on, off])
    await _run_for(group, sender, registry, 0.05)
    assert sender.rounds
    assert all(_datasets(r[0]) and len(_datasets(r[0])) == 1 for r in sender.rounds)
    assert all(r[0].DataSetPayloadHeader == [1] for r in sender.rounds)


async def test_pub4_intervals_of_zero_or_less_are_refused() -> None:
    """Part 14, 6.2.6.2: negative intervals are invalid; event-driven publishing isn't implemented."""
    for interval in (0, -5, float("nan")):
        group = _group(interval=interval)
        with pytest.raises(ua.UaError, match="PublishingInterval"):
            await group.prepare(_Sender())


async def test_pub4_publishing_keeps_a_fixed_rate_when_a_round_takes_time() -> None:
    """Part 14, 6.2.6.2: the interval is the time between publications, not the time between the end of two."""
    pds = _dataset()

    class SlowSource(PubSubDataSourceDict):
        async def on_get_value(self) -> list[DataValue]:
            await asyncio.sleep(0.02)
            return await super().on_get_value()

    slow = SlowSource(pds.dataset)
    slow.datasources = pds.get_source().datasources  # type: ignore[attr-defined]
    pds.set_source_custom(slow)
    group = _group(interval=50)
    sender = _Sender()
    await _run_for(group, sender, _Registry(pds), 1.0)
    assert len(sender.rounds) >= 18


async def test_pub4_data_set_class_id_does_not_warn_on_every_publish(caplog: pytest.LogCaptureFixture) -> None:
    pds = _dataset()
    pds.dataset.get_config().DataSetClassId = uuid.uuid4()
    group = _group()
    group._cfg.MessageSettings.NetworkMessageContentMask |= UadpNetworkMessageContentMask.DataSetClassId
    sender = _Sender()
    with caplog.at_level(logging.DEBUG):
        await _run_for(group, sender, _Registry(pds), 0.1)
    assert len(sender.rounds) >= 3
    assert not [r for r in caplog.records if "DataSetClassId" in r.getMessage() and r.levelno >= logging.WARNING]
    assert sender.rounds[0][0].Header.DataSetClassId == pds.dataset.get_config().DataSetClassId


async def test_pub4_a_message_above_the_maximum_size_is_not_sent_and_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Part 14, 6.2.5.5: a NetworkMessage larger than MaxNetworkMessageSize isn't sent."""
    transport_sent: list[bytes] = []

    class Transport:
        def sendto(self, data: bytes, addr: Any) -> None:
            transport_sent.append(data)

    protocol = OpcUdp(UdpSettings(Url="opc.udp://127.0.0.1:4840"), None, Variant(UInt16(1), VariantType.UInt16))
    protocol.transport = Transport()  # type: ignore[assignment]
    group = _group(max_network_message_size=UInt32(10))
    with caplog.at_level(logging.DEBUG):
        await _run_for(group, protocol, _Registry(_dataset()), 0.1)  # type: ignore[arg-type]
    assert transport_sent == []
    assert protocol.counters["oversize"] >= 3
    assert len([r for r in caplog.records if "MaxNetworkMessageSize" in r.getMessage()]) == 1


async def test_pub4_key_frame_count_above_one_warns_once_and_sends_key_frames(caplog: pytest.LogCaptureFixture) -> None:
    writer = DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1))
    writer._cfg.KeyFrameCount = UInt32(5)
    group = _group(writers=[writer])
    sender = _Sender()
    with caplog.at_level(logging.DEBUG):
        await _run_for(group, sender, _Registry(_dataset()), 0.1)
    assert len(sender.rounds) >= 3
    assert len([r for r in caplog.records if "KeyFrameCount" in r.getMessage()]) == 1


async def test_pub4_keep_alive_is_sent_when_a_writer_has_nothing_to_send() -> None:
    """Part 14, 6.2.6.3, 7.2.4.5.8: a keep-alive DataSetMessage when a DataSetWriter was silent for KeepAliveTime."""
    pds = _dataset()

    class Failing(PubSubDataSourceDict):
        fail = False

        async def on_get_value(self) -> list[DataValue]:
            if self.fail:
                raise OSError("source is down")
            return await super().on_get_value()

    source = Failing(pds.dataset)
    source.datasources = pds.get_source().datasources  # type: ignore[attr-defined]
    pds.set_source_custom(source)
    group = _group(interval=10, keep_alive_time=Duration(40))
    sender = _Sender()
    task = asyncio.create_task(group.run(sender, _Registry(pds)))
    await asyncio.sleep(0.05)
    source.fail = True
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    kinds = [type(_datasets(r[0])[0]).__name__ for r in sender.rounds]
    assert "UadpDataSetVariant" in kinds
    assert kinds[-1] == "UadpDataSetKeepAlive"
    assert 1 <= kinds.count("UadpDataSetKeepAlive") <= 6


async def test_pub22_the_field_content_mask_selects_the_parts_of_a_data_value() -> None:
    """Part 14, 6.2.4.2: only the DataValue parts of the mask are sent."""
    writer = DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1), datavalue=True)
    writer._cfg.DataSetFieldContentMask = DataSetFieldContentMask.StatusCode
    pds = _dataset()
    source = pds.get_source()
    assert isinstance(source, PubSubDataSourceDict)
    source.datasources[String("DS")][String("a")] = DataValue(
        Variant(Int32(1)), StatusCode(0), SourceTimestamp=DateTime.now(), ServerTimestamp=DateTime.now()
    )
    message = await writer.generate_uadp_dataset(pds)
    value = message.Data[0]  # type: ignore[attr-defined]
    assert value.StatusCode is not None
    assert value.SourceTimestamp is None
    assert value.ServerTimestamp is None


async def test_pub22_the_message_status_is_the_worst_field_status() -> None:
    writer = DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1), datavalue=True, message_status=True)
    pds = _dataset()
    source = pds.get_source()
    assert isinstance(source, PubSubDataSourceDict)
    source.datasources[String("DS")][String("a")] = DataValue(Variant(), StatusCode(ua.StatusCodes.BadNoCommunication))
    message = await writer.generate_uadp_dataset(pds)
    assert message.Header.Status == ua.StatusCodes.BadNoCommunication >> 16


async def test_pub26_raw_fields_that_cannot_be_sent_make_the_message_invalid_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Part 14, 7.2.4.5.11: a DataSetMessage with fields RawData can't carry has Valid false."""
    meta = DataSetMeta.Create(String("DS"))
    meta.add_scalar(String("s"), VariantType.String)
    pds = pubsub.PublishedDataSet.Create(String("DS"), meta)
    writer = DataSetWriter.new_uadp(String("W"), String("DS"), UInt16(1), raw=True)
    with caplog.at_level(logging.DEBUG):
        first = await writer.generate_uadp_dataset(pds)
        second = await writer.generate_uadp_dataset(pds)
    assert first.Header.Valid is False
    assert second.Header.Valid is False
    assert len([r for r in caplog.records if "RawData" in r.getMessage() and r.levelno >= logging.WARNING]) == 1


async def test_pub19_a_send_failure_puts_the_group_in_error_and_it_recovers(caplog: pytest.LogCaptureFixture) -> None:
    group = _group(interval=20)
    sender = _Sender(fail_times=2)
    states = []
    original = group._set_state

    async def record(state: PubSubState) -> None:
        states.append(state)
        await original(state)

    group._set_state = record  # type: ignore[method-assign]
    with caplog.at_level(logging.DEBUG):
        await _run_for(group, sender, _Registry(_dataset()), 0.2)
    assert PubSubState.Error in states
    assert states.index(PubSubState.Operational, states.index(PubSubState.Error)) > states.index(PubSubState.Error)
    assert sender.rounds


async def test_pub16_group_is_disabled_after_it_was_cancelled() -> None:
    group = _group()
    await _run_for(group, _Sender(), _Registry(_dataset()), 0.05)
    assert await group.get_state() == PubSubState.Disabled


async def test_pub25_group_with_an_address_sends_to_it() -> None:
    """Part 14, 7.3.2.3, 6.4.1.3.4: the destination of a unicast WriterGroup is its datagram transport Address."""
    group = _group(address="opc.udp://192.0.2.7:4850")
    assert isinstance(group._cfg.TransportSettings, DatagramWriterGroupTransport2DataType)
    assert group._cfg.TransportSettings.Address.Url == "opc.udp://192.0.2.7:4850"
    sender = _Sender()
    await _run_for(group, sender, _Registry(_dataset()), 0.05)
    assert sender.resolved == ["opc.udp://192.0.2.7:4850"]
    assert set(sender.destinations) == {("resolved", 1)}


async def test_pub4_promoted_fields_come_from_the_flagged_fields() -> None:
    """Part 14, 6.2.3.2.5, 7.2.4.4.2: promoted fields repeat the flagged fields in the NetworkMessage header."""
    meta = DataSetMeta.Create(String("DS"))
    meta.add_scalar(String("a"), VariantType.Int32)
    meta.add_scalar(String("b"), VariantType.Int32)
    meta.get_field("b").set_promoted(True)  # type: ignore[union-attr]
    pds = pubsub.PublishedDataSet.Create(String("DS"), meta)
    source = pds.get_source()
    assert isinstance(source, PubSubDataSourceDict)
    source.datasources[String("DS")] = {
        String("a"): DataValue(Variant(Int32(1))),
        String("b"): DataValue(Variant(Int32(2))),
    }
    group = _group()
    group._cfg.MessageSettings.NetworkMessageContentMask |= UadpNetworkMessageContentMask.PromotedFields
    sender = _Sender()
    await _run_for(group, sender, _Registry(pds), 0.05)
    assert sender.rounds[0][0].PromotedFields == [Variant(Int32(2))]

import logging

import pytest

from enginir_opcua.common.node import Node
from enginir_opcua.pubsub import DataSetValue, SubscribedDataSetMirror, SubScribedTargetVariables
from enginir_opcua.pubsub.dataset import DataSetMeta
from enginir_opcua.pubsub.reader import DataSetReader
from enginir_opcua.pubsub.subscribed_dataset import FieldTargets
from enginir_opcua.server.server import Server
from enginir_opcua.ua.attribute_ids import AttributeIds
from enginir_opcua.ua.status_codes import StatusCodes
from enginir_opcua.ua.uaprotocol_auto import (
    FieldTargetDataType,
    OverrideValueHandling,
    PubSubState,
    SubscribedDataSetMirrorDataType,
)
from enginir_opcua.ua.uatypes import (
    DataValue,
    Int16,
    Int32,
    LocalizedText,
    NodeId,
    StatusCode,
    String,
    UInt16,
    Variant,
    VariantType,
)

GOOD_5 = DataValue(Variant(Int32(5), VariantType.Int32), StatusCode(StatusCodes.Good))
BAD = DataValue(Variant(), StatusCode(StatusCodes.BadNoCommunication))


async def _target(
    server: Server,
    name: str,
    handling: OverrideValueHandling = OverrideValueHandling.Disabled,
    override: Variant | None = None,
    writable: bool = True,
    attribute: AttributeIds = AttributeIds.Value,
) -> tuple[Node, SubScribedTargetVariables, DataSetMeta]:
    node = await server.nodes.objects.add_variable(NodeId(String(name), Int16(1)), name, 1, VariantType.Int32)
    if writable:
        await node.set_writable()
    meta = DataSetMeta.Create(String(name))
    meta.add_scalar(String("v"), VariantType.Int32)
    field = meta.get_field("v")
    assert field is not None
    config = FieldTargetDataType(
        DataSetFieldId=field.DataSetFieldId,
        TargetNodeId=node.nodeid,
        AttributeId=attribute,
        OverrideValueHandling=handling,
        OverrideValue=override if override is not None else Variant(),
    )
    target = SubScribedTargetVariables(server, [FieldTargets(config)])
    await target.on_state_change(meta, PubSubState.Operational)
    return node, target, meta


def _field(meta: DataSetMeta, value: DataValue) -> list[DataSetValue]:
    field = meta.get_field("v")
    assert field is not None
    return [DataSetValue(String("v"), value, field)]


async def test_pub6_override_value_is_written_for_a_bad_field(server: Server) -> None:
    """Part 14, 6.2.11.1, Table 80: OverrideValue replaces a Bad value with the configured one, Good_LocalOverride."""
    node, target, meta = await _target(server, "Pub6Override", OverrideValueHandling.OverrideValue, Variant(Int32(99)))
    await target.on_dataset_received(meta, _field(meta, BAD))
    value = await node.read_data_value()
    assert value.Value is not None
    assert value.Value.Value == 99
    assert value.StatusCode is not None
    assert value.StatusCode.value == StatusCodes.GoodLocalOverride


async def test_pub6_bad_field_with_disabled_handling_writes_null_and_the_bad_status(server: Server) -> None:
    node, target, meta = await _target(server, "Pub6Disabled")
    await target.on_dataset_received(meta, _field(meta, BAD))
    value = await node.read_data_value(raise_on_bad_status=False)
    assert value.StatusCode is not None
    assert value.StatusCode.value == StatusCodes.BadNoCommunication
    assert value.Value is not None
    assert value.Value.Value is None


async def test_pub27_last_usable_value_keeps_the_value_with_an_uncertain_status(server: Server) -> None:
    node, target, meta = await _target(server, "Pub27Last", OverrideValueHandling.LastUsableValue)
    await target.on_dataset_received(meta, _field(meta, GOOD_5))
    await target.on_dataset_received(meta, _field(meta, BAD))
    value = await node.read_data_value(raise_on_bad_status=False)
    assert value.Value is not None
    assert value.Value.Value == 5
    assert value.StatusCode is not None
    assert value.StatusCode.value == StatusCodes.UncertainLastUsableValue


async def test_pub27_reader_state_changes_update_the_targets(server: Server) -> None:
    """Part 14, 6.2.11.1, Table 80: the targets are updated once when the reader leaves Operational."""
    for handling, error_value, disabled_value in (
        (OverrideValueHandling.OverrideValue, StatusCodes.GoodLocalOverride, StatusCodes.GoodLocalOverride),
        (
            OverrideValueHandling.LastUsableValue,
            StatusCodes.UncertainLastUsableValue,
            StatusCodes.UncertainLastUsableValue,
        ),
        (OverrideValueHandling.Disabled, StatusCodes.BadNoCommunication, StatusCodes.BadOutOfService),
    ):
        node, target, meta = await _target(server, f"Pub27State{handling.name}", handling, Variant(Int32(7)))
        await target.on_dataset_received(meta, _field(meta, GOOD_5))
        await target.on_state_change(meta, PubSubState.Error)
        value = await node.read_data_value(raise_on_bad_status=False)
        assert value.StatusCode is not None
        assert value.StatusCode.value == error_value
        await target.on_dataset_received(meta, _field(meta, GOOD_5))
        await target.on_state_change(meta, PubSubState.Disabled)
        value = await node.read_data_value(raise_on_bad_status=False)
        assert value.StatusCode is not None
        assert value.StatusCode.value == disabled_value


async def test_pub6_the_attribute_id_of_the_target_is_written(server: Server) -> None:
    node, target, meta = await _target(server, "Pub6Attribute", attribute=AttributeIds.Description)
    text = DataValue(Variant(LocalizedText("from the network"), VariantType.LocalizedText))
    await target.on_dataset_received(meta, _field(meta, text))
    assert (await node.read_description()).Text == "from the network"
    assert await node.read_value() == 1


async def test_pub6_unmapped_fields_are_counted_and_logged_once(
    server: Server, caplog: pytest.LogCaptureFixture
) -> None:
    _, target, _meta = await _target(server, "Pub6Unmapped")
    other = DataSetMeta.Create(String("other"))
    other.add_scalar(String("w"), VariantType.Int32)
    field = other.get_field("w")
    assert field is not None
    with caplog.at_level(logging.DEBUG):
        for _ in range(3):
            await target.on_dataset_received(other, [DataSetValue(String("w"), GOOD_5, field)])
    assert target.counters["unmapped fields"] == 3
    assert len([r for r in caplog.records if "no target" in r.getMessage()]) == 1


async def test_pub6_a_target_that_is_not_writable_is_refused_counted_and_logged_once(
    server: Server, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 4, 5.10.4: a value from the network isn't written to a Variable whose AccessLevel doesn't allow it."""
    node, target, meta = await _target(server, "Pub6ReadOnly", writable=False)
    with caplog.at_level(logging.DEBUG):
        for _ in range(3):
            await target.on_dataset_received(meta, _field(meta, GOOD_5))
    assert await node.read_value() == 1
    assert target.counters["refused writes"] == 3
    assert len([r for r in caplog.records if "AccessLevel" in r.getMessage()]) == 1


async def test_pub6_the_sink_is_told_the_dataset_meta_about_state_changes() -> None:
    class Sink:
        def __init__(self) -> None:
            self.metas: list[object] = []

        async def on_dataset_received(self, meta: DataSetMeta, fields: list[DataSetValue]) -> None:
            pass

        async def on_state_change(self, meta: DataSetMeta, state: PubSubState) -> None:
            self.metas.append(meta)

        def get_subscribed_dataset(self) -> None:
            return None

    sink = Sink()
    meta = DataSetMeta.Create(String("Meta"))
    reader = DataSetReader.new(Variant(UInt16(1), VariantType.UInt16), UInt16(1), UInt16(1), meta, "R", True, sink)
    await reader.start()
    await reader.stop()
    assert sink.metas
    assert all(isinstance(m, DataSetMeta) for m in sink.metas)


async def test_pub31_the_mirror_creates_its_variables_once_and_updates_them(server: Server) -> None:
    parent = await server.nodes.objects.add_object(NodeId(String("Pub31Parent"), Int16(1)), "Pub31Parent")
    meta = DataSetMeta.Create(String("Mirror"))
    meta.add_scalar(String("a"), VariantType.Int32)
    meta.add_scalar(String("b"), VariantType.Int32)
    mirror = SubscribedDataSetMirror(SubscribedDataSetMirrorDataType(ParentNodeName="Pub31Mirror"), parent)
    await mirror.on_state_change(meta, PubSubState.Operational)
    await mirror.on_state_change(meta, PubSubState.Operational)
    folder = await parent.get_child("1:Pub31Mirror")
    assert len(await folder.get_children()) == 2
    fields = [
        DataSetValue(f.Name, DataValue(Variant(Int32(i + 10), VariantType.Int32)), f)
        for i, f in enumerate(meta._fields)
    ]
    await mirror.on_dataset_received(meta, fields)
    assert await (await folder.get_child("1:a")).read_value() == 10
    assert await (await folder.get_child("1:b")).read_value() == 11

import dataclasses

from enginir_opcua import pubsub, ua
from enginir_opcua.common.node import Node
from enginir_opcua.pubsub.dataset import (
    DataSetField,
    DataSetMeta,
    PublishedDataItems,
    PubSubDataSourceDict,
    TargetVariable,
    _get_datatype_or_built_in,
)
from enginir_opcua.pubsub.information_model import PubSubInformationModel
from enginir_opcua.server.server import Server
from enginir_opcua.ua.object_ids import ObjectIds
from enginir_opcua.ua.status_codes import StatusCodes
from enginir_opcua.ua.uaprotocol_auto import DataSetFieldFlags
from enginir_opcua.ua.uatypes import (
    DataValue,
    DateTime,
    Int16,
    Int32,
    NodeId,
    StatusCode,
    String,
    Variant,
    VariantType,
)


def test_pub21_add_array_creates_a_one_dimensional_field() -> None:
    meta = DataSetMeta.Create(String("Arrays"))
    meta.add_array(String("a"), VariantType.Int32)
    field = meta.get_field("a")
    assert field is not None
    assert field.ValueRank == 1


def test_pub21_remove_field_removes_it_from_the_fields_and_the_metadata() -> None:
    meta = DataSetMeta.Create(String("Fields"))
    meta.add_scalar(String("a"), VariantType.Int32)
    meta.add_scalar(String("b"), VariantType.Int32)
    meta.remove_field("a")
    assert meta.get_field("a") is None
    assert [f.Name for f in meta.get_config().Fields] == ["b"]
    assert [f.Name for f in meta._fields] == ["b"]


def test_pub21_configuration_version_follows_the_changes() -> None:
    meta = DataSetMeta.Create(String("Versions"))
    version = meta.get_config().ConfigurationVersion
    assert version.MajorVersion == version.MinorVersion
    meta.get_config().ConfigurationVersion.MajorVersion = 100
    meta.get_config().ConfigurationVersion.MinorVersion = 100
    meta.add_scalar(String("a"), VariantType.Int32)
    assert meta.get_config().ConfigurationVersion.MajorVersion == 100
    assert meta.get_config().ConfigurationVersion.MinorVersion > 100
    meta.get_config().ConfigurationVersion.MinorVersion = 100
    meta.remove_field("a")
    version = meta.get_config().ConfigurationVersion
    assert version.MajorVersion > 100
    assert version.MinorVersion == version.MajorVersion


async def test_pub21_published_data_items_create_sets_flags_and_field_metadata(server: Server) -> None:
    node = await server.nodes.objects.add_variable(
        NodeId(String("Pub21Var"), Int16(1)), "Pub21Var", 1, VariantType.Int32
    )
    other = await server.nodes.objects.add_variable(
        NodeId(String("Pub21Other"), Int16(1)), "Pub21Other", 2, VariantType.Int32
    )
    items = await PublishedDataItems.Create(
        String("Pub21"),
        server,
        [TargetVariable("a", node.nodeid, Promoted=True), TargetVariable("b", other.nodeid, Promoted=False)],
    )
    fields = items.dataset.get_config().Fields
    assert all(isinstance(f, ua.FieldMetaData) for f in fields)
    assert DataSetFieldFlags.PromotedField in fields[0].FieldFlags
    assert DataSetFieldFlags.PromotedField not in fields[1].FieldFlags
    version = items.dataset.get_config().ConfigurationVersion
    assert version.MajorVersion == version.MinorVersion != 0


def test_pub26_built_in_type_of_derived_and_abstract_data_types() -> None:
    cases = {
        ObjectIds.Duration: VariantType.Double,
        ObjectIds.UtcTime: VariantType.DateTime,
        ObjectIds.Counter: VariantType.UInt32,
        ObjectIds.Number: VariantType.Variant,
        ObjectIds.Enumeration: VariantType.Int32,
        ObjectIds.Structure: VariantType.ExtensionObject,
        ObjectIds.BaseDataType: VariantType.Variant,
        ObjectIds.DiagnosticInfo: VariantType.DiagnosticInfo,
        ObjectIds.Int32: VariantType.Int32,
    }
    for object_id, expected in cases.items():
        _, built_in = _get_datatype_or_built_in(NodeId(object_id))
        assert built_in == expected.value, object_id


def test_pub26_datatype_name_is_looked_up_in_the_given_registry() -> None:
    class Custom:
        pass

    registry = ua.TypeRegistry()
    custom_id = NodeId(String("Pub26Custom"), Int16(2))
    registry.register_alias(custom_id, Custom, "Custom")
    field = DataSetField(ua.FieldMetaData(Name="c", DataType=custom_id, BuiltInType=ua.Byte(0)))
    assert field.get_datatype_name(registry) == "Custom"


async def test_pub22_get_value_leaves_the_stored_values_alone() -> None:
    meta = DataSetMeta.Create(String("Source"))
    meta.add_scalar(String("a"), VariantType.Int32)
    source = PubSubDataSourceDict(meta)
    stored = DataValue(Variant(Int32(1)), StatusCode(0), SourceTimestamp=DateTime.now(), ServerTimestamp=DateTime.now())
    before = dataclasses.replace(stored)
    source.datasources[String("Source")] = {String("a"): stored}
    values = await source.get_value(False, False, False)
    assert values[0].StatusCode is None
    assert values[0].SourceTimestamp is None
    assert values[0].ServerTimestamp is None
    assert stored == before


async def test_pub27_bad_and_uncertain_fields_are_sent_as_status_code_and_data_value_variants() -> None:
    meta = DataSetMeta.Create(String("Status"))
    for name in ("good", "bad", "uncertain"):
        meta.add_scalar(String(name), VariantType.Int32)
    source = PubSubDataSourceDict(meta)
    source.datasources[String("Status")] = {
        String("good"): DataValue(Variant(Int32(1)), StatusCode(StatusCodes.Good)),
        String("bad"): DataValue(Variant(), StatusCode(StatusCodes.BadNoCommunication)),
        String("uncertain"): DataValue(Variant(Int32(3)), StatusCode(StatusCodes.UncertainSubstituteValue)),
    }
    values, status, _ = await source.get_variant()
    assert values[0] == Variant(Int32(1))
    assert values[1].VariantType == VariantType.StatusCode
    assert values[1].Value.value == StatusCodes.BadNoCommunication
    assert values[2].VariantType == VariantType.DataValue
    assert values[2].Value.Value == Variant(Int32(3))
    assert status.value == StatusCodes.BadNoCommunication


async def test_pub26_null_values_are_encoded_as_raw_data_not_dropped() -> None:
    meta = DataSetMeta.Create(String("Raw"))
    meta.add_scalar(String("a"), VariantType.Int32)
    meta.add_scalar(String("b"), VariantType.Int32)
    source = PubSubDataSourceDict(meta)
    source.datasources[String("Raw")] = {String("b"): DataValue(Variant(Int32(7)))}
    raw, status, _ = await source.get_raw(meta.get_config().Fields)
    assert raw == [bytes(4), (7).to_bytes(4, "little")]
    assert not status.is_good()


async def test_pub23_get_node_value_returns_the_value(server: Server) -> None:
    node: Node = await server.nodes.objects.add_variable(
        NodeId(String("Pub23Var"), Int16(1)), "Pub23Var", 5, VariantType.Int32
    )

    class Model(PubSubInformationModel):
        pass

    model = Model()
    model._node = server.nodes.objects
    value = await model.get_node_value("0:Pub23Var")
    assert value == 5
    assert node is not None


async def test_pub20_a_loaded_published_data_items_dataset_reads_the_servers_variables(
    server: Server, tmp_path
) -> None:
    node = await server.nodes.objects.add_variable(
        NodeId(String("Pub20Var"), Int16(1)), "Pub20Var", 41, VariantType.Int32
    )
    items = await PublishedDataItems.Create(String("Pub20"), server, [TargetVariable("v", node.nodeid)])
    saver = pubsub.PubSub.new(connections=[], datasets=[items])
    path = tmp_path / "pub20.bin"
    await saver.save_binary_file(path)
    loader = pubsub.PubSub(None, server)
    await loader.load_binary_file(path)
    loaded = loader.get_published_dataset(String("Pub20"))
    assert loaded is not None
    values, status, _ = await loaded.get_source().get_variant()
    assert values == [Variant(Int32(41))]
    assert status.is_good()


async def test_pub32_a_saved_configuration_file_can_be_loaded_again(tmp_path) -> None:
    meta = DataSetMeta.Create(String("Saved"))
    meta.add_scalar(String("a"), VariantType.Int32)
    saver = pubsub.PubSub.new(connections=[], datasets=[pubsub.PublishedDataSet.Create(String("Saved"), meta)])
    path = tmp_path / "saved.bin"
    await saver.save_binary_file(path)
    loader = pubsub.PubSub()
    await loader.load_binary_file(path)
    loaded = loader.get_published_dataset(String("Saved"))
    assert loaded is not None
    assert [f.Name for f in loaded.dataset.get_config().Fields] == ["a"]

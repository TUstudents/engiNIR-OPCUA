import pytest

from enginir_opcua import ua
from enginir_opcua.common.structures104 import new_enum, new_enum_field, new_struct, new_struct_field
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import struct_from_binary, struct_to_binary

pytestmark = pytest.mark.asyncio


def test_ua56_data_type_attributes_follow_the_wire_layout_of_part_4() -> None:
    """Part 4, 7.24.8: the body has no DataTypeDefinition, and bit 22 of SpecifiedAttributes is reserved."""
    attributes = ua.DataTypeAttributes(DisplayName=ua.LocalizedText("T"), IsAbstract=True)
    assert not attributes.SpecifiedAttributes & ua.NodeAttributesMask.DataTypeDefinition
    body = struct_to_binary(attributes)
    reference = struct_to_binary(
        ua.uaprotocol_auto.DataTypeAttributes(
            SpecifiedAttributes=attributes.SpecifiedAttributes,
            DisplayName=ua.LocalizedText("T"),
            IsAbstract=True,
        )
    )
    assert body == reference
    buffer = Buffer(body + b"\xff")
    decoded = struct_from_binary(ua.DataTypeAttributes, buffer)
    assert decoded.DisplayName.Text == "T"
    assert bytes(buffer) == b"\xff"


async def test_ua56_a_data_type_added_through_a_session_can_get_a_definition(opc) -> None:
    uri = "urn:test:ua56"
    ns = await opc.opc.register_namespace(uri)
    dtype, _ = await new_struct(opc.opc, ns, "Ua56Struct", [new_struct_field("a", ua.VariantType.Int32)])
    definition = await dtype.read_data_type_definition()
    assert isinstance(definition, ua.StructureDefinition)
    assert [field.Name for field in definition.Fields] == ["a"]


async def test_com41_array_field_has_unknown_maximum_length() -> None:
    assert new_struct_field("a", ua.VariantType.Int32, array=True).ArrayDimensions == [0]
    scalar = new_struct_field("a", ua.VariantType.Int32)
    assert scalar.ArrayDimensions is None
    assert scalar.ValueRank == ua.ValueRank.Scalar


async def test_com89_new_enum_keeps_given_values_and_does_not_change_its_arguments(opc) -> None:
    ns = await opc.opc.register_namespace("urn:test:com89a")
    given = new_enum_field("Big")
    given.Value = 100
    node = await new_enum(opc.opc, ns, "Com89Enum", [given, "Next", "Last"])
    definition = await node.read_data_type_definition()
    assert isinstance(definition, (ua.EnumDefinition, ua.StructureDefinition))
    assert [(field.Name, field.Value) for field in definition.Fields] == [("Big", 100), ("Next", 101), ("Last", 102)]
    assert given.Value == 100


async def test_com89_overwrite_existing_replaces_a_changed_definition(opc) -> None:
    ns = await opc.opc.register_namespace("urn:test:com89b")
    node, _ = await new_struct(opc.opc, ns, "Com89Changing", [new_struct_field("a", ua.VariantType.Int32)])
    await opc.opc.load_data_type_definitions()
    first = opc.opc.types.by_name("Com89Changing")
    definition = await node.read_data_type_definition()
    assert isinstance(definition, (ua.EnumDefinition, ua.StructureDefinition))
    definition.Fields.append(new_struct_field("b", ua.VariantType.Int32))
    await node.write_data_type_definition(definition)
    await opc.opc.load_data_type_definitions()
    assert opc.opc.types.by_name("Com89Changing") is first
    await opc.opc.load_data_type_definitions(overwrite_existing=True)
    assert opc.opc.types.get(node.nodeid) is not first
    assert {field.name for field in __import__("dataclasses").fields(opc.opc.types.get(node.nodeid))} == {"a", "b"}


async def test_com42_enumeration_members_that_clean_to_the_same_name_are_an_error() -> None:
    from enginir_opcua.common.structures104 import make_enum

    definition = ua.EnumDefinition()
    for name, value in (("A-B", 0), ("A_B", 1)):
        field = new_enum_field(name)
        field.Value = value
        definition.Fields.append(field)
    with pytest.raises(ua.UaError, match="A_B"):
        make_enum("Clash", definition, False)


async def test_com42_generated_defaults_do_not_depend_on_time_or_randomness(opc) -> None:
    ns = await opc.opc.register_namespace("urn:test:com42")
    await new_struct(
        opc.opc,
        ns,
        "Com42Defaults",
        [new_struct_field("g", ua.NodeId(ua.ObjectIds.Guid)), new_struct_field("t", ua.NodeId(ua.ObjectIds.DateTime))],
    )
    await opc.opc.load_data_type_definitions()
    cls = opc.opc.types.by_name("Com42Defaults")
    assert cls() == cls()

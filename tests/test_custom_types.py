import enum
import struct
from typing import Any

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


def _structure_definition(*fields: ua.StructureField, kind: ua.StructureType = ua.StructureType.Structure):
    definition = ua.StructureDefinition()
    definition.StructureType = kind
    definition.Fields = list(fields)
    return definition


def _matrix_field(name: str, rank: int, datatype: int = ua.ObjectIds.Int32) -> ua.StructureField:
    field = ua.StructureField()
    field.Name = name
    field.DataType = ua.NodeId(datatype)
    field.ValueRank = rank
    field.ArrayDimensions = [0] * rank
    return field


def test_com89_c_matrix_field_is_encoded_inline() -> None:
    """Part 6, 5.2.5, Table 28: the dimensions, then the values flat."""
    from enginir_opcua.common.structures104 import make_structure

    cls = make_structure(ua.NodeId(70001, 2), "Com89Matrix", _structure_definition(_matrix_field("M", 2)))[
        "Com89Matrix"
    ]
    value = cls(M=[[1, 2, 3], [4, 5, 6]])
    expected = struct.pack("<i", 2) + struct.pack("<ii", 2, 3) + struct.pack("<6i", 1, 2, 3, 4, 5, 6)
    assert struct_to_binary(value) == expected
    assert struct_from_binary(cls, Buffer(expected)).M == [[1, 2, 3], [4, 5, 6]]


def test_com89_c_matrix_field_of_rank_three_and_empty_matrix() -> None:
    from enginir_opcua.common.structures104 import make_structure

    cls = make_structure(ua.NodeId(70002, 2), "Com89Matrix3", _structure_definition(_matrix_field("M", 3)))[
        "Com89Matrix3"
    ]
    nested = [[[1, 2], [3, 4]], [[5, 6], [7, 8]]]
    data = struct_to_binary(cls(M=nested))
    assert data[:16] == struct.pack("<iiii", 3, 2, 2, 2)
    assert struct_from_binary(cls, Buffer(data)).M == nested
    assert struct_from_binary(cls, Buffer(struct_to_binary(cls()))).M == []


def test_com89_c_matrix_field_with_inconsistent_dimensions_is_rejected() -> None:
    from enginir_opcua.common.structures104 import make_structure

    cls = make_structure(ua.NodeId(70003, 2), "Com89MatrixBad", _structure_definition(_matrix_field("M", 2)))[
        "Com89MatrixBad"
    ]
    with pytest.raises(ua.UaError):
        struct_from_binary(cls, Buffer(struct.pack("<iii", 2, 1_000_000, 1_000_000)))


def test_com89_d_union_with_subtyped_values_is_built() -> None:
    from enginir_opcua.common.structures104 import make_structure

    anything = ua.StructureField()
    anything.Name = "Anything"
    anything.DataType = ua.NodeId(ua.ObjectIds.Structure)
    anything.ValueRank = ua.ValueRank.Scalar
    anything.IsOptional = True
    number = ua.StructureField()
    number.Name = "Number"
    number.DataType = ua.NodeId(ua.ObjectIds.Int32)
    number.ValueRank = ua.ValueRank.Scalar
    definition = _structure_definition(anything, number, kind=ua.StructureType.UnionWithSubtypedValues)
    cls: Any = make_structure(ua.NodeId(70004, 2), "Com89SubtypedUnion", definition)["Com89SubtypedUnion"]
    assert issubclass(cls, ua.UaUnion)
    value = cls()
    value.Anything = ua.ReadValueId()
    decoded = struct_from_binary(cls, Buffer(struct_to_binary(value)))
    assert decoded.Encoding == 1
    assert isinstance(decoded.Anything, ua.ReadValueId)
    other = cls()
    other.Number = 7
    assert struct_from_binary(cls, Buffer(struct_to_binary(other))).Number == 7


async def _option_set_below(opc, base_id: int, ns: int, name: str, bits: list[str]):
    base = opc.opc.get_node(ua.NodeId(base_id))
    node = await base.add_data_type(ns, name)
    definition = ua.EnumDefinition()
    for position, bit in enumerate(bits):
        entry = new_enum_field(bit)
        entry.Value = position
        definition.Fields.append(entry)
    await node.write_data_type_definition(definition)
    return node


@pytest.mark.parametrize(
    "base_id,size",
    [(ua.ObjectIds.Byte, 1), (ua.ObjectIds.UInt16, 2), (ua.ObjectIds.UInt32, 4), (ua.ObjectIds.UInt64, 8)],
)
async def test_com89_e_option_set_has_the_width_of_its_base_type(opc, base_id: int, size: int) -> None:
    ns = await opc.opc.register_namespace(f"urn:test:com89e{size}")
    node = await _option_set_below(opc, base_id, ns, f"Com89Bits{size}", ["A", "B", "C"])
    await opc.opc.load_data_type_definitions()
    bits = opc.opc.types.get(node.nodeid)
    assert issubclass(bits, enum.IntFlag)
    assert bits.B == 2
    holder = ua.StructureField()
    holder.Name = "Flags"
    holder.DataType = node.nodeid
    holder.ValueRank = ua.ValueRank.Scalar
    holder_node, _ = await new_struct(opc.opc, ns, f"Com89Holder{size}", [holder])
    await opc.opc.load_data_type_definitions()
    cls = opc.opc.types.get(holder_node.nodeid)
    data = struct_to_binary(cls(Flags=bits.A | bits.C))
    assert len(data) == size
    assert struct_from_binary(cls, Buffer(data)).Flags == bits.A | bits.C


@pytest.mark.parametrize("kind", ["strings", "values"])
async def test_com89_f_enumeration_without_definition_uses_its_properties(opc, kind: str) -> None:
    ns = await opc.opc.register_namespace(f"urn:test:com89f{kind}")
    node = await opc.opc.nodes.enum_data_type.add_data_type(ns, f"Com89Props{kind}")
    if kind == "strings":
        await node.add_property(
            ua.NodeId(0, ns),
            ua.QualifiedName("EnumStrings", 0),
            [ua.LocalizedText("Off"), ua.LocalizedText("On")],
            ua.VariantType.LocalizedText,
        )
        expected = {"Off": 0, "On": 1}
    else:
        values = [
            ua.EnumValueType(Value=5, DisplayName=ua.LocalizedText("Five")),
            ua.EnumValueType(Value=9, DisplayName=ua.LocalizedText("Nine")),
        ]
        await node.add_property(
            ua.NodeId(0, ns), ua.QualifiedName("EnumValues", 0), values, ua.VariantType.ExtensionObject
        )
        expected = {"Five": 5, "Nine": 9}
    await opc.opc.load_data_type_definitions()
    enum_cls = opc.opc.types.get(node.nodeid)
    assert {member.name: member.value for member in enum_cls} == expected

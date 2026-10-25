import array
import io
import struct
import typing
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Optional

import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua import ua_binary
from enginir_opcua.ua.ua_binary import (
    _reshape,
    extensionobject_from_binary,
    extensionobject_to_binary,
    from_binary,
    list_to_binary,
    nodeid_from_binary,
    nodeid_to_binary,
    pack_uatype_array,
    struct_to_binary,
    to_binary,
    unpack_uatype_array,
    variant_from_binary,
)

UNKNOWN_TYPE_ID = bytes.fromhex("01 02 0500")


@dataclass
class _Empty:
    pass


@dataclass
class _Item:
    Value: ua.Int32 = 0


@dataclass
class _Holder:
    Items: list[_Item] = field(default_factory=list)
    Numbers: list[ua.Int32] = field(default_factory=list)


@dataclass
class _EmptyHolder:
    Items: list[_Empty] = field(default_factory=list)


@dataclass
class _WithOptional:
    Encoding: ua.UInt32 = field(default=0, repr=False, init=True, compare=False)
    Required: ua.Int32 = 0
    First: ua.Int32 | None = None
    Second: ua.Int32 | None = None


@dataclass
class _Wrapper:
    Inner: ua.ExtensionObject = field(default_factory=ua.ExtensionObject)


@dataclass
class _Chain:
    Encoding: ua.UInt32 = field(default=0, repr=False, init=True, compare=False)
    Child: "_Chain | None" = None


@dataclass
class _IntOrText(ua.UaUnion):
    _union_types: ClassVar[list[Any]] = [ua.Int32, ua.String]
    Encoding: ua.UInt32 = field(default=0, repr=False, compare=False)
    Value: Any = None


class _Color(Enum):
    Red = 1
    Green = 2


def test_ua37_extensionobject_xml_body_is_read() -> None:
    """Part 6, 5.2.2.15: encoding byte 2 is followed by an Int32 length and the XML bytes."""
    data = UNKNOWN_TYPE_ID + bytes.fromhex("02 04000000") + b"<a/>" + bytes.fromhex("d2040000")
    buf = Buffer(data)
    obj = extensionobject_from_binary(buf)
    assert obj.TypeId == ua.NodeId(5, 2)
    assert obj.Body == b"<a/>"
    assert ua_binary.Primitives.Int32.unpack(buf) == 1234


def test_ua37_extensionobject_xml_body_round_trips() -> None:
    """Part 6, 5.2.2.15: encoding byte 2 is followed by an Int32 length and the XML bytes."""
    data = UNKNOWN_TYPE_ID + bytes.fromhex("02 04000000") + b"<a/>"
    assert extensionobject_to_binary(extensionobject_from_binary(Buffer(data))) == data


def test_ua37_extensionobject_unknown_encoding_raises() -> None:
    """Part 6, 5.2.2.15: only encodings 0, 1 and 2 are defined."""
    with pytest.raises(ua.UaError):
        extensionobject_from_binary(Buffer(UNKNOWN_TYPE_ID + bytes.fromhex("03 00000000")))


def test_ua38_extensionobject_empty_structure_has_length() -> None:
    """Part 6, 5.2.2.15: the length is written whenever the encoding byte is 1."""
    data = extensionobject_to_binary(ua.MonitoringFilter())
    assert data == bytes.fromhex("01 00 d102 01 00000000")
    buf = Buffer(data + bytes.fromhex("d2040000"))
    assert isinstance(extensionobject_from_binary(buf), ua.MonitoringFilter)
    assert ua_binary.Primitives.Int32.unpack(buf) == 1234


def test_ua39_null_struct_array_decodes_as_empty_list_by_decision() -> None:
    """Part 6, 5.1.11: null and empty arrays are equal; decided: null struct arrays decode as an empty list."""
    holder = from_binary(_Holder, Buffer(bytes.fromhex("ffffffff ffffffff")))
    assert holder.Items == []
    assert holder.Numbers is None


def test_ua39_empty_struct_array_decodes_as_empty_list() -> None:
    """Part 6, 5.2.5: a count of 0 is an empty array."""
    holder = from_binary(_Holder, Buffer(bytes.fromhex("00000000 00000000")))
    assert holder.Items == []


def test_ua40_array_accepts_any_iterable() -> None:
    """Part 6, 5.2.5: the array is encoded from its elements, whatever container holds them."""
    expected = bytes.fromhex("03000000 01000000 02000000 03000000")
    assert pack_uatype_array(ua.VariantType.Int32, iter([1, 2, 3])) == expected  # type: ignore[arg-type]
    assert pack_uatype_array(ua.VariantType.Int32, range(1, 4)) == expected  # type: ignore[arg-type]
    assert pack_uatype_array(ua.VariantType.Int32, array.array("i", [1, 2, 3])) == expected  # type: ignore[arg-type]
    assert list_to_binary(ua.Int32, (i for i in (1, 2, 3))) == expected  # type: ignore[arg-type]


def test_ua40_non_primitive_array_accepts_any_iterable() -> None:
    """Part 6, 5.2.5: the array is encoded from its elements, whatever container holds them."""
    expected = bytes.fromhex("02000000 01000000 61 01000000 62")
    assert pack_uatype_array(ua.VariantType.String, iter(["a", "b"])) == expected  # type: ignore[arg-type]
    assert list_to_binary(ua.String, iter(["a", "b"])) == expected  # type: ignore[arg-type]


def test_ua40_array_scalar_raises() -> None:
    """Part 6, 5.2.5: a scalar is not an array."""
    with pytest.raises(ua.UaError):
        pack_uatype_array(ua.VariantType.Int32, 5)  # type: ignore[arg-type]
    with pytest.raises(ua.UaError):
        pack_uatype_array(ua.VariantType.String, "abc")  # type: ignore[arg-type]
    with pytest.raises(ua.UaError):
        list_to_binary(ua.String, 5)  # type: ignore[arg-type]


def test_ua40_array_none_is_null() -> None:
    assert pack_uatype_array(ua.VariantType.Int32, None) == bytes.fromhex("ffffffff")
    assert list_to_binary(ua.String, None) == bytes.fromhex("ffffffff")


def test_ua41_plain_enum_is_encoded_by_value() -> None:
    """Part 6, 5.2.4: an enumeration is an Int32."""
    assert to_binary(_Color, _Color.Green) == bytes.fromhex("02000000")
    assert from_binary(_Color, Buffer(bytes.fromhex("02000000"))) is _Color.Green


def test_ua42_strip_optional_handles_both_spellings() -> None:
    assert ua_binary.strip_optional(Optional[int]) is int  # noqa: UP045
    assert ua_binary.strip_optional(typing.Union[int, None]) is int  # noqa: UP007
    assert ua_binary.strip_optional(int | None) is int
    assert ua_binary.strip_optional(int) is int


def test_ua42_bit_helper_is_not_named_like_a_test() -> None:
    assert not hasattr(ua_binary, "test_bit")
    assert ua_binary.is_bit_set(0b100, 2)
    assert not ua_binary.is_bit_set(0b100, 1)


def test_ua44_extensionobject_length_minus_one_unknown_type_raises() -> None:
    """Part 6, 5.2.2.15: the extent of an unknown body is only known from its length."""
    data = UNKNOWN_TYPE_ID + bytes.fromhex("01 ffffffff 61626364")
    with pytest.raises(ua.UaError):
        extensionobject_from_binary(Buffer(data))


def test_ua44_extensionobject_length_minus_one_known_type_decodes_from_stream() -> None:
    """Interop with stacks that omit the length, only for types this library knows."""
    data = bytes.fromhex("01 00 d102 01 ffffffff d2040000")
    buf = Buffer(data)
    assert isinstance(extensionobject_from_binary(buf), ua.MonitoringFilter)
    assert ua_binary.Primitives.Int32.unpack(buf) == 1234


def test_ua44_extensionobject_length_below_minus_one_raises() -> None:
    """Part 6, 5.2.2.15: a length is -1 or not negative."""
    with pytest.raises(ua.UaError):
        extensionobject_from_binary(Buffer(UNKNOWN_TYPE_ID + bytes.fromhex("01 fdffffff 6162")))


def test_ua44_extensionobject_length_beyond_data_raises() -> None:
    """Part 6, 5.2.2.15: the body is as long as its length says."""
    with pytest.raises(ua.UaError):
        extensionobject_from_binary(Buffer(UNKNOWN_TYPE_ID + bytes.fromhex("01 10000000 6162")))


def _variant_with_dimensions(count: int, dims: list[int] | None) -> bytes:
    body = bytes([0xC0 | ua.VariantType.Int32.value]) + struct.pack(f"<i{count}i", count, *range(count))
    if dims is None:
        return body + struct.pack("<i", -1)
    return body + struct.pack(f"<i{len(dims)}i", len(dims), *dims)


def test_ua44_variant_dimensions_match_count() -> None:
    """Part 6, 5.2.2.16: the dimensions multiply up to the number of elements."""
    variant = variant_from_binary(Buffer(_variant_with_dimensions(6, [2, 3])))
    assert variant.Value == [[0, 1, 2], [3, 4, 5]]


@pytest.mark.parametrize("dims", [[2, 4], [2, 2], [7], [2, 3, 2]])
def test_ua44_variant_dimensions_mismatch_raises(dims: list[int]) -> None:
    """Part 6, 5.2.2.16: inconsistent dimensions are a decoding error."""
    with pytest.raises(ua.UaError):
        variant_from_binary(Buffer(_variant_with_dimensions(6, dims)))


@pytest.mark.parametrize("dims", [[0, 6], [-2, -3], [6, 0]])
def test_ua44_variant_dimensions_zero_or_negative_raise(dims: list[int]) -> None:
    """Part 6, 5.2.2.16: every dimension is greater than zero."""
    with pytest.raises(ua.UaError):
        variant_from_binary(Buffer(_variant_with_dimensions(6, dims)))


@pytest.mark.parametrize("dims", [[0, 3], [3, 0], [0, 0]])
def test_ua44_variant_zero_dimension_accepted_for_empty_array(dims: list[int]) -> None:
    """Part 6, 5.2.2.16: the array length is 0 if a dimension is 0; older peers may still send the field."""
    data = bytes([0xC0 | ua.VariantType.Int32.value]) + struct.pack(f"<ii{len(dims)}i", 0, len(dims), *dims)
    variant = variant_from_binary(Buffer(data))
    assert variant.Value == []
    assert variant.Dimensions == dims


def test_ua44_variant_null_array_with_zero_dimension_accepted() -> None:
    """Part 6, 5.2.2.16: the array length is 0 if a dimension is 0."""
    data = bytes([0xC0 | ua.VariantType.Int32.value]) + struct.pack("<iiii", -1, 2, 0, 3)
    assert variant_from_binary(Buffer(data)).Dimensions == [0, 3]


def test_ua44_variant_empty_array_with_positive_dimensions_raises() -> None:
    """Part 6, 5.2.2.16: dimensions must agree with the array length."""
    data = bytes([0xC0 | ua.VariantType.Int32.value]) + struct.pack("<iiii", 0, 2, 2, 3)
    with pytest.raises(ua.UaError):
        variant_from_binary(Buffer(data))


def test_ua44_variant_negative_dimension_raises_for_empty_array() -> None:
    """Part 6, 5.2.2.16: negative dimensions are invalid."""
    data = bytes([0xC0 | ua.VariantType.Int32.value]) + struct.pack("<iiii", 0, 2, -1, 3)
    with pytest.raises(ua.UaError):
        variant_from_binary(Buffer(data))


def test_ua44_variant_dimensions_null_raises() -> None:
    """Part 6, 5.2.2.16: the dimension flag needs the dimensions."""
    with pytest.raises(ua.UaError):
        variant_from_binary(Buffer(_variant_with_dimensions(6, None)))


def test_ua44_reshape_short_list_raises() -> None:
    with pytest.raises(ua.UaError):
        _reshape([1, 2, 3], [2, 3])


def test_ua44_empty_multidimensional_variant_round_trips() -> None:
    """Part 6, 5.2.2.16: the dimension field is only written for dimensions greater than zero."""
    variant = ua.Variant([[], [], []], ua.VariantType.Int32)
    assert variant_from_binary(Buffer(ua_binary.variant_to_binary(variant))).Value == []


def test_ua47_negative_array_count_raises() -> None:
    """Part 6, 5.2.5: -1 is the only negative count."""
    data = struct.pack("<i", -2)
    with pytest.raises(ua.UaError):
        unpack_uatype_array(ua.VariantType.Int32, Buffer(data))
    with pytest.raises(ua.UaError):
        unpack_uatype_array(ua.VariantType.String, Buffer(data))
    with pytest.raises(ua.UaError):
        from_binary(_Holder, Buffer(data + struct.pack("<i", -1)))
    with pytest.raises(ua.UaError):
        from_binary(_Holder, Buffer(struct.pack("<ii", -1, -5)))


def test_ua47_count_beyond_remaining_bytes_raises() -> None:
    """Part 6, 5.2.5: every element takes at least one byte."""
    data = struct.pack("<i", 1_000_000) + b"\x00" * 10
    for vtype in (ua.VariantType.Int32, ua.VariantType.String, ua.VariantType.Variant):
        with pytest.raises(ua.UaError):
            unpack_uatype_array(vtype, Buffer(data))
    with pytest.raises(ua.UaError):
        from_binary(_Holder, Buffer(data))


def test_ua47_zero_size_elements_are_capped() -> None:
    """Part 6, 5.2.6: a structure without fields has no bytes, so a count cannot be checked against the data."""
    ok = from_binary(_EmptyHolder, Buffer(struct.pack("<i", 65_536)))
    assert len(ok.Items) == 65_536
    with pytest.raises(ua.UaError):
        from_binary(_EmptyHolder, Buffer(struct.pack("<i", 5_000_000)))
    with pytest.raises(ua.UaError):
        unpack_uatype_array(ua.VariantType.Null, Buffer(struct.pack("<i", 5_000_000)))


def test_ua48_union_switch_above_field_count_raises_on_decode() -> None:
    """Part 6, 5.2.8: the switch value selects a field or means no field."""
    assert from_binary(_IntOrText, Buffer(bytes.fromhex("00000000"))).Value is None
    assert from_binary(_IntOrText, Buffer(bytes.fromhex("01000000 07000000"))).Value == 7
    with pytest.raises(ua.UaError):
        from_binary(_IntOrText, Buffer(bytes.fromhex("03000000 07000000")))


def test_ua48_union_switch_above_field_count_raises_on_encode() -> None:
    """Part 6, 5.2.8: the switch value selects a field or means no field."""
    with pytest.raises(ua.UaError):
        struct_to_binary(_IntOrText(Encoding=3, Value=1))
    assert struct_to_binary(_IntOrText(Encoding=2, Value="a")) == bytes.fromhex("02000000 01000000 61")


def test_ua48_unassigned_optional_mask_bit_raises() -> None:
    """Part 6, 5.2.7: only the bits of the optional fields may be set."""
    ok = from_binary(_WithOptional, Buffer(bytes.fromhex("03000000 05000000 01000000 02000000")))
    assert (ok.Required, ok.First, ok.Second) == (5, 1, 2)
    with pytest.raises(ua.UaError):
        from_binary(_WithOptional, Buffer(bytes.fromhex("04000000 05000000")))


def test_ua50_nodeid_bad_format_raises_uaerror() -> None:
    """Part 6, 5.2.2.9: formats 0 to 5 are defined."""
    for first in (6, 7, 0x3F, 0x46, 0xBF):
        with pytest.raises(ua.UaError):
            nodeid_from_binary(Buffer(bytes([first]) + b"\x00" * 8))


def test_ua50_unknown_enum_value_raises_uaerror() -> None:
    """Part 6, 5.2.4: an enumeration value outside the defined ones is a decoding error here."""
    assert from_binary(ua.MessageSecurityMode, Buffer(struct.pack("<i", 2))) == ua.MessageSecurityMode.Sign
    with pytest.raises(ua.UaError):
        from_binary(ua.MessageSecurityMode, Buffer(struct.pack("<i", 99)))
    with pytest.raises(ua.UaError):
        from_binary(_Color, Buffer(struct.pack("<i", 9)))


def test_ua50_short_read_from_stream_raises_uaerror() -> None:
    """Part 6, 5.2.2.2: a value is as wide as its type."""
    with pytest.raises(ua.UaError):
        ua_binary.Primitives.Int32.unpack(io.BytesIO(b"\x01"))
    with pytest.raises(ua.UaError):
        nodeid_from_binary(io.BytesIO(b"\x01\x02"))
    with pytest.raises(ua.UaError):
        ua_binary.Primitives.Guid.unpack(io.BytesIO(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"))
    with pytest.raises(ua.UaError):
        ua_binary.Primitives.String.unpack(io.BytesIO(bytes.fromhex("05000000 6162")))


def _nested_variants(depth: int) -> bytes:
    prefix = bytes([0x80 | ua.VariantType.Variant.value]) + struct.pack("<i", 1)
    return prefix * depth + b"\x00"


def test_ua51_variant_nesting_is_bounded() -> None:
    """Part 6, 5.2.2.16: a Variant holds arrays of Variants; the depth is limited by this library."""
    with pytest.raises(ua.UaError):
        variant_from_binary(Buffer(_nested_variants(5_000)))
    variant_from_binary(Buffer(_nested_variants(50)))


def test_ua51_self_containing_structure_nesting_is_bounded() -> None:
    """Part 6, 5.2.7: a structure may contain itself; the depth is limited by this library."""
    deep = bytes.fromhex("01000000") * 5_000 + bytes.fromhex("00000000")
    with pytest.raises(ua.UaError):
        from_binary(_Chain, Buffer(deep))
    shallow = bytes.fromhex("01000000") * 20 + bytes.fromhex("00000000")
    assert from_binary(_Chain, Buffer(shallow)).Child is not None


def test_ua51_extensionobject_nesting_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 6, 5.2.2.15: ExtensionObjects can hold ExtensionObjects; the depth is limited by this library."""
    type_id = ua.NodeId(9999, 2)
    monkeypatch.setitem(ua.extension_objects_by_typeid, type_id, _Wrapper)
    wrapped = bytes.fromhex("00 00 00")
    for _ in range(2_000):
        wrapped = nodeid_to_binary(type_id) + b"\x01" + struct.pack("<i", len(wrapped)) + wrapped
    with pytest.raises(ua.UaError):
        extensionobject_from_binary(Buffer(wrapped))


def test_ua52_null_extensionobject_needs_whole_nodeid() -> None:
    """Part 6, 5.2.2.15: the null ExtensionObject has the null NodeId; ns=2;i=0 is not null."""
    obj = extensionobject_from_binary(Buffer(bytes.fromhex("01 02 0000 01 00000000")))
    assert obj.TypeId == ua.NodeId(0, 2)
    assert obj.Body == b""
    assert extensionobject_from_binary(Buffer(bytes.fromhex("00 00 00"))) == ua.ExtensionObject()


def test_ua53_localizedtext_omits_empty_fields() -> None:
    """Part 6, 5.2.2.14: a field that is null or empty is not written."""
    assert struct_to_binary(ua.LocalizedText("", "")) == b"\x00"
    assert struct_to_binary(ua.LocalizedText("a", "")) == bytes.fromhex("02 01000000 61")
    assert struct_to_binary(ua.LocalizedText("", "en")) == bytes.fromhex("01 02000000 656e")
    assert struct_to_binary(ua.LocalizedText("a", "en")) == bytes.fromhex("03 02000000 656e 01000000 61")
    assert struct_to_binary(ua.LocalizedText()) == b"\x00"


def test_ua53_localizedtext_empty_fields_decode_as_null() -> None:
    """Part 6, 5.2.2.14: an absent field is null."""
    text = from_binary(ua.LocalizedText, Buffer(bytes.fromhex("02 01000000 61")))
    assert text.Text == "a"
    assert text.Locale is None

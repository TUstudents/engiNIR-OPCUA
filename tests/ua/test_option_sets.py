import pytest

from enginir_opcua import ua
from enginir_opcua.ua import ua_binary
from enginir_opcua.ua.uatypes import _MaskEnum


class MyEnum(_MaskEnum):
    member1 = 0
    member2 = 1


def test_invalid_input():
    with pytest.raises(ValueError):
        MyEnum(12345)


def test_parsing():
    assert MyEnum.parse_bitfield(0b0) == set()
    assert MyEnum.parse_bitfield(0b1) == {MyEnum.member1}
    assert MyEnum.parse_bitfield(0b10) == {MyEnum.member2}
    assert MyEnum.parse_bitfield(0b11) == {MyEnum.member1, MyEnum.member2}


def test_identity():
    bitfields = [0b00, 0b01, 0b10, 0b11]

    for bitfield in bitfields:
        as_set = MyEnum.parse_bitfield(bitfield)
        back_to_bitfield = MyEnum.to_bitfield(as_set)
        assert back_to_bitfield == bitfield


def test_option_set_size():
    # Test if DataSetFieldFlags is 2 bytes instead of 4 bytes of all other flagfields
    val = ua.DataSetFieldFlags.PromotedField
    binary = ua_binary.to_binary(ua.DataSetFieldFlags, val)
    assert len(binary) == 2
    val_2 = ua_binary.from_binary(ua.DataSetFieldFlags, ua.utils.Buffer(binary))
    assert val == val_2


def test_ua9_write_mask_bits_22_to_25() -> None:
    """Part 3, 8.60: bits 22 to 25 of the AttributeWriteMask."""
    assert ua.WriteMask.DataTypeDefinition.value == 22
    assert ua.WriteMask.RolePermissions.value == 23
    assert ua.WriteMask.AccessRestrictions.value == 24
    assert ua.WriteMask.AccessLevelEx.value == 25
    assert ua.WriteMask.parse_bitfield(1 << 25) == {ua.WriteMask.AccessLevelEx}


def test_to_bitfield_duplicates() -> None:
    """Part 3, 8.60: a repeated member sets the same bit."""
    members = [ua.WriteMask.BrowseName, ua.WriteMask.BrowseName, ua.WriteMask.DataType]
    assert ua.WriteMask.to_bitfield(members) == (1 << 2) | (1 << 4)
    assert ua.AccessLevel.to_bitfield([ua.AccessLevel.CurrentRead, ua.AccessLevel.CurrentRead]) == 1


def test_ua8_parse_bitfield_message() -> None:
    with pytest.raises(ValueError, match="of type"):
        ua.AccessLevel.parse_bitfield("x")  # type: ignore[arg-type]

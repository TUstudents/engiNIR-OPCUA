import typing
from dataclasses import dataclass
from typing import Optional, Union

import pytest

import enginir_opcua.ua.uaerrors as uaerrors
from enginir_opcua import ua
from enginir_opcua.common.ua_utils import copy_dataclass_attr, value_to_datavalue
from enginir_opcua.common.utils import Buffer, NotEnoughData, fields_with_resolved_types
from enginir_opcua.ua.uaerrors import UaStatusCodeError
from enginir_opcua.ua.uatypes import (
    type_is_list,
    type_is_optional,
    type_is_union,
    type_string_from_type,
    types_from_union,
    types_or_list_from_union,
)


def test_com1_negative_read_raises() -> None:
    """Part 6, 5.1.2: a decoder never reads before its current position."""
    buf = Buffer(b"0123456789")
    buf.read(4)
    with pytest.raises(NotEnoughData):
        buf.read(-2)
    assert buf.cur_pos == 4
    assert len(buf) == 6


def test_com1_negative_skip_raises() -> None:
    """Part 6, 5.1.2: a decoder never reads before its current position."""
    buf = Buffer(b"0123456789")
    buf.skip(4)
    with pytest.raises(NotEnoughData):
        buf.skip(-2)
    assert buf.cur_pos == 4
    assert len(buf) == 6


def test_com1_read_past_end_leaves_cursor() -> None:
    buf = Buffer(b"0123")
    with pytest.raises(NotEnoughData):
        buf.read(5)
    assert buf.read(4) == b"0123"


def test_com2_copy_window_bytes_len_rewind() -> None:
    """Part 6, 5.1.2: a copy is limited to its window."""
    window = Buffer(b"0123456789").copy(3)
    assert bytes(window) == b"012"
    assert len(window) == 3
    window.read(2)
    assert bytes(window) == b"2"
    window.rewind()
    assert len(window) == 3
    assert bytes(window) == b"012"


def test_com2_rewind_defaults_to_window_start() -> None:
    buf = Buffer(b"0123456789")
    buf.read(4)
    window = buf.copy(3)
    window.read(3)
    window.rewind()
    assert window.cur_pos == 4
    assert bytes(window) == b"456"


def test_com2_rewind_outside_window_raises() -> None:
    buf = Buffer(b"0123456789")
    buf.read(4)
    window = buf.copy(3)
    with pytest.raises(ua.UaError):
        window.rewind(2)
    with pytest.raises(ua.UaError):
        window.rewind(8)
    window.rewind(7)
    assert len(window) == 0


def test_com2_rewind_absolute_position_in_window() -> None:
    buf = Buffer(b"0123456789")
    buf.read(4)
    window = buf.copy(5)
    window.read(3)
    window.rewind(5)
    assert bytes(window) == b"5678"


def test_com2_copy_larger_than_remaining_raises() -> None:
    buf = Buffer(b"0123")
    buf.read(1)
    with pytest.raises(NotEnoughData):
        buf.copy(4)
    assert len(buf.copy()) == 3
    assert len(buf.copy(3)) == 3


def test_com2_copy_negative_raises() -> None:
    with pytest.raises(ua.UaError):
        Buffer(b"0123").copy(-2)


def test_com2_copy_does_not_move_original() -> None:
    buf = Buffer(b"0123456789")
    window = buf.copy(3)
    window.read(3)
    assert buf.cur_pos == 0
    assert len(buf) == 10


@pytest.mark.parametrize(
    ("start", "size"),
    [(-1, -1), (11, -1), (0, 11), (5, 6), (0, -2), (2, -5)],
)
def test_com2_constructor_validates_window(start: int, size: int) -> None:
    """Part 6, 5.1.2: the window must lie inside the data."""
    with pytest.raises(ua.UaError):
        Buffer(b"0123456789", start, size)


def test_com2_constructor_accepts_valid_windows() -> None:
    assert len(Buffer(b"0123456789", 10)) == 0
    assert len(Buffer(b"0123456789", 2, 8)) == 8
    assert len(Buffer(b"")) == 0


def test_com3_fields_with_resolved_types_returns_copies() -> None:
    original = [f.type for f in ua.ReadValueId.__dataclass_fields__.values()]
    assert all(isinstance(t, str) for t in original)
    resolved = fields_with_resolved_types(ua.ReadValueId, globalns={"ua": ua})
    assert all(not isinstance(f.type, str) for f in resolved)
    assert [f.type for f in ua.ReadValueId.__dataclass_fields__.values()] == original


def test_copy_dataclass_attr() -> None:
    @dataclass
    class A:
        x: int = 1
        y: int = 2

    @dataclass
    class B:
        y: int = 12
        z: int = 13

    b = B()
    a = A()

    assert a.y != b.y
    copy_dataclass_attr(a, b)
    assert a.y == b.y == 2
    assert a.x == 1
    assert b.z == 13

    b.y = 9
    copy_dataclass_attr(b, a)
    assert a.y == b.y == 9
    assert a.x == 1
    assert b.z == 13


def test_com12_write_value_sends_no_source_timestamp() -> None:
    """Part 4, 5.11.4.2: a server needs the TimestampWrite bit for a timestamp the client sends."""
    for value in (5, ua.Variant(5, ua.VariantType.Int32)):
        dv = value_to_datavalue(value)
        assert dv.SourceTimestamp is None
        assert dv.ServerTimestamp is None


status_code_bad_internal = 0x80020000
status_code_unknown = "Definitely Not A Status Code"


@pytest.fixture()
def errors():
    return {
        "direct": uaerrors.BadInternalError(),
        "indirect": UaStatusCodeError(status_code_bad_internal),
        "unknown": UaStatusCodeError(status_code_unknown),
    }


def test_subclass_selection(errors):
    assert type(errors["direct"]) is uaerrors.BadInternalError
    assert type(errors["indirect"]) is uaerrors.BadInternalError
    assert type(errors["unknown"]) is UaStatusCodeError


def test_code(errors):
    assert errors["direct"].code == status_code_bad_internal
    assert errors["indirect"].code == status_code_bad_internal
    assert errors["unknown"].code == status_code_unknown


def test_string_repr(errors):
    assert "BadInternal" in str(errors["direct"])
    assert "BadInternal" in str(errors["indirect"])


def test_ua2_only_integer_keys_registered() -> None:
    assert all(isinstance(key, int) for key in UaStatusCodeError._subclasses)


def test_ua4_status_code_errors_codes() -> None:
    error = uaerrors.UaStatusCodeErrors([0, status_code_bad_internal, 0x80010000])
    assert error.codes == [0, status_code_bad_internal, 0x80010000]
    assert error.code == status_code_bad_internal
    assert uaerrors.UaStatusCodeErrors([0, 0]).code is None
    assert "BadInternalError" in str(error)


def test_com_78_detail_keyword_is_accepted() -> None:
    error = UaStatusCodeError(0x80010000, detail="why")
    assert isinstance(error, uaerrors.BadUnexpectedError)
    assert error.detail == "why"
    assert "why" in str(error)
    assert uaerrors.BadInternalError(detail="x").detail == "x"


# ruff: noqa: UP006, UP007, UP045


def test_ua5_ua6_modern_annotations() -> None:
    """Part 6, 5.1.2: Optional, union and list annotations in every spelling."""
    assert types_or_list_from_union(list[int] | None) == (True, list[int])
    assert types_or_list_from_union(typing.List[int] | None) == (True, typing.List[int])
    assert types_or_list_from_union(Optional[list[int]]) == (True, list[int])
    assert types_or_list_from_union(int | None) == (False, int)
    assert types_or_list_from_union(None | int) == (False, int)
    assert types_or_list_from_union(Optional[int]) == (False, int)


def test_ua6_types_from_union_accepts_pipe_unions() -> None:
    """Part 6, 5.1.2: `A | B` is a union like `typing.Union[A, B]`."""
    assert types_from_union(int | str | None) == [int, str]
    assert types_from_union(Union[int, str]) == [int, str]
    assert types_from_union(None | int) == [int]


def test_ua5_types_from_union_with_list_member() -> None:
    assert types_from_union(list[int] | None) == [list[int]]


def test_union_without_member_raises() -> None:
    with pytest.raises(ValueError):
        types_from_union(Union[None, None])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        types_or_list_from_union(type(None) | None)


def test_type_predicates_cover_all_spellings() -> None:
    for annotation in (Optional[int], int | None, None | int):
        assert type_is_optional(annotation)
        assert type_is_union(annotation)
    assert not type_is_optional(int | str)
    assert type_is_list(list[int])
    assert type_is_list(list[int])
    assert not type_is_list(list[int] | None)


def test_type_string_from_type_nested_annotations() -> None:
    assert type_string_from_type(list[ua.Int32] | None) == "Int32"
    assert type_string_from_type(Optional[list[ua.Int32]]) == "Int32"
    assert type_string_from_type(ua.NodeId | None) == "NodeId"
    assert type_string_from_type(None | ua.NodeId) == "NodeId"
    assert type_string_from_type("list[ua.Int32] | None") == "Int32"
    assert type_string_from_type("Optional[list[ua.Int32]]") == "Int32"
    assert type_string_from_type("ua.NodeId | None") == "NodeId"
    assert type_string_from_type("'ua.String | None'") == "String"
    assert type_string_from_type("List[ua.Byte]") == "Byte"

# ruff: noqa: UP006, UP007, UP045
import typing
from typing import Optional, Union

import pytest

from enginir_opcua import ua
from enginir_opcua.ua.uatypes import (
    type_is_list,
    type_is_optional,
    type_is_union,
    type_string_from_type,
    types_from_union,
    types_or_list_from_union,
)


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

"""The NumericRange of OPC 10000-4 v1.05, 7.27: parsing, selecting for reads and composing for writes."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .uaerrors import BadIndexRangeDataMismatch, BadIndexRangeInvalid, BadIndexRangeNoData
from .uatypes import Variant, VariantType, get_shape

MAX_DIMENSIONS = 32
MAX_INDEX = 0xFFFFFFFF
_DIMENSION = re.compile(r"([0-9]+)(?::([0-9]+))?", re.ASCII)
_STRING_TYPES = (VariantType.String, VariantType.ByteString)


@dataclass(frozen=True, slots=True)
class Dimension:
    low: int
    high: int

    @property
    def size(self) -> int:
        return self.high - self.low + 1

    def __str__(self) -> str:
        return str(self.low) if self.low == self.high else f"{self.low}:{self.high}"


def _parse_dimension(text: str) -> Dimension:
    match = _DIMENSION.fullmatch(text)
    if match is None:
        raise BadIndexRangeInvalid()
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) is not None else low
    if low > MAX_INDEX or high > MAX_INDEX or (match.group(2) is not None and low >= high):
        raise BadIndexRangeInvalid()
    return Dimension(low, high)


def _is_string_type(variant: Variant) -> bool:
    return variant.VariantType in _STRING_TYPES


def _array_depth(variant: Variant) -> int:
    return len(variant.Dimensions) if variant.Dimensions else 1


def _reshape(flat: list[Any], dimensions: Sequence[int]) -> list[Any]:
    if len(dimensions) <= 1:
        return list(flat)
    step = 1
    for size in dimensions[1:]:
        step *= size
    return [_reshape(flat[i * step : (i + 1) * step], dimensions[1:]) for i in range(dimensions[0])]


def _nested(variant: Variant) -> list[Any]:
    value = list(variant.Value) if variant.Value is not None else []
    depth = _array_depth(variant)
    if depth > 1 and value and not isinstance(value[0], list | tuple):
        return _reshape(value, variant.Dimensions or [])
    return value


def _character_length(item: Any) -> int:
    return 0 if item is None else len(item)


def _result(source: Variant, value: Any, array: bool) -> Variant:
    dimensions = get_shape(value) if array else None
    return Variant(
        value, source.VariantType, Dimensions=dimensions if dimensions and len(dimensions) > 1 else None, is_array=array
    )


@dataclass(frozen=True, slots=True)
class IndexRange:
    dimensions: tuple[Dimension, ...]

    @classmethod
    def parse(cls, text: str | None) -> IndexRange | None:
        if text is None or text == "":
            return None
        parts = text.split(",")
        if len(parts) > MAX_DIMENSIONS:
            raise BadIndexRangeInvalid()
        return cls(tuple(_parse_dimension(part) for part in parts))

    def __str__(self) -> str:
        return ",".join(str(dimension) for dimension in self.dimensions)

    def __len__(self) -> int:
        return len(self.dimensions)

    def fits(self, array_dimensions: Sequence[int]) -> bool:
        if len(self.dimensions) > len(array_dimensions) + 1:
            return False
        return all(known == 0 or dimension.low < known for dimension, known in zip(self.dimensions, array_dimensions))

    def _split(self, value: Variant) -> tuple[Sequence[Dimension], Dimension | None]:
        if value.Value is None or value.VariantType == VariantType.Null:
            raise BadIndexRangeNoData()
        if not value.is_array:
            if not _is_string_type(value) or len(self.dimensions) != 1:
                raise BadIndexRangeNoData()
            return (), self.dimensions[0]
        depth = _array_depth(value)
        if len(self.dimensions) == depth:
            return self.dimensions, None
        if len(self.dimensions) == depth + 1 and _is_string_type(value):
            return self.dimensions[:depth], self.dimensions[depth]
        raise BadIndexRangeNoData()

    def select(self, value: Variant) -> Variant:
        array_ranges, leaf = self._split(value)
        if not value.is_array:
            assert leaf is not None
            cut = _cut(value.Value, leaf)
            if cut is None:
                raise BadIndexRangeNoData()
            return Variant(cut, value.VariantType, is_array=False)
        found: list[bool] = []

        def take(item: Any) -> Any:
            if leaf is None:
                return item
            part = _cut(item, leaf)
            found.append(part is not None)
            return part

        selected = _select(_nested(value), array_ranges, take)
        if leaf is not None and not any(found):
            raise BadIndexRangeNoData()
        return _result(value, selected, True)

    def compose(self, current: Variant, new: Variant) -> Variant:
        array_ranges, leaf = self._split(current)
        if new.VariantType != current.VariantType:
            if not (
                current.VariantType == VariantType.Byte and new.VariantType == VariantType.ByteString and new.Value
            ):
                raise BadIndexRangeDataMismatch()
            new = Variant(list(new.Value), VariantType.Byte, is_array=True)
        if not current.is_array:
            assert leaf is not None
            if _character_length(current.Value) <= leaf.high:
                raise BadIndexRangeNoData()
            if new.is_array or _character_length(new.Value) != leaf.size:
                raise BadIndexRangeDataMismatch()
            replaced = current.Value[: leaf.low] + new.Value + current.Value[leaf.high + 1 :]
            return Variant(replaced, current.VariantType, is_array=False)
        if not new.is_array:
            raise BadIndexRangeDataMismatch()
        sizes = [dimension.size for dimension in array_ranges]
        if get_shape(_select(_nested(current), array_ranges, _identity)) != sizes:
            raise BadIndexRangeNoData()
        incoming = _nested(new)
        if get_shape(incoming) != sizes:
            raise BadIndexRangeDataMismatch()
        replaced_value = _replace(_nested(current), array_ranges, incoming, leaf)
        return _result(current, replaced_value, True)


def _identity(item: Any) -> Any:
    return item


def _cut(item: Any, dimension: Dimension) -> Any:
    length = _character_length(item)
    if dimension.low >= length:
        return None
    return item[dimension.low : dimension.high + 1]


def _select(data: list[Any], ranges: Sequence[Dimension], take: Callable[[Any], Any]) -> list[Any]:
    dimension, rest = ranges[0], ranges[1:]
    if dimension.low >= len(data):
        raise BadIndexRangeNoData()
    part = data[dimension.low : dimension.high + 1]
    if rest:
        return [_select(item, rest, take) for item in part]
    return [take(item) for item in part]


def _replace(data: list[Any], ranges: Sequence[Dimension], incoming: list[Any], leaf: Dimension | None) -> list[Any]:
    dimension, rest = ranges[0], ranges[1:]
    if dimension.high >= len(data):
        raise BadIndexRangeNoData()
    result = list(data)
    for offset, new_item in enumerate(incoming):
        index = dimension.low + offset
        if rest:
            result[index] = _replace(data[index], rest, new_item, leaf)
        elif leaf is None:
            result[index] = new_item
        else:
            old = data[index]
            if _character_length(old) <= leaf.high:
                raise BadIndexRangeNoData()
            if _character_length(new_item) != leaf.size:
                raise BadIndexRangeDataMismatch()
            result[index] = old[: leaf.low] + new_item + old[leaf.high + 1 :]
    return result


def select_index_range(value: Any, text: str) -> tuple[int, Any]:
    try:
        parsed = IndexRange.parse(text)
        if parsed is None:
            return 0, value
        if value is None:
            raise BadIndexRangeNoData()
        if isinstance(value, Variant):
            return 0, parsed.select(value)
        return 0, parsed.select(Variant(value)).Value
    except (BadIndexRangeInvalid, BadIndexRangeNoData) as error:
        return int(error.code), None
    except Exception:
        return int(BadIndexRangeNoData.code), None

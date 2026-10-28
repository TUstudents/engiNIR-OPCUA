"""Checks of a Variant against a DataType, ValueRank and ArrayDimensions (OPC 10000-4 v1.05, 5.11.4; OPC 10000-3 v1.05, 5.6.2)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from enginir_opcua import ua

BASE_DATA_TYPE = ua.NodeId(ua.ObjectIds.BaseDataType)
ENUMERATION = ua.NodeId(ua.ObjectIds.Enumeration)
STRUCTURE = ua.NodeId(ua.ObjectIds.Structure)
BYTE = ua.NodeId(ua.ObjectIds.Byte)
BYTE_STRING = ua.NodeId(ua.ObjectIds.ByteString)
HAS_SUBTYPE = ua.NodeId(ua.ObjectIds.HasSubtype)
MAX_SUPERTYPE_DEPTH = 64


class HasReferences(Protocol):
    references: list[ua.ReferenceDescription]


class NodeLookup(Protocol):
    def get(self, nodeid: ua.NodeId) -> HasReferences | None: ...


class DataTypeChecker:
    def __init__(self, nodes: NodeLookup) -> None:
        self._nodes = nodes

    def parent_of(self, datatype: ua.NodeId) -> ua.NodeId | None:
        node = self._nodes.get(datatype)
        if node is None:
            return None
        for ref in node.references:
            if ref.ReferenceTypeId == HAS_SUBTYPE and not ref.IsForward:
                return ref.NodeId
        return None

    def is_subtype(self, datatype: ua.NodeId, ancestor: ua.NodeId) -> bool:
        current: ua.NodeId | None = datatype
        for _ in range(MAX_SUPERTYPE_DEPTH):
            if current is None:
                return False
            if current == ancestor:
                return True
            current = self.parent_of(current)
        return False

    def is_known(self, datatype: ua.NodeId) -> bool:
        return self._nodes.get(datatype) is not None

    def element_matches(self, vtype: ua.VariantType, items: Sequence[Any], datatype: ua.NodeId) -> bool:
        if datatype == BASE_DATA_TYPE or datatype.is_null() or not self.is_known(datatype):
            return True
        if vtype == ua.VariantType.ExtensionObject:
            return all(self._structure_matches(item, datatype) for item in items if item is not None)
        builtin = ua.NodeId(int(vtype))
        if self.is_subtype(builtin, datatype) or self.is_subtype(datatype, builtin):
            return True
        if vtype == ua.VariantType.Int32 and self.is_subtype(datatype, ENUMERATION):
            return True
        if vtype == ua.VariantType.ByteString and self.is_subtype(datatype, BYTE):
            return True
        return vtype == ua.VariantType.Byte and self.is_subtype(datatype, BYTE_STRING)

    def _structure_matches(self, item: Any, datatype: ua.NodeId) -> bool:
        if not self.is_subtype(datatype, STRUCTURE):
            return False
        item_type = getattr(item, "data_type", None)
        if not isinstance(item_type, ua.NodeId) or not self.is_known(item_type):
            return True
        return self.is_subtype(item_type, datatype)

    def allows_null(self, datatype: ua.NodeId, allow_nulls: bool) -> bool:
        return allow_nulls or datatype == BASE_DATA_TYPE or datatype.is_null() or not self.is_known(datatype)


def dimensions_of(variant: ua.Variant) -> list[int]:
    if not variant.is_array:
        return []
    if variant.Dimensions:
        return [int(d) for d in variant.Dimensions]
    return [len(variant.Value) if variant.Value is not None else 0]


def rank_allows(value_rank: int, dimension_count: int) -> bool:
    if value_rank == ua.ValueRank.Any:
        return True
    if value_rank == ua.ValueRank.ScalarOrOneDimension:
        return dimension_count <= 1
    if value_rank == ua.ValueRank.Scalar:
        return dimension_count == 0
    if value_rank == ua.ValueRank.OneOrMoreDimensions:
        return dimension_count >= 1
    return dimension_count == value_rank


def array_dimensions_allow(array_dimensions: Sequence[int], dimensions: Sequence[int]) -> bool:
    return all(limit == 0 or size <= limit for limit, size in zip(array_dimensions, dimensions))


def effective_shape(variant: ua.Variant, datatype: ua.NodeId, checker: DataTypeChecker) -> list[int]:
    dimensions = dimensions_of(variant)
    if variant.VariantType == ua.VariantType.ByteString and not variant.is_array and checker.is_subtype(datatype, BYTE):
        return [len(variant.Value) if variant.Value is not None else 0]
    if (
        variant.VariantType == ua.VariantType.Byte
        and len(dimensions) == 1
        and datatype == BYTE_STRING
        and checker.is_known(datatype)
    ):
        return []
    return dimensions


def check_variant(
    checker: DataTypeChecker,
    variant: ua.Variant,
    datatype: ua.NodeId,
    value_rank: int,
    array_dimensions: Sequence[int],
    allow_nulls: bool,
) -> bool:
    if variant.VariantType == ua.VariantType.Null:
        return checker.allows_null(datatype, allow_nulls)
    items: Sequence[Any]
    if variant.Value is None:
        items = []
    elif variant.is_array:
        items = _flat(variant.Value)
    else:
        items = [variant.Value]
    if not checker.element_matches(variant.VariantType, items, datatype):
        return False
    shape = effective_shape(variant, datatype, checker)
    return rank_allows(value_rank, len(shape)) and array_dimensions_allow(array_dimensions, shape)


def _flat(value: Any) -> list[Any]:
    flat: list[Any] = []
    for item in value:
        if isinstance(item, list | tuple):
            flat.extend(_flat(item))
        else:
            flat.append(item)
    return flat

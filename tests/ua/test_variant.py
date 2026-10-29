from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import variant_from_binary, variant_to_binary
from enginir_opcua.ua.uatypes import datatype_to_varianttype


def test_variant_type_ids_table1() -> None:
    """Part 6, 5.1.2, Table 1: ids 0 to 25."""
    assert ua.VariantType.Null == 0
    assert ua.VariantType.DiagnosticInfo == 25
    assert len(ua.VariantType) == 26


def test_ua27_custom_variant_type_range() -> None:
    """Part 6, 5.2.2.16: ids 26 to 63 fit the six bits of the encoding mask."""
    for bad in (-1, 0, 25, 64, 89):
        with pytest.raises(ua.UaError, match="26"):
            ua.VariantTypeCustom(bad)
    assert ua.VariantTypeCustom(26).value == 26
    assert ua.VariantTypeCustom(63).value == 63


def test_ua27_datatype_to_varianttype_range() -> None:
    """Part 6, 5.2.2.16."""
    assert datatype_to_varianttype(25) is ua.VariantType.DiagnosticInfo
    assert datatype_to_varianttype(26) == ua.VariantTypeCustom(26)
    for bad in (-1, 64):
        with pytest.raises(ua.UaError):
            datatype_to_varianttype(bad)


def test_ua25_variant_copy_keeps_is_array_and_dimensions() -> None:
    """Part 6, 5.1.9, 5.2.2.16: a copy of an array Variant is an array Variant."""
    inner = ua.Variant([1, 2, 3])
    copy = ua.Variant(inner)
    assert copy.is_array
    assert copy.Value == [1, 2, 3]
    matrix = ua.Variant([[1, 2], [3, 4]])
    copy = ua.Variant(matrix)
    assert copy.is_array
    assert copy.Dimensions == [2, 2]
    assert copy == matrix
    assert not ua.Variant(ua.Variant(5)).is_array


class Plain:
    pass


def test_ua26_unknown_object_raises() -> None:
    """Part 6, 5.1.9: only built-in types and structures can be guessed."""
    with pytest.raises(ua.UaError, match="type"):
        ua.Variant(Plain())
    with pytest.raises(ua.UaError):
        ua.Variant({"a": 1})
    assert ua.Variant(Plain(), ua.VariantType.ExtensionObject).VariantType is ua.VariantType.ExtensionObject


def test_variant_guess_type_order() -> None:
    """Part 6, 5.1.2: bool before int, enum members are Int32."""
    assert ua.Variant(True).VariantType is ua.VariantType.Boolean
    assert ua.Variant(1).VariantType is ua.VariantType.Int64
    assert ua.Variant(1.5).VariantType is ua.VariantType.Double
    assert ua.Variant(ua.NodeClass.Object).VariantType is ua.VariantType.Int32
    assert ua.Variant(datetime.now(UTC)).VariantType is ua.VariantType.DateTime
    assert ua.Variant(ua.ApplicationDescription()).VariantType is ua.VariantType.ExtensionObject
    assert ua.Variant(None).VariantType is ua.VariantType.Null


NULLABLE = [
    ua.VariantType.Null,
    ua.VariantType.String,
    ua.VariantType.DateTime,
    ua.VariantType.Guid,
    ua.VariantType.ByteString,
    ua.VariantType.XmlElement,
    ua.VariantType.NodeId,
    ua.VariantType.ExpandedNodeId,
    ua.VariantType.QualifiedName,
    ua.VariantType.LocalizedText,
    ua.VariantType.ExtensionObject,
    ua.VariantType.DataValue,
    ua.VariantType.Variant,
]


@pytest.mark.parametrize("vtype", NULLABLE)
def test_null_scalar_variant_types(vtype: ua.VariantType) -> None:
    """Part 6, 5.1.2, Table 1: a scalar of a nullable type may be null."""
    ua.Variant(None, vtype)


@pytest.mark.parametrize(
    "vtype",
    [t for t in ua.VariantType if t not in NULLABLE and t is not ua.VariantType.DiagnosticInfo],
)
def test_null_scalar_rejected_for_non_nullable(vtype: ua.VariantType) -> None:
    """Part 6, 5.1.2, Table 1: Nullable is No."""
    with pytest.raises(ua.UaError):
        ua.Variant(None, vtype)


def test_null_scalar_becomes_default_where_default_is_not_none() -> None:
    """Part 6, 5.1.2, Table 1: a default is equivalent to null."""
    assert ua.Variant(None, ua.VariantType.NodeId).Value == ua.NodeId()
    assert ua.Variant(None, ua.VariantType.ExpandedNodeId).Value == ua.ExpandedNodeId()
    assert ua.Variant(None, ua.VariantType.QualifiedName).Value == ua.QualifiedName()
    assert ua.Variant(None, ua.VariantType.LocalizedText).Value == ua.LocalizedText()
    assert ua.Variant(None, ua.VariantType.String).Value is None


@pytest.mark.parametrize("vtype", [t for t in NULLABLE if t is not ua.VariantType.XmlElement])
def test_null_scalar_round_trips_on_wire(vtype: ua.VariantType) -> None:
    """Part 6, 5.2.2.16."""
    var = ua.Variant(None, vtype)
    again = variant_from_binary(ua.utils.Buffer(variant_to_binary(var)))
    assert again.VariantType in (vtype, ua.VariantType.Null)


def test_variant_rejects_diagnostic_info() -> None:
    """Part 6, 5.1.9: Variants cannot contain DiagnosticInfo."""
    with pytest.raises(ua.UaError):
        ua.Variant(ua.DiagnosticInfo())
    with pytest.raises(ua.UaError):
        ua.Variant(None, ua.VariantType.DiagnosticInfo)
    with pytest.raises(ua.UaError):
        ua.Variant([ua.DiagnosticInfo()], ua.VariantType.DiagnosticInfo)


def test_ua57_equality_includes_dimensions_and_is_array() -> None:
    """Part 6, 5.2.2.16: Dimensions and the array flag are part of the value."""
    assert ua.Variant([1, 2, 3, 4], ua.VariantType.Int32) != ua.Variant([[1, 2], [3, 4]], ua.VariantType.Int32)
    flat = ua.Variant([1, 2, 3, 4], ua.VariantType.Int32, [ua.Int32(4)])
    assert flat != ua.Variant([1, 2, 3, 4], ua.VariantType.Int32, [ua.Int32(2), ua.Int32(2)])
    assert ua.Variant([1], ua.VariantType.Int32) != ua.Variant(1, ua.VariantType.Int32)
    assert ua.Variant([1, 2], ua.VariantType.Int32) == ua.Variant([1, 2], ua.VariantType.Int32)


def test_datavalue_wraps_variant_defaults() -> None:
    """Part 6, 5.2.2.17."""
    value: Any = ua.DataValue(5)
    assert isinstance(value.Value, ua.Variant)
    assert value.StatusCode.is_good()


def test_variant_guess_nodeid_subclasses() -> None:
    """Part 6, 5.1.2, Table 1: every NodeId class is a NodeId or ExpandedNodeId."""
    assert ua.Variant(ua.NumericNodeId(5)).VariantType is ua.VariantType.NodeId
    assert ua.Variant(ua.NodeId(5)).VariantType is ua.VariantType.NodeId
    assert ua.Variant(ua.ExpandedNodeId(5)).VariantType is ua.VariantType.ExpandedNodeId


def test_null_xml_element_scalar_round_trips() -> None:
    """Part 6, 5.1.2: XmlElement is nullable, so a scalar None has to encode."""
    variant = ua.Variant(None, ua.VariantType.XmlElement)
    assert variant_from_binary(Buffer(variant_to_binary(variant))) == ua.Variant(
        ua.XmlElement(), ua.VariantType.XmlElement
    )

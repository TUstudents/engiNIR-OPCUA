from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua import flatten, get_shape
from enginir_opcua.ua.ua_binary import (
    _reshape,
    variant_from_binary,
    variant_to_binary,
)
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


def test_variant_array_none():
    v = ua.Variant(None, VariantType=ua.VariantType.Int32, is_array=True)
    data = variant_to_binary(v)
    v2 = variant_from_binary(ua.utils.Buffer(data))
    assert v == v2
    assert v2.is_array
    assert v2.Dimensions is None

    v = ua.Variant(None, VariantType=ua.VariantType.Null, is_array=True)
    data = variant_to_binary(v)
    v2 = variant_from_binary(ua.utils.Buffer(data))
    assert v == v2
    assert v2.is_array
    assert v2.Dimensions is None

    v = ua.Variant(None, VariantType=ua.VariantType.Null, Dimensions=[0, 0])
    data = variant_to_binary(v)
    v2 = variant_from_binary(ua.utils.Buffer(data))
    assert v2 == ua.Variant(None, VariantType=ua.VariantType.Null, is_array=True)
    assert v2.is_array
    assert v2.Dimensions is None


def test_variant_empty_list():
    v = ua.Variant([], VariantType=ua.VariantType.Int32, is_array=True)
    data = variant_to_binary(v)
    v2 = variant_from_binary(ua.utils.Buffer(data))
    assert v == v2
    assert v2.is_array
    assert v2.Dimensions is None

    v = ua.Variant([], VariantType=ua.VariantType.Int32, is_array=True, Dimensions=[0])
    data = variant_to_binary(v)
    v2 = variant_from_binary(ua.utils.Buffer(data))
    assert v2 == ua.Variant([], VariantType=ua.VariantType.Int32, is_array=True)
    assert v2.is_array
    assert v2.Dimensions is None


def test_variant_dimensions():
    arry = [
        [[1.0, 1.0, 1.0, 1.0], [2.0, 2.0, 2.0, 2.0], [3.0, 3.0, 3.0, 3.0]],
        [[5.0, 5.0, 5.0, 5.0], [7.0, 8.0, 9.0, 01.0], [1.0, 1.0, 1.0, 1.0]],
    ]
    v = ua.Variant(arry)
    assert [2, 3, 4] == v.Dimensions
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v == v2
    assert v.Dimensions == v2.Dimensions

    # very special case
    arry = [[[], [], []], [[], [], []]]
    v = ua.Variant(arry, ua.VariantType.UInt32)
    assert [2, 3, 0] == v.Dimensions
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v2.Dimensions is None
    assert v2.Value == []


def test_flatten():
    arry = [
        [[1.0, 1.0, 1.0, 1.0], [1.0, 1.0, 1.0, 1.0], [1.0, 1.0, 1.0, 1.0]],
        [[1.0, 1.0, 1.0, 1.0], [1.0, 1.0, 1.0, 1.0], [1.0, 1.0, 1.0, 1.0]],
    ]
    l2 = flatten(arry)
    dims = get_shape(arry)
    assert [2, 3, 4] == dims
    assert arry != l2

    l3 = _reshape(l2, (2, 3, 4))
    assert arry == l3

    arry = [[[], [], []], [[], [], []]]
    l2 = flatten(arry)
    dims = get_shape(arry)
    assert dims == [2, 3, 0]

    arry = [1, 2, 3, 4]
    l2 = flatten(arry)
    dims = get_shape(arry)
    assert dims == [4]
    assert arry == l2


def test_reshape_rejects_oversized_dimensions():
    with pytest.raises(ua.UaError, match="exceeds MAX_RESHAPE_ELEMENTS"):
        _reshape([1, 2, 3], [50_000_000])


def test_custom_variant():
    with pytest.raises(ua.UaError):
        v = ua.Variant(b"ljsdfljds", ua.VariantTypeCustom(89))
    v = ua.Variant(b"ljsdfljds", ua.VariantTypeCustom(61))
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v.VariantType == v2.VariantType
    assert v == v2


def test_custom_variant_array():
    v = ua.Variant([b"ljsdfljds", b"lkjsdljksdf"], ua.VariantTypeCustom(40))
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v.VariantType == v2.VariantType
    assert v == v2


def test_variant_to_binary_type_mismatch_error():
    """Float stored as Int32 must raise a clear UaError (issue #1614)."""
    v = ua.Variant(1.5, ua.VariantType.Int32)
    with pytest.raises(ua.UaError, match=r"Cannot pack VariantType\.Int32.*1\.5.*float"):
        variant_to_binary(v)

    v_arr = ua.Variant([1, 2.5], ua.VariantType.Int32)
    with pytest.raises(ua.UaError, match=r"Cannot pack VariantType\.Int32"):
        variant_to_binary(v_arr)


def test_variant():
    dv = ua.Variant(True, ua.VariantType.Boolean)
    assert dv.Value is True
    assert isinstance(dv.Value, bool)
    now = datetime.now(UTC)
    v = ua.Variant(now)
    assert v.Value == now
    assert v.VariantType == ua.VariantType.DateTime
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v.Value == v2.Value
    assert v.VariantType == v2.VariantType
    # commonity method:
    assert v == ua.Variant(v)


def test_variant_array():
    v = ua.Variant([1, 2, 3, 4, 5])
    assert v.Value[1] == 2
    # assert v.VarianType, ua.VariantType.Int64) # we do not care, we should aonly test for sutff that matter
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v.Value == v2.Value
    assert v.VariantType == v2.VariantType
    assert v2.Dimensions is None

    now = datetime.now(UTC)
    v = ua.Variant([now])
    assert v.Value[0] == now
    assert v.VariantType == ua.VariantType.DateTime
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v.Value == v2.Value
    assert v.VariantType == v2.VariantType
    assert v2.Dimensions is None


def test_variant_array_dim():
    v = ua.Variant([1, 2, 3, 4, 5, 6], Dimensions=[2, 3])
    assert v.Value[1] == 2
    assert v.Dimensions == [2, 3]

    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))

    assert _reshape(v.Value, (2, 3)) == v2.Value
    assert v.VariantType == v2.VariantType
    assert v.Dimensions == v2.Dimensions
    assert v2.Dimensions == [2, 3]


def test_variant_intenum():
    ase = ua.AxisScaleEnumeration(ua.AxisScaleEnumeration.Linear)  # Just pick an existing IntEnum class
    vAse = ua.Variant(ase)
    assert vAse.VariantType == ua.VariantType.Int32


def test_builtin_type_variant():
    v = ua.Variant(ua.Int16(4))
    assert v.VariantType == ua.VariantType.Int16
    v = ua.Variant(ua.UInt64(4))
    assert v.VariantType == ua.VariantType.UInt64
    b = variant_to_binary(v)
    v2 = variant_from_binary(ua.utils.Buffer(b))
    assert v == v2
    v = ua.Variant(ua.Byte(4))
    assert v.VariantType == ua.VariantType.Byte
    v = ua.Variant(ua.ByteString(b"hj"))
    assert v.VariantType == ua.VariantType.ByteString
    v = ua.Variant(4, ua.Byte)
    assert v.VariantType == ua.VariantType.Byte
    v = ua.Variant(None, ua.String)
    assert v.VariantType == ua.VariantType.String

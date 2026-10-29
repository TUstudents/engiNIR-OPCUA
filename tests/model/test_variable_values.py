from datetime import UTC, datetime, timedelta

import pytest

from enginir_opcua import ua
from tests.access_rig import declare_writable

pytestmark = pytest.mark.asyncio


async def test_add_node_using_builtin(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderBuiltin")
    var = await fold.add_variable(2, "VarBuiltin", ua.UInt16(9))
    await declare_writable(opc, var)
    dv = await var.read_data_value()
    assert dv.Value.VariantType == ua.VariantType.UInt16
    data_type = await var.read_data_type()
    assert data_type.Identifier == ua.VariantType.UInt16.value == ua.ObjectIds.UInt16
    assert data_type.NamespaceIndex == 0
    await var.write_value(ua.UInt16(6))
    dv = await var.read_data_value()
    assert dv.Value.VariantType == ua.VariantType.UInt16
    assert dv.Value.Value == 6
    assert (await var.read_value()) == 6


async def test_datetime_read_value(opc):
    time_node = opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
    dt = await time_node.read_value()
    utcnow = datetime.now(UTC)
    delta = utcnow - dt
    assert delta < timedelta(seconds=2)


async def test_datetime_write_value(opc):
    now = datetime.now(UTC)
    objects = opc.opc.nodes.objects
    v1 = await objects.add_variable(4, "test_datetime", now)
    tid = await v1.read_value()
    assert now == tid
    await opc.opc.delete_nodes([v1])


async def test_variant_array_dim(opc):
    objects = opc.opc.nodes.objects
    arry = [
        [[1.0, 1.0, 1.0, 1.0], [2.0, 2.0, 2.0, 2.0], [3.0, 3.0, 3.0, 3.0]],
        [[5.0, 5.0, 5.0, 5.0], [7.0, 8.0, 9.0, 1.0], [1.0, 1.0, 1.0, 1.0]],
    ]
    v = await objects.add_variable(3, "variableWithDims", arry)
    await declare_writable(opc, v, attributes=(ua.AttributeIds.ArrayDimensions, ua.AttributeIds.ValueRank))

    await v.write_array_dimensions([0, 0, 0])
    dim = await v.read_array_dimensions()
    assert [0, 0, 0] == dim

    await v.write_value_rank(0)
    rank = await v.read_value_rank()
    assert 0 == rank

    v2 = await v.read_value()
    assert arry == v2
    dv = await v.read_data_value()
    assert [2, 3, 4] == dv.Value.Dimensions

    arry = [[[], [], []], [[], [], []]]
    variant = ua.Variant(arry, ua.VariantType.UInt32)
    v1 = await objects.add_variable(3, "variableWithDimsEmpty", variant)
    v2 = await v1.read_value()
    assert v2 in (arry, [])
    dv = await v1.read_data_value()
    assert dv.Value.Dimensions in ([2, 3, 0], None)
    await opc.opc.delete_nodes([v, v1])


async def test_add_numeric_variable(opc):
    objects = opc.opc.nodes.objects
    v = await objects.add_variable("ns=3;i=888;", "3:numericnodefromstring", 99)
    nid = ua.NodeId(888, 3)
    qn = ua.QualifiedName("numericnodefromstring", 3)
    assert nid == v.nodeid
    assert qn == await v.read_browse_name()
    await opc.opc.delete_nodes([v])


async def test_add_string_variable(opc):
    objects = opc.opc.nodes.objects
    v = await objects.add_variable("ns=3;s=stringid", "3:stringnodefromstring", [68])
    nid = ua.NodeId("stringid", 3)
    qn = ua.QualifiedName("stringnodefromstring", 3)
    assert nid == v.nodeid
    assert qn == await v.read_browse_name()
    await opc.opc.delete_nodes([v])


async def test_utf8(opc):
    objects = opc.opc.nodes.objects
    utf_string = "æøå@%&"
    bn = ua.QualifiedName(utf_string, 3)
    nid = ua.NodeId("æølå", 3)
    val = "æøå"
    v = await objects.add_variable(nid, bn, val)
    assert nid == v.nodeid
    val2 = await v.read_value()
    assert val == val2
    bn2 = await v.read_browse_name()
    assert bn == bn2
    await opc.opc.delete_nodes([v])


async def test_null_variable(opc):
    objects = opc.opc.nodes.objects
    var = await objects.add_variable(3, "nullstring", "a string")
    await declare_writable(opc, var)
    await var.write_value(ua.Variant(None, ua.VariantType.String))
    val = await var.read_value()
    assert val is None
    await var.write_value("")
    val = await var.read_value()
    assert val is not None
    assert "" == val
    await opc.opc.delete_nodes([var])


async def test_variable_data_type(opc):
    objects = opc.opc.nodes.objects
    var = await objects.add_variable(3, "stringfordatatype", "a string")
    val = await var.read_data_type_as_variant_type()
    assert ua.VariantType.String == val
    await opc.opc.delete_nodes([var])
    var = await objects.add_variable(3, "stringarrayfordatatype", ["a", "b"])
    val = await var.read_data_type_as_variant_type()
    assert ua.VariantType.String == val
    await opc.opc.delete_nodes([var])


async def test_add_string_array_variable(opc):
    objects = opc.opc.nodes.objects
    v = await objects.add_variable("ns=3;s=stringarrayid", "9:stringarray", ["l", "b"])
    nid = ua.NodeId("stringarrayid", 3)
    qn = ua.QualifiedName("stringarray", 9)
    assert nid == v.nodeid
    assert qn == await v.read_browse_name()
    val = await v.read_value()
    assert ["l", "b"] == val
    await opc.opc.delete_nodes([v])


async def test_add_read_node(opc):
    objects = opc.opc.nodes.objects
    o = await objects.add_object("ns=2;i=102;", "2:AddReadObject")
    nid = ua.NodeId(102, 2)
    assert nid == o.nodeid
    qn = ua.QualifiedName("AddReadObject", 2)
    assert qn == await o.read_browse_name()
    await opc.opc.delete_nodes([o])


async def test_simple_value(opc):
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "VariableTestValue", 4.32)
    val = await v.read_value()
    assert 4.32 == val
    await opc.opc.delete_nodes([v])


async def test_add_exception(opc):
    objects = opc.opc.nodes.objects
    v = await objects.add_object("ns=2;i=103;", "2:AddReadObject")
    with pytest.raises(ua.UaStatusCodeError):
        await objects.add_object("ns=2;i=103;", "2:AddReadObject")
    await opc.opc.delete_nodes([v])


async def test_negative_value(opc):
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "VariableNegativeValue", 4.0)
    await declare_writable(opc, v)
    await v.write_value(-4.54)
    assert -4.54 == await v.read_value()
    await opc.opc.delete_nodes([v])


async def test_bad_node(opc):
    bad = opc.opc.get_node(ua.NodeId(999, 999))
    with pytest.raises(ua.UaStatusCodeError):
        await bad.read_browse_name()
    with pytest.raises(ua.UaStatusCodeError):
        await bad.write_value(89)
    with pytest.raises(ua.UaStatusCodeError):
        await bad.add_object(0, "0:myobj")
    with pytest.raises(ua.UaStatusCodeError):
        await bad.get_child("0:myobj")
    await opc.opc.delete_nodes([bad])


async def test_value(opc):
    o = opc.opc.nodes.objects
    var = ua.Variant(ua.Double(1.98))
    v = await o.add_variable(3, "VariableValue", var)
    assert 1.98 == await v.read_value()
    dvar = ua.DataValue(var)
    dv = await v.read_data_value()
    assert ua.DataValue is type(dv)
    assert dvar.Value == dv.Value
    assert dvar.Value == var
    await opc.opc.delete_nodes([v])


async def test_write_value(opc):
    o = opc.opc.nodes.objects
    var = ua.Variant(1.98, ua.VariantType.Double)
    dvar = ua.DataValue(var)
    v = await o.add_variable(3, "VariableValue", var)
    await declare_writable(opc, v)
    await v.write_value(var.Value)
    v1 = await v.read_value()
    assert v1 == var.Value
    await v.write_value(var)
    v2 = await v.read_value()
    assert v2 == var.Value
    await v.write_value(dvar)
    v3 = await v.read_data_value()
    assert v3.Value == dvar.Value
    await opc.opc.delete_nodes([v])


async def test_write_value_statuscode_bad(opc):
    o = opc.opc.nodes.objects
    var = ua.Variant("Some value that should not be set!")
    dvar = ua.DataValue(None, StatusCode=ua.StatusCode(ua.StatusCodes.BadDeviceFailure))
    v = await o.add_variable(3, "VariableValueBad", var)
    await declare_writable(opc, v, status=True)
    await v.write_value(dvar)
    with pytest.raises(ua.UaStatusCodeError) as error_read:
        await v.read_data_value()
    assert error_read.type.code == dvar.StatusCode.value
    await opc.opc.delete_nodes([v])


async def test_array_value(opc):
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "VariableArrayValue", [1, 2, 3])
    assert [1, 2, 3] == await v.read_value()
    await opc.opc.delete_nodes([v])


async def test_bool_variable(opc):
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "BoolVariable", True)
    await declare_writable(opc, v)
    dt = await v.read_data_type_as_variant_type()
    assert ua.VariantType.Boolean == dt
    val = await v.read_value()
    assert val is True
    await v.write_value(False)
    val = await v.read_value()
    assert val is False
    await opc.opc.delete_nodes([v])


async def test_array_size_one_value(opc):
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "VariableArrayValue2", [1, 2, 3])
    await declare_writable(opc, v)
    await v.write_value([1])
    assert [1] == await v.read_value()
    await opc.opc.delete_nodes([v])


async def test_variable_with_datatype(opc):
    v1 = await opc.opc.nodes.objects.add_variable(
        3,
        "VariableEnumType1",
        ua.ApplicationType.ClientAndServer,
        datatype=ua.NodeId(ua.ObjectIds.ApplicationType),
    )
    tp1 = await v1.read_data_type()
    assert tp1 == ua.NodeId(ua.ObjectIds.ApplicationType)

    v2 = await opc.opc.nodes.objects.add_variable(
        3,
        "VariableEnumType2",
        ua.ApplicationType.ClientAndServer,
        datatype=ua.NodeId(ua.ObjectIds.ApplicationType),
    )
    tp2 = await v2.read_data_type()
    assert tp2 == ua.NodeId(ua.ObjectIds.ApplicationType)
    await opc.opc.delete_nodes([v1, v2])


async def test_sub_class(opc):
    idx = 4
    struct_with_sub = ua.PublishedDataSetDataType(
        "Test",
        [""],
        ua.DataSetMetaDataType(),
        [],
        ua.PublishedEventsDataType(ua.NodeId(NamespaceIndex=1), [], ua.ContentFilter([])),
    )
    var = await opc.opc.nodes.objects.add_variable(
        idx, "struct with sub", struct_with_sub, datatype=struct_with_sub.data_type
    )
    await declare_writable(opc, var)
    await var.write_value(struct_with_sub)
    val = await var.read_value()
    assert val == struct_with_sub
    assert val.DataSetSource == struct_with_sub.DataSetSource

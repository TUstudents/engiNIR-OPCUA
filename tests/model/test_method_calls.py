import math

import pytest

from enginir_opcua import ua, uamethod
from enginir_opcua.common.methods import call_method_full
from enginir_opcua.common.structures104 import new_enum, new_struct, new_struct_field

pytestmark = pytest.mark.asyncio


async def test_method(opc):
    o = opc.opc.nodes.objects
    await o.get_child("2:ServerMethod")
    result = await o.call_method("2:ServerMethod", 2.1)
    assert 4.2 == result
    with pytest.raises(ua.UaStatusCodeError):
        # FIXME: we should raise a more precise exception
        await o.call_method("2:ServerMethod", 2.1, 89, 9)
    with pytest.raises(ua.UaStatusCodeError):
        await o.call_method(ua.NodeId(999), 2.1)  # non existing method


async def test_method_no_arg(opc):
    o = opc.opc.nodes.objects
    await o.get_child("2:ServerMethodNoArg")
    result = await o.call_method("2:ServerMethodNoArg")
    assert 13 == result
    with pytest.raises(ua.UaStatusCodeError):
        # FIXME: we should raise a more precise exception
        await o.call_method("2:ServerMethodNoArg", 2.1, 89, 9)


async def test_method_array(opc):
    o = opc.opc.nodes.objects
    m = await o.get_child("2:ServerMethodArray")
    result = await o.call_method(m, "sin", ua.Variant(math.pi))
    assert result < 0.01
    with pytest.raises(ua.UaStatusCodeError) as exc_info:
        await o.call_method(m, "cos", ua.Variant(math.pi))
    assert ua.StatusCodes.BadInvalidArgument == exc_info.type.code
    with pytest.raises(ua.UaStatusCodeError) as exc_info:
        await o.call_method(m, "panic", ua.Variant(math.pi))
    assert ua.StatusCodes.BadOutOfMemory == exc_info.type.code


async def test_method_array2(opc):
    o = opc.opc.nodes.objects
    m = await o.get_child("2:ServerMethodArray2")
    result = await o.call_method(m, [1.1, 3.4, 9])
    assert [2.2, 6.8, 18] == result
    result = await call_method_full(o, m, [1.1, 3.4, 9])
    assert [[2.2, 6.8, 18]] == result.OutputArguments


async def test_method_tuple(opc):
    o = opc.opc.nodes.objects
    m = await o.get_child("2:ServerMethodTuple")
    result = await o.call_method(m)
    assert [1, 2, 3] == result
    result = await call_method_full(o, m)
    assert [1, 2, 3] == result.OutputArguments


async def test_method_none(opc):
    # this test calls the function linked to the type's method..
    o = await opc.opc.get_node(ua.ObjectIds.BaseObjectType).get_child("2:ObjectWithMethodsType")
    m = await o.get_child("2:ServerMethodDefault")
    result = await o.call_method(m)
    assert result is None
    result = await call_method_full(o, m)
    assert [] == result.OutputArguments


async def test_method_async(opc):
    o = opc.opc.nodes.objects
    m = await o.get_child("2:ServerMethodAsync")
    await o.call_method(m)
    await call_method_full(o, m)


async def test_method_byte_array(opc):
    o = opc.opc.nodes.objects
    m = await o.get_child("2:ServerMethodByteArray")
    val, mybytes = await o.call_method(
        m, ua.Variant(1, ua.VariantType.Byte), ua.Variant((2, 3, 4), ua.VariantType.Byte)
    )
    assert val == 1
    assert mybytes == [2, 3]


async def test_method_byte_array_better(opc):
    o = opc.opc.nodes.objects
    m = await o.get_child("2:ServerMethodByteArray")
    val, mybytes = await o.call_method(
        m, ua.Variant(1, ua.VariantType.Byte), ua.Variant(b"\x02\x03\x04", ua.VariantType.ByteString)
    )
    assert val == 1
    assert mybytes == [2, 3]


async def test_custom_method_with_struct(opc):
    idx = 4

    data_type, _nodes = await new_struct(
        opc.opc,
        idx,
        "MyStructArg",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32", ua.VariantType.UInt32, array=True),
        ],
    )

    await opc.opc.load_data_type_definitions()
    await opc.server.load_data_type_definitions()

    @uamethod
    def func(parent, mystruct):
        mystruct.MyUInt32.append(100)
        return mystruct

    methodid = await opc.server.nodes.objects.add_method(
        ua.NodeId("ServerMethodWithStruct", 10),
        ua.QualifiedName("ServerMethodWithStruct", 10),
        func,
        [ua.MyStructArg],
        [ua.MyStructArg],
    )

    mystruct = ua.MyStructArg()
    mystruct.MyUInt32 = [78, 79]

    assert data_type.nodeid == mystruct.data_type

    result = await opc.opc.nodes.objects.call_method(methodid, mystruct)

    assert result.MyUInt32 == [78, 79, 100]


async def test_custom_method_with_enum(opc):
    idx = 4
    enum_node = await new_enum(
        opc.opc,
        idx,
        "MyCustEnumForMethod",
        [
            "titi",
            "toto",
        ],
    )

    await opc.opc.load_data_type_definitions()

    @uamethod
    def func(parent, myenum1, myenum2, myenum3):
        assert myenum1 == ua.MyCustEnumForMethod.titi
        return ua.MyCustEnumForMethod.toto

    methodid = await opc.server.nodes.objects.add_method(
        ua.NodeId("servermethodwithenum", 10),
        ua.QualifiedName("servermethodwithenum", 10),
        func,
        [ua.MyCustEnumForMethod, enum_node, enum_node.nodeid],
        [ua.MyCustEnumForMethod],
    )

    result = await opc.opc.nodes.objects.call_method(
        methodid,
        ua.MyCustEnumForMethod.titi,
        ua.MyCustEnumForMethod.titi,
        ua.MyCustEnumForMethod.titi,
    )

    assert result == ua.MyCustEnumForMethod.toto


async def test_object_meth_args(opc):
    # Test if InputArguments and OutputArguments are create in an instantiated object
    base_otype = opc.opc.get_node(ua.ObjectIds.BaseObjectType)
    custom_otype = await base_otype.add_object_type(2, "ObjectWithMethodTestArgs")

    @uamethod
    def func(_parent, value):
        return value * 2

    meth = await custom_otype.add_method(
        ua.NodeId("ObjectWithMethodTestArgsTest", 2),
        ua.QualifiedName("ObjectWithMethodTestArgsTest", 2),
        func if hasattr(opc.opc, "iserver") else None,
        [ua.VariantType.Int64],
        [ua.VariantType.Int64],
    )
    await meth.set_modelling_rule(True)
    obj = await opc.opc.nodes.objects.add_object(2, "ObjectWithMethodsArgs", custom_otype)
    await obj.get_child(["2:ObjectWithMethodTestArgsTest", "InputArguments"])
    await obj.get_child(["2:ObjectWithMethodTestArgsTest", "OutputArguments"])

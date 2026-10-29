import math
from typing import Any

import pytest

from enginir_opcua import Server, ua, uamethod
from enginir_opcua.common import methods
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


@pytest.mark.parametrize(
    "payload",
    [
        ua.Variant((2, 3, 4), ua.VariantType.Byte),
        ua.Variant(b"\x02\x03\x04", ua.VariantType.ByteString),
    ],
    ids=["byte-array", "byte-string"],
)
async def test_method_byte_array(opc, payload):
    o = opc.opc.nodes.objects
    m = await o.get_child("2:ServerMethodByteArray")
    val, mybytes = await o.call_method(m, ua.Variant(1, ua.VariantType.Byte), payload)
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


@pytest.fixture(scope="module")
async def local_server() -> Any:
    srv = Server()
    await srv.init()
    await srv.register_namespace("urn:test:methods")
    yield srv


async def test_com8_failed_call_carries_argument_results_and_diagnostics(local_server: Server) -> None:
    """Part 4, 5.12.2: InputArgumentResults and InputArgumentDiagnosticInfos explain a Bad_InvalidArgument."""

    def echo(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return list(arguments)

    method = await local_server.nodes.objects.add_method(
        ua.NodeId(0, 2), ua.QualifiedName("Echo", 2), echo, [ua.VariantType.Int32], [ua.VariantType.Int32]
    )
    with pytest.raises(ua.UaStatusCodeError) as error:
        await local_server.nodes.objects.call_method(method, ua.Variant(1, ua.VariantType.Int64))
    assert error.value.code == ua.StatusCodes.BadInvalidArgument
    assert error.value.input_argument_results[0].value == ua.StatusCodes.BadTypeMismatch  # type: ignore[attr-defined]
    assert error.value.input_argument_diagnostic_infos == []  # type: ignore[attr-defined]


async def test_com8_argument_error_drops_the_cached_declaration(local_server: Server) -> None:
    def echo(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return list(arguments)

    method = await local_server.nodes.objects.add_method(
        ua.NodeId(0, 2), ua.QualifiedName("Echo2", 2), echo, [ua.VariantType.Int32], [ua.VariantType.Int32]
    )
    session = local_server.nodes.objects.session
    assert await local_server.nodes.objects.call_method(method, 5) == 5
    assert method.nodeid in methods._input_arguments[session]
    with pytest.raises(ua.UaStatusCodeError):
        await local_server.nodes.objects.call_method(method, ua.Variant(1, ua.VariantType.Int64))
    assert method.nodeid not in methods._input_arguments[session]


async def test_com103_two_dimensional_argument_is_converted(local_server: Server) -> None:
    """Part 3, 8.6: ValueRank 2 declares a two-dimensional array."""
    seen: list[ua.Variant] = []

    def record(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        seen.extend(arguments)
        return []

    argument = ua.Argument()
    argument.Name = "matrix"
    argument.DataType = ua.NodeId(ua.ObjectIds.Int32)
    argument.ValueRank = 2
    argument.ArrayDimensions = [0, 0]
    method = await local_server.nodes.objects.add_method(
        ua.NodeId(0, 2), ua.QualifiedName("Matrix", 2), record, [argument]
    )
    await local_server.nodes.objects.call_method(method, [[1, 2], [3, 4]])
    assert seen[0].VariantType == ua.VariantType.Int32
    assert seen[0].Dimensions == [2, 2]
    assert list(seen[0].Value) == [[1, 2], [3, 4]] or list(seen[0].Value) == [1, 2, 3, 4]


def test_com103_ragged_argument_is_a_type_error() -> None:
    with pytest.raises(TypeError):
        methods._convert_argument([[1, 2], 3], ua.VariantType.Int32, 2, 0)


def test_com7_uamethod_return_rules() -> None:
    parent = ua.NodeId(1, 1)

    @uamethod
    def none(parent: ua.NodeId, a: int) -> None:
        return None

    @uamethod
    def pair(parent: ua.NodeId, a: int) -> tuple[int, str]:
        return (a, "x")

    @uamethod
    def listing(parent: ua.NodeId, a: int) -> list[int]:
        return [a, a]

    @uamethod
    def status(parent: ua.NodeId, a: int) -> ua.StatusCode:
        return ua.StatusCode(ua.StatusCodes.BadInvalidState)

    @uamethod
    def full(parent: ua.NodeId, a: int) -> ua.CallMethodResult:
        return ua.CallMethodResult(OutputArguments=[7])

    argument = ua.Variant(3, ua.VariantType.Int32)
    assert none(parent, argument) == []
    assert [v.Value for v in pair(parent, argument)] == [3, "x"]
    outputs = listing(parent, argument)
    assert len(outputs) == 1 and outputs[0].Value == [3, 3]
    assert status(parent, argument).value == ua.StatusCodes.BadInvalidState
    assert full(parent, argument).OutputArguments[0].Value == 7


def test_com7_uamethod_on_an_object_method_gets_self_first() -> None:
    class Holder:
        @uamethod
        def method(self, parent: ua.NodeId, a: int) -> int:
            return a + 1

    holder = Holder()
    result = holder.method(ua.NodeId(1, 1), ua.Variant(3, ua.VariantType.Int32))
    assert result[0].Value == 4

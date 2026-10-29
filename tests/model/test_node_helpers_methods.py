from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import methods
from enginir_opcua.common.methods import uamethod


@pytest.fixture
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

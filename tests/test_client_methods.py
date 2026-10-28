import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.methods import uamethod


@pytest.fixture(scope="module")
async def typed_node(server: Server) -> ua.NodeId:
    def record(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return [ua.Variant(",".join(argument.VariantType.name for argument in arguments), ua.VariantType.String)]

    node = await server.nodes.objects.add_method(
        ua.NodeId("TypedMethod", 2),
        ua.QualifiedName("TypedMethod", 2),
        record,
        [ua.VariantType.Int32, ua.VariantType.Byte, ua.VariantType.UInt16, ua.VariantType.Float],
        [ua.VariantType.String],
    )
    return node.nodeid


@pytest.fixture
async def typed_method(server: Server, typed_node: ua.NodeId) -> AsyncIterator[tuple[Client, ua.NodeId]]:
    client = Client(server.endpoint.geturl())
    await client.connect()
    yield client, typed_node
    await client.disconnect()


async def test_cli23_int_argument_is_sent_as_the_declared_type(typed_method: tuple[Client, ua.NodeId]) -> None:
    """Part 4, 5.12.2.2: the arguments have the types the method declares; a Python int is not always Int64."""
    client, method_id = typed_method
    objects = client.get_objects_node()
    assert await objects.call_method(method_id, 1, 2, 3, 4.5) == "Int32,Byte,UInt16,Float"


async def test_cli23_variant_argument_is_sent_unchanged(typed_method: tuple[Client, ua.NodeId]) -> None:
    """An explicit Variant is the override: it is sent as it is, and the server's answer is reported."""
    client, method_id = typed_method
    objects = client.get_objects_node()
    arguments = [ua.Variant(1, ua.VariantType.Int64), 2, 3, 4.5]
    with pytest.raises(ua.UaStatusCodeError) as error:
        await objects.call_method(method_id, *arguments)
    assert error.value.code == ua.StatusCodes.BadInvalidArgument
    results = error.value.input_argument_results  # type: ignore[attr-defined]
    assert results[0].value == ua.StatusCodes.BadTypeMismatch
    assert results[1].is_good()


@pytest.mark.parametrize(
    "arguments",
    [("text", 2, 3, 4.5), (1.5, 2, 3, 4.5), (1, 300, 3, 4.5), (1, 2, -1, 4.5), (1, 2, 3, "x"), (1, [2], 3, 4.5)],
)
async def test_cli23_unconvertible_argument_is_a_type_error(
    typed_method: tuple[Client, ua.NodeId], arguments: tuple[Any, ...]
) -> None:
    """Part 4, 5.12.2.2: a value that cannot become the declared type fails before the call."""
    client, method_id = typed_method
    with pytest.raises(TypeError):
        await client.get_objects_node().call_method(method_id, *arguments)


async def test_cli23_too_many_arguments_fail_locally(typed_method: tuple[Client, ua.NodeId]) -> None:
    """Part 4, 5.12.2.2: Bad_TooManyArguments."""
    client, method_id = typed_method
    with pytest.raises(ua.uaerrors.BadTooManyArguments):
        await client.get_objects_node().call_method(method_id, 1, 2, 3, 4.5, 5)


async def test_cli23_bytes_for_a_byte_array_are_sent_as_a_byte_string(server: Server) -> None:
    """Part 4, 5.12.2.2, Table 62: a ByteString is accepted for an array of Byte."""

    def record(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return [ua.Variant(arguments[0].VariantType.name, ua.VariantType.String)]

    node = await server.nodes.objects.add_method(
        ua.NodeId("ByteArrayMethod", 2),
        ua.QualifiedName("ByteArrayMethod", 2),
        record,
        [[ua.VariantType.Byte]],
        [ua.VariantType.String],
    )
    client = Client(server.endpoint.geturl())
    async with client:
        assert await client.get_objects_node().call_method(node.nodeid, b"\x01\x02") == "ByteString"


async def test_cli33_call_method_accepts_a_timeout(server: Server) -> None:
    """Part 4, 7.33: a long call needs a longer deadline than the client's normal request timeout."""

    @uamethod
    async def slow(parent: Any) -> int:
        await asyncio.sleep(1.0)
        return 7

    node = await server.nodes.objects.add_method(
        ua.NodeId("SlowMethod", 2), ua.QualifiedName("SlowMethod", 2), slow, [], [ua.VariantType.Int64]
    )
    async with Client(server.endpoint.geturl(), timeout=0.3) as client:
        objects = client.get_objects_node()
        with pytest.raises(TimeoutError):
            await objects.call_method(node.nodeid)
        assert await objects.call_method(node.nodeid, timeout=5) == 7

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from enginir_opcua import Client, Node, Server, ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.config import ServerLimits
from enginir_opcua.server.user_managers import PermissiveUserManager
from enginir_opcua.ua.ua_binary import DecodeLimits, decode_limits, variant_from_binary, variant_to_binary
from tests.access_rig import free_port

MAX_STRING = 64
MAX_BYTES = 128
MAX_ARRAY = 10


@dataclass
class LimitRig:
    server: Server
    client: Client
    ns: int


@pytest.fixture(name="limit_rig")
async def make_limit_rig() -> AsyncIterator[LimitRig]:
    port = free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    server.max_string_length = MAX_STRING
    server.max_byte_string_length = MAX_BYTES
    server.max_array_length = MAX_ARRAY
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    ns = await server.register_namespace("http://test.example/limits")
    await server.start()
    client = Client(f"opc.tcp://admin@127.0.0.1:{port}", timeout=10)
    await client.connect()
    yield LimitRig(server, client, ns)
    await client.disconnect()
    await server.stop()


async def writable(rig: LimitRig, name: str, value: object, vtype: ua.VariantType | None = None) -> Node:
    node = await rig.server.nodes.objects.add_variable(ua.NodeId(name, rig.ns), f"{rig.ns}:{name}", value, vtype)
    await node.set_writable()
    return node


def test_srv85_defaults_and_server_limits(tmp_path: Path) -> None:
    """Part 5, 6.3.2: the three values are server limits with defaults, and ServerLimits carries them."""
    server = Server()
    assert server.max_string_length == 16_777_216
    assert server.max_byte_string_length == 16_777_216
    assert server.max_array_length == 1_000_000
    limits = ServerLimits(max_string_length=8_192, max_byte_string_length=16_384, max_array_length=500)
    configured = Server.quickstart("opc.tcp://127.0.0.1:4840", profile="development", pki=tmp_path, limits=limits)
    assert (configured.max_string_length, configured.max_byte_string_length, configured.max_array_length) == (
        8_192,
        16_384,
        500,
    )


async def test_srv85_server_capabilities_publish_the_three_limits(limit_rig: LimitRig) -> None:
    """Part 5, 6.3.2: ServerCapabilities holds MaxStringLength, MaxByteStringLength and MaxArrayLength."""
    values = {}
    for name in ("MaxStringLength", "MaxByteStringLength", "MaxArrayLength"):
        node = limit_rig.client.get_node(ua.NodeId(getattr(ua.ObjectIds, f"Server_ServerCapabilities_{name}")))
        values[name] = await node.read_value()
    assert values == {"MaxStringLength": MAX_STRING, "MaxByteStringLength": MAX_BYTES, "MaxArrayLength": MAX_ARRAY}


async def test_srv85_request_with_a_long_string_is_refused_at_decode(limit_rig: LimitRig) -> None:
    """Part 4, 5.3: a request with a String over the limit gets a ServiceFault Bad_EncodingLimitsExceeded."""
    node = limit_rig.client.get_node(ua.NodeId("x" * (MAX_STRING + 1), limit_rig.ns))
    with pytest.raises(ua.uaerrors.BadEncodingLimitsExceeded):
        await node.read_value()
    ok = limit_rig.client.get_node(ua.NodeId("x" * MAX_STRING, limit_rig.ns))
    with pytest.raises(ua.uaerrors.BadNodeIdUnknown):
        await ok.read_value()


async def test_srv85_request_with_a_long_byte_string_is_refused_at_decode(limit_rig: LimitRig) -> None:
    """Part 4, 5.3: the same for a ByteString, here the identifier of a NodeId."""
    node = limit_rig.client.get_node(ua.NodeId(b"x" * (MAX_BYTES + 1), limit_rig.ns))
    with pytest.raises(ua.uaerrors.BadEncodingLimitsExceeded):
        await node.read_value()


async def test_srv85_string_limit_counts_bytes(limit_rig: LimitRig) -> None:
    """Part 5, 6.3.2: MaxStringLength is a number of bytes."""
    node = limit_rig.client.get_node(ua.NodeId("é" * (MAX_STRING // 2 + 1), limit_rig.ns))
    with pytest.raises(ua.uaerrors.BadEncodingLimitsExceeded):
        await node.read_value()


async def test_srv85_write_of_long_values_is_out_of_range_per_operation(limit_rig: LimitRig) -> None:
    """Part 4, 5.11.4.4: Write answers Bad_OutOfRange for the value, and the other operations still run."""
    text = await writable(limit_rig, "WText", "a")
    blob = await writable(limit_rig, "WBlob", b"a", ua.VariantType.ByteString)
    array = await writable(limit_rig, "WArray", [1, 2], ua.VariantType.Int32)
    fine = await writable(limit_rig, "WFine", 1, ua.VariantType.Int32)
    values = [
        (text, ua.Variant("x" * (MAX_STRING + 1), ua.VariantType.String)),
        (blob, ua.Variant(b"x" * (MAX_BYTES + 1), ua.VariantType.ByteString)),
        (array, ua.Variant(list(range(MAX_ARRAY + 1)), ua.VariantType.Int32)),
        (fine, ua.Variant(7, ua.VariantType.Int32)),
        (text, ua.Variant("x" * MAX_STRING, ua.VariantType.String)),
    ]
    writes = []
    for node, variant in values:
        item = ua.WriteValue()
        item.NodeId = node.nodeid
        item.AttributeId = ua.AttributeIds.Value
        item.Value = ua.DataValue(variant)
        writes.append(item)
    params = ua.WriteParameters(NodesToWrite=writes)
    results = await limit_rig.client.uaclient.write(params)
    assert [r.value for r in results] == [ua.StatusCodes.BadOutOfRange] * 3 + [ua.StatusCodes.Good] * 2
    assert await text.read_value() == "x" * MAX_STRING
    assert await array.read_value() == [1, 2]
    assert await fine.read_value() == 7


async def test_srv85_write_of_a_long_string_inside_a_string_array(limit_rig: LimitRig) -> None:
    """Part 5, 6.3.2: when the value is an array the String limit applies to each element."""
    node = await writable(limit_rig, "WStrings", ["a"], ua.VariantType.String)
    remote = limit_rig.client.get_node(node.nodeid)
    with pytest.raises(ua.uaerrors.BadOutOfRange):
        await remote.write_value(ua.Variant(["a", "x" * (MAX_STRING + 1)], ua.VariantType.String))
    await remote.write_value(ua.Variant(["a", "x" * MAX_STRING], ua.VariantType.String))


async def test_srv85_call_with_long_arguments_names_the_argument(limit_rig: LimitRig) -> None:
    """Part 4, 5.12.2.4: the Method answers Bad_InvalidArgument and the argument result Bad_OutOfRange."""
    calls = []

    def callback(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        calls.append(arguments)
        return []

    method = await limit_rig.server.nodes.objects.add_method(
        ua.NodeId("LimitMethod", limit_rig.ns),
        ua.QualifiedName("LimitMethod", limit_rig.ns),
        callback,
        [ua.VariantType.String, ua.VariantType.ByteString, ua.VariantType.Int32],
        [],
    )
    request = ua.CallMethodRequest(
        ObjectId=limit_rig.server.nodes.objects.nodeid,
        MethodId=method.nodeid,
        InputArguments=[
            ua.Variant("ok", ua.VariantType.String),
            ua.Variant(b"x" * (MAX_BYTES + 1), ua.VariantType.ByteString),
            ua.Variant(1, ua.VariantType.Int32),
        ],
    )
    (result,) = await limit_rig.client.uaclient.call([request])
    assert result.StatusCode == ua.StatusCode(ua.StatusCodes.BadInvalidArgument)
    assert [r.value for r in result.InputArgumentResults] == [
        ua.StatusCodes.Good,
        ua.StatusCodes.BadOutOfRange,
        ua.StatusCodes.Good,
    ]
    assert calls == []
    request.InputArguments[1] = ua.Variant(b"x" * MAX_BYTES, ua.VariantType.ByteString)
    (result,) = await limit_rig.client.uaclient.call([request])
    assert result.StatusCode == ua.StatusCode(ua.StatusCodes.Good)
    assert len(calls) == 1


async def test_srv85_in_process_writes_are_not_limited(limit_rig: LimitRig) -> None:
    """The limits are for requests from clients; the application's own writes are trusted."""
    node = await writable(limit_rig, "Local", "a")
    await node.write_value("x" * (MAX_STRING + 10))
    assert await node.read_value() == "x" * (MAX_STRING + 10)


def test_srv85_decoder_without_limits_is_unchanged_and_array_is_checked_before_reading() -> None:
    """The decoder enforces limits only where a receiver sets them; the client side sets none."""
    data = variant_to_binary(ua.Variant(list(range(50)), ua.VariantType.Int32))
    assert len(variant_from_binary(Buffer(data)).Value) == 50
    token = decode_limits.set(DecodeLimits(100, 100, 49))
    try:
        with pytest.raises(ua.uaerrors.BadEncodingLimitsExceeded):
            variant_from_binary(Buffer(data))
        exempt = decode_limits.set(DecodeLimits(100, 100, 49, variant_values=False))
        try:
            assert len(variant_from_binary(Buffer(data)).Value) == 50
        finally:
            decode_limits.reset(exempt)
    finally:
        decode_limits.reset(token)

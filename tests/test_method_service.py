from typing import Any

from enginir_opcua import Node, ua

from .access_rig import AccessRig, make_access_rig  # noqa: F401


def code(value: int) -> ua.StatusCode:
    return ua.StatusCode(value)


def int64(value: int) -> ua.Variant:
    return ua.Variant(value, ua.VariantType.Int64)


async def call(
    rig: AccessRig, object_id: ua.NodeId, method_id: ua.NodeId, *arguments: ua.Variant, admin: bool = False
) -> ua.CallMethodResult:
    request = ua.CallMethodRequest(ObjectId=object_id, MethodId=method_id, InputArguments=list(arguments))
    client = rig.admin if admin else rig.user
    return (await client.uaclient.call([request]))[0]


async def add_method(rig: AccessRig, parent: Node, name: str, inputs: list[Any], outputs: list[Any]) -> Node:
    calls: list[tuple[Any, ...]] = []

    def callback(parent_id: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        calls.append((parent_id, *arguments))
        return [int64(sum(arg.Value for arg in arguments if isinstance(arg.Value, int)))]

    method = await parent.add_method(rig.node_id(name), ua.QualifiedName(name, rig.ns), callback, inputs, outputs)
    method.calls = calls  # type: ignore[attr-defined]
    return method


async def test_srv17_call_with_unknown_and_null_nodes(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.4."""
    method = await add_method(access_rig, access_rig.server.nodes.objects, "KnownMethod", [], [ua.VariantType.Int64])
    objects = access_rig.server.nodes.objects.nodeid
    assert (await call(access_rig, ua.NodeId("Nothing", access_rig.ns), method.nodeid)).StatusCode == code(
        ua.StatusCodes.BadNodeIdUnknown
    )
    assert (await call(access_rig, objects, ua.NodeId("Nothing", access_rig.ns))).StatusCode == code(
        ua.StatusCodes.BadNodeIdUnknown
    )
    assert (await call(access_rig, ua.NodeId(), method.nodeid)).StatusCode == code(ua.StatusCodes.BadNodeIdInvalid)
    assert (await call(access_rig, objects, ua.NodeId(ua.ObjectIds.Server))).StatusCode == code(
        ua.StatusCodes.BadMethodInvalid
    )


async def test_srv18_method_must_belong_to_object_or_its_type(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.2."""
    owner = await access_rig.server.nodes.objects.add_object(access_rig.node_id("MethodOwner"), "MethodOwner")
    stranger = await access_rig.server.nodes.objects.add_object(access_rig.node_id("MethodStranger"), "MethodStranger")
    method = await add_method(access_rig, owner, "OwnedMethod", [], [ua.VariantType.Int64])
    ok = await call(access_rig, owner.nodeid, method.nodeid)
    assert ok.StatusCode == code(0)
    assert method.calls == [(owner.nodeid,)]  # type: ignore[attr-defined]
    for other in (stranger.nodeid, ua.NodeId(ua.ObjectIds.Server)):
        result = await call(access_rig, other, method.nodeid)
        assert result.StatusCode == code(ua.StatusCodes.BadMethodInvalid)
    assert len(method.calls) == 1  # type: ignore[attr-defined]


async def test_srv18_type_level_call(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.2; Part 3, 5.7.1."""
    object_type = await access_rig.server.nodes.base_object_type.add_object_type(
        access_rig.node_id("MethodType"), "MethodType"
    )
    method = await add_method(access_rig, object_type, "TypeMethod", [], [ua.VariantType.Int64])
    instance = await access_rig.server.nodes.objects.add_object(
        access_rig.node_id("MethodTypeInstance"), "MethodTypeInstance", object_type.nodeid
    )
    on_instance = await call(access_rig, instance.nodeid, method.nodeid)
    assert on_instance.StatusCode == code(0)
    on_type = await call(access_rig, object_type.nodeid, method.nodeid)
    assert on_type.StatusCode == code(0)
    assert method.calls == [(instance.nodeid,), (object_type.nodeid,)]  # type: ignore[attr-defined]


async def test_srv18_executable_and_user_executable(access_rig: AccessRig) -> None:
    """Part 3, 5.7.1; Part 4, 5.12.2.4."""
    method = await add_method(access_rig, access_rig.server.nodes.objects, "GuardedMethod", [], [ua.VariantType.Int64])
    objects = access_rig.server.nodes.objects.nodeid
    await method.write_attribute(
        ua.AttributeIds.UserExecutable, ua.DataValue(ua.Variant(False, ua.VariantType.Boolean))
    )
    for admin in (False, True):
        result = await call(access_rig, objects, method.nodeid, admin=admin)
        assert result.StatusCode == code(ua.StatusCodes.BadUserAccessDenied)
    await method.write_attribute(ua.AttributeIds.Executable, ua.DataValue(ua.Variant(False, ua.VariantType.Boolean)))
    for admin in (False, True):
        result = await call(access_rig, objects, method.nodeid, admin=admin)
        assert result.StatusCode == code(ua.StatusCodes.BadNotExecutable)
    assert method.calls == []  # type: ignore[attr-defined]


async def test_srv18_in_process_call_skips_the_executable_bits(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.4."""
    method = await add_method(access_rig, access_rig.server.nodes.objects, "LocalMethod", [], [ua.VariantType.Int64])
    await method.write_attribute(ua.AttributeIds.Executable, ua.DataValue(ua.Variant(False, ua.VariantType.Boolean)))
    result = await access_rig.server.nodes.objects.call_method(method.nodeid)
    assert result == 0


async def test_srv18_too_many_missing_and_optional_arguments(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.2, 5.12.2.4."""
    method = await add_method(
        access_rig,
        access_rig.server.nodes.objects,
        "CountedMethod",
        [ua.VariantType.Int64, ua.VariantType.Int64],
        [ua.VariantType.Int64],
    )
    objects = access_rig.server.nodes.objects.nodeid
    too_many = await call(access_rig, objects, method.nodeid, int64(1), int64(2), int64(3))
    assert too_many.StatusCode == code(ua.StatusCodes.BadTooManyArguments)
    missing = await call(access_rig, objects, method.nodeid, int64(1))
    assert missing.StatusCode == code(ua.StatusCodes.BadArgumentsMissing)
    assert missing.InputArgumentResults == []
    good = await call(access_rig, objects, method.nodeid, int64(1), int64(2))
    assert good.StatusCode == code(0)
    assert good.OutputArguments[0].Value == 3
    none_expected = await add_method(access_rig, access_rig.server.nodes.objects, "NoArguments", [], [])
    extra = await call(access_rig, objects, none_expected.nodeid, int64(1))
    assert extra.StatusCode == code(ua.StatusCodes.BadTooManyArguments)


async def test_srv18_argument_type_mismatch_lists_input_argument_results(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.2, 5.12.2.4."""
    method = await add_method(
        access_rig,
        access_rig.server.nodes.objects,
        "TypedMethod",
        [ua.VariantType.Int64, ua.VariantType.String, [ua.VariantType.Int64]],
        [ua.VariantType.Int64],
    )
    objects = access_rig.server.nodes.objects.nodeid
    wrong = await call(
        access_rig,
        objects,
        method.nodeid,
        ua.Variant(1, ua.VariantType.Int32),
        ua.Variant("text", ua.VariantType.String),
        ua.Variant(5, ua.VariantType.Int64),
    )
    assert wrong.StatusCode == code(ua.StatusCodes.BadInvalidArgument)
    assert wrong.InputArgumentResults == [
        code(ua.StatusCodes.BadTypeMismatch),
        code(0),
        code(ua.StatusCodes.BadTypeMismatch),
    ]
    assert method.calls == []  # type: ignore[attr-defined]
    right = await call(
        access_rig,
        objects,
        method.nodeid,
        int64(1),
        ua.Variant("text", ua.VariantType.String),
        ua.Variant([5, 6], ua.VariantType.Int64),
    )
    assert right.StatusCode == code(0)
    assert right.InputArgumentResults == []


async def test_srv18_method_without_callback_is_not_supported(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.4."""
    method = await access_rig.server.nodes.objects.add_method(
        access_rig.node_id("NoCallback"), ua.QualifiedName("NoCallback", access_rig.ns), None, [], []
    )
    result = await call(access_rig, access_rig.server.nodes.objects.nodeid, method.nodeid)
    assert result.StatusCode == code(ua.StatusCodes.BadNotSupported)


async def test_srv18_callback_exception_is_unexpected_error_without_text(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.4."""

    def broken(parent_id: ua.NodeId) -> None:
        raise RuntimeError("secret detail")

    objects = access_rig.server.nodes.objects
    method = await objects.add_method(
        access_rig.node_id("Broken"), ua.QualifiedName("Broken", access_rig.ns), broken, [], []
    )
    result = await call(access_rig, objects.nodeid, method.nodeid)
    assert result.StatusCode == code(ua.StatusCodes.BadUnexpectedError)
    assert result.OutputArguments == []


async def test_srv18_callback_status_results(access_rig: AccessRig) -> None:
    """Part 4, 5.12.2.2."""

    def refusing(parent_id: ua.NodeId) -> ua.StatusCode:
        return ua.StatusCode(ua.StatusCodes.BadOutOfRange)

    def raising(parent_id: ua.NodeId) -> None:
        raise ua.uaerrors.BadNotImplemented()

    objects = access_rig.server.nodes.objects
    first = await objects.add_method(
        access_rig.node_id("Refusing"), ua.QualifiedName("Refusing", access_rig.ns), refusing, [], []
    )
    second = await objects.add_method(
        access_rig.node_id("Raising"), ua.QualifiedName("Raising", access_rig.ns), raising, [], []
    )
    assert (await call(access_rig, objects.nodeid, first.nodeid)).StatusCode == code(ua.StatusCodes.BadOutOfRange)
    assert (await call(access_rig, objects.nodeid, second.nodeid)).StatusCode == code(ua.StatusCodes.BadNotImplemented)

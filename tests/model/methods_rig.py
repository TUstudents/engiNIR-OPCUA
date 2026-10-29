import asyncio
import math

from enginir_opcua import ua, uamethod


async def add_server_methods(srv):
    @uamethod
    def func(parent, value):
        return value * 2

    o = srv.nodes.objects
    await o.add_method(
        ua.NodeId("ServerMethod", 2),
        ua.QualifiedName("ServerMethod", 2),
        func,
        [ua.VariantType.Double],
        [ua.VariantType.Double],
    )

    @uamethod
    def func_no_arg(parent):
        return 13

    o = srv.nodes.objects
    await o.add_method(
        ua.NodeId("ServerMethodNoArg", 2),
        ua.QualifiedName("ServerMethodNoArg", 2),
        func_no_arg,
    )

    @uamethod
    def func2(parent, methodname, value):
        if methodname == "panic":
            return ua.StatusCode(ua.StatusCodes.BadOutOfMemory)
        if methodname != "sin":
            res = ua.CallMethodResult()
            res.StatusCode = ua.StatusCode(ua.StatusCodes.BadInvalidArgument)
            res.InputArgumentResults = [
                ua.StatusCode(ua.StatusCodes.BadNotSupported),
                ua.StatusCode(),
            ]
            return res
        return math.sin(value)

    o = srv.nodes.objects
    await o.add_method(
        ua.NodeId("ServerMethodArray", 2),
        ua.QualifiedName("ServerMethodArray", 2),
        func2,
        [ua.VariantType.String, ua.VariantType.Double],
        [ua.VariantType.Double],
    )

    @uamethod
    def func3(parent, mylist):
        return [i * 2 for i in mylist]

    o = srv.nodes.objects
    await o.add_method(
        ua.NodeId("ServerMethodArray2", 2),
        ua.QualifiedName("ServerMethodArray2", 2),
        func3,
        [[ua.VariantType.Double]],
        [[ua.VariantType.Double]],
    )

    @uamethod
    def func4(parent):
        return None

    base_otype = srv.get_node(ua.ObjectIds.BaseObjectType)
    custom_otype = await base_otype.add_object_type(2, "ObjectWithMethodsType")
    await custom_otype.add_method(2, "ServerMethodDefault", func4)
    await (await custom_otype.add_method(2, "ServerMethodMandatory", func4)).set_modelling_rule(True)
    await (await custom_otype.add_method(2, "ServerMethodOptional", func4)).set_modelling_rule(False)
    await (await custom_otype.add_method(2, "ServerMethodNone", func4)).set_modelling_rule(None)
    await o.add_object(2, "ObjectWithMethods", custom_otype)

    @uamethod
    def func5(parent):
        return 1, 2, 3

    o = srv.nodes.objects
    await o.add_method(
        ua.NodeId("ServerMethodTuple", 2),
        ua.QualifiedName("ServerMethodTuple", 2),
        func5,
        [],
        [ua.VariantType.Int64, ua.VariantType.Int64, ua.VariantType.Int64],
    )

    @uamethod
    async def func6(parent):
        await asyncio.sleep(0)

    o = srv.nodes.objects
    await o.add_method(
        ua.NodeId("ServerMethodAsync", 2),
        ua.QualifiedName("ServerMethodAsync", 2),
        func6,
        [],
        [],
    )

    @uamethod
    async def func7(parent, val, mybytes):
        return (val, [mybytes[0], mybytes[1]])

    o = srv.nodes.objects
    await o.add_method(
        ua.NodeId("ServerMethodByteArray", 2),
        ua.QualifiedName("ServerMethodByteArray", 2),
        func7,
        [ua.VariantType.Byte, [ua.VariantType.Byte, ua.VariantType.Byte, ua.VariantType.Byte]],
        [ua.VariantType.Boolean, [ua.VariantType.Byte, ua.VariantType.Byte]],
    )

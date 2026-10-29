"""
Methods with typed, named arguments.

Shows: a server method declared with ua.Argument (name, data type, description), the client reading the declared
arguments from the InputArguments and OutputArguments properties, calling the method, and a call that the server
refuses (an argument of the wrong type (checked by the client against the declaration) and a status code returned by the method). Calling a method needs the "user" role.

Run: python examples/04_methods.py

Spec: OPC 10000-3 v1.05, 5.7 (Method NodeClass) and 8.6 (Argument); OPC 10000-4 v1.05, 5.12 (Method service set:
Call).
"""

import asyncio
from typing import Any

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua, uamethod
from enginir_opcua.crypto.users_file import UserRecord, hash_password, write_users


def argument(name: str, data_type: ua.NodeId, description: str, rank: int = -1) -> ua.Argument:
    arg = ua.Argument()
    arg.Name = name
    arg.DataType = data_type
    arg.ValueRank = rank
    arg.ArrayDimensions = [0] if rank == 1 else []
    arg.Description = ua.LocalizedText(description)
    return arg


@uamethod
def scale(parent: ua.NodeId, value: float, factor: float) -> float | ua.StatusCode:
    if factor == 0:
        return ua.StatusCode(ua.StatusCodes.BadInvalidArgument)
    return value * factor


@uamethod
def mean(parent: ua.NodeId, values: list[float]) -> float:
    return sum(values) / len(values)


async def main() -> None:
    with workdir() as directory:
        users = directory / "users.toml"
        write_users(users, [UserRecord("operator", "user", hash_password("operator-secret"))])
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki", users=users)
        client = Client.quickstart(url, pki=directory / "client-pki", username="operator", password="operator-secret")
        await server.init()
        idx = await server.register_namespace("urn:enginir:example:methods")
        double = ua.NodeId(ua.ObjectIds.Double)
        scale_node = await server.nodes.objects.add_method(
            idx,
            "Scale",
            scale,
            [argument("Value", double, "the value to scale"), argument("Factor", double, "multiplier, not zero")],
            [argument("Result", double, "Value times Factor")],
        )
        await server.nodes.objects.add_method(
            idx, "Mean", mean, [argument("Values", double, "samples", rank=1)], [argument("Mean", double, "average")]
        )
        await pair(directory / "server-pki", directory / "client-pki", client.application_uri)

        async with server, client:
            objects = client.nodes.objects
            method = client.get_node(scale_node.nodeid)
            declared: list[Any] = await (await method.get_child("0:InputArguments")).read_value()
            print("Scale takes:", ", ".join(f"{a.Name} ({a.Description.Text})" for a in declared))
            print("Scale(6, 7) =", await objects.call_method(method, 6.0, 7.0))
            mean_id = ua.QualifiedName("Mean", idx)
            print("Mean([1, 2, 6]) =", await objects.call_method(mean_id, [1.0, 2.0, 6.0]))
            try:
                await objects.call_method(method, 6.0, 0.0)
            except ua.UaStatusCodeError as error:
                print("Scale(6, 0) refused:", ua.StatusCode(error.code).name)
            try:
                await objects.call_method(method, "six", 7.0)
            except TypeError as error:
                print("Scale('six', 7) refused by the client:", error)
    print("OK 04_methods")


if __name__ == "__main__":
    asyncio.run(main())

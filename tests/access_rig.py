import socket
from collections.abc import AsyncIterator
from contextlib import closing
from dataclasses import dataclass
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.node import Node
from enginir_opcua.server.user_managers import PermissiveUserManager


def payload(dv: ua.DataValue) -> Any:
    assert dv.Value is not None
    return dv.Value.Value


@dataclass
class AccessRig:
    server: Server
    admin: Client
    user: Client
    ns: int

    def node_id(self, name: str) -> ua.NodeId:
        return ua.NodeId(name, self.ns)

    async def add_variable(
        self,
        name: str,
        value: object,
        varianttype: ua.VariantType | None = None,
        *,
        access: int | None = None,
        user_access: int | None = None,
        writable: bool = False,
    ) -> Node:
        node = await self.server.nodes.objects.add_variable(self.node_id(name), f"{self.ns}:{name}", value, varianttype)
        if writable:
            await node.set_writable()
        if access is not None:
            await node.write_attribute(
                ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access, ua.VariantType.Byte))
            )
        if user_access is not None:
            await node.write_attribute(
                ua.AttributeIds.UserAccessLevel, ua.DataValue(ua.Variant(user_access, ua.VariantType.Byte))
            )
        return node


def free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module", name="access_rig")
async def make_access_rig() -> AsyncIterator[AccessRig]:
    port = free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    ns = await server.register_namespace("http://test.example/access")
    await server.start()
    admin = Client(f"opc.tcp://admin@127.0.0.1:{port}", timeout=10)
    user = Client(f"opc.tcp://someone@127.0.0.1:{port}", timeout=10)
    await admin.connect()
    await user.connect()
    yield AccessRig(server, admin, user, ns)
    await user.disconnect()
    await admin.disconnect()
    await server.stop()

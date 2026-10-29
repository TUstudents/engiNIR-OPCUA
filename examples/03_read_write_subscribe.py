"""
Reading, writing and subscribing, and what happens when the server restarts.

Shows: Node.read_value and write_value, a data-change subscription with a handler, and a client that reconnects by
itself (Client.quickstart(auto_reconnect=True)): the server is stopped and started again, the client's session and
subscription come back, and the handler keeps receiving values.

Run: python examples/03_read_write_subscribe.py

Spec: OPC 10000-4 v1.05, 5.11 (Attribute services: Read and Write), 5.13 (MonitoredItem services),
5.14 (Subscription services), 6.7 (Re-establishing connections).
"""

import asyncio
from pathlib import Path
from typing import Any

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.node import Node
from enginir_opcua.crypto.users_file import UserRecord, hash_password, write_users

NAMESPACE = "urn:enginir:example:subscribe"
COUNTER = ua.NodeId("Counter", 2)


class Handler:
    def __init__(self) -> None:
        self.values: asyncio.Queue[Any] = asyncio.Queue()

    def datachange_notification(self, node: Node, value: Any, data: ua.DataChangeNotification) -> None:
        print("data change:", value)
        self.values.put_nowait(value)


async def build_server(url: str, pki: Path, users: Path) -> tuple[Server, Node]:
    server = Server.quickstart(url, pki=pki, users=users)
    await server.init()
    idx = await server.register_namespace(NAMESPACE)
    counter = await server.nodes.objects.add_variable(ua.NodeId("Counter", idx), "Counter", 0)
    await counter.set_writable()
    return server, counter


async def main() -> None:
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server_pki = directory / "server-pki"
        users = directory / "users.toml"
        write_users(users, [UserRecord("operator", "user", hash_password("operator-secret"))])
        client = Client.quickstart(
            url,
            pki=directory / "client-pki",
            username="operator",
            password="operator-secret",
            auto_reconnect=True,
            timeout=2.0,
        )
        server, counter = await build_server(url, server_pki, users)
        await pair(server_pki, directory / "client-pki", client.application_uri)
        await server.start()

        async with client:
            node = client.get_node(counter.nodeid)
            await node.write_value(5)
            print("read back:", await node.read_value())

            handler = Handler()
            subscription = await client.create_subscription(100, handler)
            await subscription.subscribe_data_change(node)
            await asyncio.wait_for(handler.values.get(), 5)
            await node.write_value(6)
            assert await asyncio.wait_for(handler.values.get(), 5) == 6

            print("stopping the server")
            await server.stop()
            server, counter = await build_server(url, server_pki, users)
            await server.start()
            print("server is back; waiting for the client")
            while True:
                if await asyncio.wait_for(handler.values.get(), 15) == 0:
                    break
            await counter.write_value(7)
            assert await asyncio.wait_for(handler.values.get(), 5) == 7
        await server.stop()
    print("OK 03_read_write_subscribe")


if __name__ == "__main__":
    asyncio.run(main())

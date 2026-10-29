"""
Reverse connect: the server dials the client, the client then runs the secure channel on that socket.

Shows: Server.add_reverse_connect (the server connects out to a client that listens and sends a ReverseHello with
its application URI) and Client.listen_reverse (the client waits for that server and accepts nobody else). This is
the pattern for a server behind a firewall that only allows outgoing connections. Security is unchanged: the same
certificates are exchanged and have to be trusted as with a normal connection.

Run: python examples/16_reverse_connect.py

Spec: OPC 10000-6 v1.05, 7.1.2.6 (ReverseHello message) and 7.1.3 (reverse connect: socket handling and
endpoint selection); OPC 10000-4 v1.05, 7.14 (EndpointDescription).
"""

import asyncio

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua


async def main() -> None:
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        listen_url = f"opc.tcp://127.0.0.1:{free_port()}"
        server = Server.quickstart(url, pki=directory / "server-pki")
        client = Client.quickstart(url, pki=directory / "client-pki", timeout=5.0)
        await server.init()
        await pair(directory / "server-pki", directory / "client-pki", client.application_uri)

        server.add_reverse_connect(listen_url, retry_interval=0.5)
        client.listen_reverse(listen_url, server_uri=server.get_application_uri(), accept_timeout=20.0)
        async with server, client:
            state = await client.get_node(ua.ObjectIds.Server_ServerStatus_State).read_value()
            print("connected through the server's call:", ua.ServerState(state).name)
    print("OK 16_reverse_connect")


if __name__ == "__main__":
    asyncio.run(main())

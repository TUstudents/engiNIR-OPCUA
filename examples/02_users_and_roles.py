"""
Users with roles, from a users file with salted password hashes.

Shows: write_users and hash_password to create a users file (the command-line way is `enginir-opcua user add`),
Server.quickstart(users=...), and three clients: anonymous (read only), a "user" (may also write and call methods) and
an "admin" (may also change the address space). A refused request comes back as BadUserAccessDenied.

Run: python examples/02_users_and_roles.py

Spec: OPC 10000-4 v1.05, 7.40 (UserIdentityToken parameters), 5.7.2 (CreateSession) and 5.7.3
(ActivateSession); OPC 10000-18 v1.05 (Role-Based Security, well-known roles).
"""

import asyncio

from _common import create_client_credentials, free_port, trust, workdir

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.users_file import UserRecord, hash_password, write_users


async def attempt(label: str, action) -> None:  # type: ignore[no-untyped-def]
    try:
        await action()
    except ua.UaStatusCodeError as error:
        print(f"{label:<28} refused: {ua.StatusCode(error.code).name}")
        return
    print(f"{label:<28} allowed")


async def main() -> None:
    with workdir() as directory:
        users = directory / "users.toml"
        write_users(
            users,
            [
                UserRecord("alice", "user", hash_password("alice-secret-1")),
                UserRecord("root", "admin", hash_password("root-secret-1")),
            ],
        )
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki", users=users)
        await server.init()
        idx = await server.register_namespace("urn:enginir:example:users")
        setpoint = await server.nodes.objects.add_variable(idx, "Setpoint", 10.0)
        await setpoint.set_writable()

        client_pki = directory / "client-pki"
        anonymous = Client.quickstart(url, pki=client_pki)
        alice = Client.quickstart(url, pki=client_pki, username="alice", password="alice-secret-1")
        root = Client.quickstart(url, pki=client_pki, username="root", password="root-secret-1")
        await create_client_credentials(client_pki, anonymous.application_uri)
        trust(directory / "server-pki", client_pki)
        trust(client_pki, directory / "server-pki")

        async with server, anonymous, alice, root:
            for label, client in (("anonymous", anonymous), ("alice (user)", alice), ("root (admin)", root)):
                node = client.get_node(setpoint.nodeid)
                await attempt(f"{label} reads", node.read_value)
                await attempt(f"{label} writes", lambda node=node: node.write_value(11.0))
                folder = client.nodes.objects
                await attempt(f"{label} adds a node", lambda folder=folder, label=label: folder.add_folder(idx, label))
            print("setpoint is now", await setpoint.read_value())
    print("OK 02_users_and_roles")


if __name__ == "__main__":
    asyncio.run(main())

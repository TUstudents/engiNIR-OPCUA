"""
Certificate management over OPC UA (the push model): a SecurityAdmin trusts a rejected client remotely.

Shows: Server.enable_push_management, which adds the ServerConfiguration object and the TrustList of the server;
a guest client whose certificate the server does not trust and that is therefore rejected (the certificate lands in
the server's rejected folder); an administrator with the SecurityAdmin role, connected over SignAndEncrypt, who
reads the rejected list with GetRejectedList and trusts the guest certificate with the TrustList method
AddCertificate; and the guest connecting afterwards. Only a SecurityAdmin on a SignAndEncrypt channel may call these
methods.

Run: python examples/14_certificate_management.py

Spec: OPC 10000-12 v1.05, 7.4 (push management), 7.7.2 (workflow), 7.8.2 (TrustLists), 7.8.2.6 (AddCertificate),
7.10.4 (ServerConfiguration) and 7.10.12 (GetRejectedList); OPC 10000-18 v1.05 (SecurityAdmin role).
"""

import asyncio
from typing import Any

from _common import create_client_credentials, free_port, trust, workdir

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.users_file import UserRecord, hash_password, write_users

SERVER_CONFIGURATION = ua.NodeId(ua.ObjectIds.ServerConfiguration)
TRUST_LIST = ua.NodeId(ua.ObjectIds.ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList)


async def call(client: Client, parent: ua.NodeId, method: str, *args: ua.Variant) -> Any:
    return await client.get_node(parent).call_method(ua.QualifiedName(method, 0), *args)


async def main() -> None:
    with workdir() as directory:
        users = directory / "users.toml"
        write_users(users, [UserRecord("root", "security_admin", hash_password("root-secret-1"))])
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki", users=users)
        admin = Client.quickstart(url, pki=directory / "admin-pki", username="root", password="root-secret-1")
        guest = Client.quickstart(url, pki=directory / "guest-pki", application_uri="urn:enginir:example:guest")
        await server.init()
        await server.enable_push_management()
        await create_client_credentials(directory / "admin-pki", admin.application_uri)
        await create_client_credentials(directory / "guest-pki", guest.application_uri)
        trust(directory / "server-pki", directory / "admin-pki")
        trust(directory / "admin-pki", directory / "server-pki")
        trust(directory / "guest-pki", directory / "server-pki")

        async with server, admin:
            try:
                await guest.connect()
            except Exception as error:
                print("guest refused:", type(error).__name__)
            else:
                raise SystemExit("the guest must not be trusted yet")

            async with asyncio.timeout(10):
                while not (rejected := await call(admin, SERVER_CONFIGURATION, "GetRejectedList")):
                    await asyncio.sleep(0.05)
            print("rejected certificates:", len(rejected))
            await call(
                admin,
                TRUST_LIST,
                "AddCertificate",
                ua.Variant(rejected[0], ua.VariantType.ByteString),
                ua.Variant(True),
            )
            print("the administrator trusted the guest certificate")

            async with guest:
                print(
                    "guest connected, server time:",
                    await guest.get_node(ua.ObjectIds.Server_ServerStatus_CurrentTime).read_value(),
                )
    print("OK 14_certificate_management")


if __name__ == "__main__":
    asyncio.run(main())

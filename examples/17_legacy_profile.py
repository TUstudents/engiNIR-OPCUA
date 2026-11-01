"""
THE LEGACY PROFILE: EVERY POLICY, FOR DEVICES THAT CANNOT DO BETTER. A DECISION OF THE USER, LOGGED AT EVERY START.

Shows: Server.quickstart(profile="legacy") offers the secure policies, their Sign modes, the deprecated Basic256 and
Basic128Rsa15, and None, and relaxes the certificate checks for revocation lists and host names. A legacy client
with security "auto" takes the strongest endpoint the server offers; a second client names a deprecated policy, a
third asks for no security. Nothing is blocked, and each weaker choice is logged as a warning that names the setting
and the risk. Use it to reach old devices, not as a default: 01_secure_pair.py is the profile for everything else.

Run: python examples/17_legacy_profile.py

Spec: OPC 10000-7 v1.05 (security policies and their deprecation); OPC 10000-4 v1.05, 5.6 (SecureChannel service set).
"""

import asyncio
import logging

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server


async def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/legacy/"
        server = Server.quickstart(url, pki=directory / "server-pki", profile="legacy")
        await server.init()
        await pair(directory / "server-pki", directory / "client-pki", "urn:enginir:opcua:legacy-client")
        idx = await server.register_namespace("urn:enginir:example:legacy")
        reading = await server.nodes.objects.add_variable(idx, "Reading", 4.2)

        clients = {
            "auto": Client.quickstart(
                url, pki=directory / "client-pki", profile="legacy", application_uri="urn:enginir:opcua:legacy-client"
            ),
            "deprecated": Client.quickstart(
                url,
                pki=directory / "client-pki",
                profile="legacy",
                application_uri="urn:enginir:opcua:legacy-client",
                security="Basic128Rsa15,SignAndEncrypt",
            ),
            "none": Client.quickstart(url, profile="legacy", pki=None, security="None"),
        }
        async with server:
            for name, client in clients.items():
                async with client:
                    policy = type(client.security_policy).__name__.removeprefix("SecurityPolicy")
                    value = await client.get_node(reading.nodeid).read_value()
                    print(f"{name}: {policy} {client.security_policy.Mode.name}, reading {value}")
    print("OK 17_legacy_profile")


if __name__ == "__main__":
    asyncio.run(main())

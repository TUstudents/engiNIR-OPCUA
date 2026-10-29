"""
THE DEVELOPMENT PROFILE: NO SECURITY, LOOPBACK ONLY. FOR LOCAL EXPERIMENTS, NEVER FOR A PLANT.

This is the only example that uses the security policy None. Messages are neither signed nor encrypted, the
certificates are not checked and a user name travels in clear text, so the profile refuses any address that is not
loopback: Server.quickstart(profile="development") raises ConfigurationError for a host such as 0.0.0.0, and the
server logs a warning when it starts. Everything else about the API is the same as in 01_secure_pair.py, which
needs a PKI directory and trust; here there is nothing to set up, which is the point and the danger.

Run: python examples/15_development_profile.py

Spec: OPC 10000-4 v1.05, 6.1 (security: certificates and validation, which a None channel skips); OPC 10000-7
v1.05 (SecurityPolicy None).
"""

import asyncio

from _common import free_port

from enginir_opcua import Client, Server
from enginir_opcua.ua.uaerrors import ConfigurationError


async def main() -> None:
    try:
        Server.quickstart("opc.tcp://0.0.0.0:4840/dev/", profile="development")
    except ConfigurationError as error:
        print("refused as expected:", error)

    url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/dev/"
    server = Server.quickstart(url, profile="development")
    client = Client.quickstart(url, profile="development")
    await server.init()
    idx = await server.register_namespace("urn:enginir:example:development")
    greeting = await server.nodes.objects.add_variable(idx, "Greeting", "hello, development")
    async with server, client:
        print("read without any security:", await client.get_node(greeting.nodeid).read_value())
    print("OK 15_development_profile")


if __name__ == "__main__":
    asyncio.run(main())

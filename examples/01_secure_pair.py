"""
A secure server and client in one process, with the quick setup.

Shows: Server.quickstart and Client.quickstart with the "secure" profile (Basic256Sha256, SignAndEncrypt), a PKI
directory that is created with a self-signed certificate at runtime, and the one step nobody can skip: each side puts
the other's certificate into its trusted/certs folder. `enginir-opcua pair SERVER_PKI CLIENT_PKI` does the same on the
command line; nothing is ever trusted automatically.

Run: python examples/01_secure_pair.py

Spec: OPC 10000-4 v1.05, 6.1 (application instance certificate and trust), 5.6 (SecureChannel and Session
services); OPC 10000-6 v1.05, 6.2 (security policies).
"""

import asyncio
import shutil
from pathlib import Path

from _common import free_port, workdir

from enginir_opcua import Client, Server
from enginir_opcua.crypto import pki


def trust(own: Path, other: Path) -> None:
    shutil.copy(other / "own" / "certs" / pki.CERTIFICATE_NAME, own / "trusted" / "certs" / f"{other.name}.der")


async def main() -> None:
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki")
        client = Client.quickstart(url, pki=directory / "client-pki")

        await server.init()
        client_pki = directory / "client-pki"
        pki.create_directories(client_pki)
        await pki.load_own_credentials(
            client_pki, application_uri=client.application_uri, host_names=["localhost"], usage=pki.CLIENT_USAGE
        )
        trust(directory / "server-pki", client_pki)
        trust(client_pki, directory / "server-pki")

        idx = await server.register_namespace("urn:enginir:example:secure-pair")
        temperature = await server.nodes.objects.add_variable(idx, "Temperature", 21.5)
        async with server, client:
            endpoint = client.security_policy.URI.rsplit("#", 1)[-1]
            print("secure channel with", endpoint)
            print("temperature:", await client.get_node(temperature.nodeid).read_value())
    print("OK 01_secure_pair")


if __name__ == "__main__":
    asyncio.run(main())

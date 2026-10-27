"""
A server with encryption that creates its own certificate and only accepts clients it trusts.

The server uses a PKI directory, examples/certificates/generated/server-pki. On the first run the folders are
created and a self-signed server certificate and its private key are generated in own/. A client certificate is
only accepted when it is in trusted/certs. A client that is refused leaves its certificate in rejected/certs: run
client-with-encryption.py, move its file from rejected/certs to trusted/certs and restart the server (a running
server picks the file up with server.reload_trust_store()).
"""

import asyncio
import logging
import socket
import sys
from pathlib import Path

sys.path.insert(0, "..")
from enginir_opcua import Server, ua
from enginir_opcua.server.user_managers import CertificateUserManager

logging.basicConfig(level=logging.INFO)


async def main():
    pki = Path(__file__).parent / "certificates" / "generated" / "server-pki"
    client_cert = (
        Path(__file__).parent / "certificates" / "generated" / "client-pki" / "own" / "certs" / "application.der"
    )

    host_name = socket.gethostname()
    server_app_uri = f"myselfsignedserver@{host_name}"

    cert_user_manager = CertificateUserManager()
    if client_cert.exists():
        await cert_user_manager.add_user(client_cert, name="test_user")

    server = Server(user_manager=cert_user_manager)

    await server.init()

    await server.set_application_uri(server_app_uri)
    server.set_endpoint("opc.tcp://0.0.0.0:4840/enginir-opcua/server/")
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await server.set_pki_directory(pki)

    idx = 0

    myobj = await server.nodes.objects.add_object(idx, "MyObject")
    myvar = await myobj.add_variable(idx, "MyVariable", 0.0)
    await myvar.set_writable()

    async with server:
        while True:
            await asyncio.sleep(1)
            current_val = await myvar.get_value()
            count = current_val + 0.1
            await myvar.write_value(count)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

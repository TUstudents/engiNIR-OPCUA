"""
A server with encryption that creates its own certificate and only accepts clients it trusts.

The server certificate and private key are generated in examples/certificates/generated on the first run.
A client certificate is only accepted when it is in examples/certificates/generated/trusted-clients, so run
client-with-encryption.py once to create the client certificate and copy
examples/certificates/generated/client-certificate-example.der into that directory before starting the server.
"""

import asyncio
import logging
import socket
import sys
from pathlib import Path

sys.path.insert(0, "..")
from cryptography.x509.oid import ExtendedKeyUsageOID

from enginir_opcua import Server, ua
from enginir_opcua.crypto.cert_gen import setup_self_signed_certificate
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.server.user_managers import CertificateUserManager

logging.basicConfig(level=logging.INFO)


async def main():
    generated = Path(__file__).parent / "certificates" / "generated"
    server_cert = generated / "server-certificate-example.der"
    server_private_key = generated / "server-private-key-example.pem"
    client_cert = generated / "client-certificate-example.der"
    trusted_clients = generated / "trusted-clients"
    trusted_clients.mkdir(parents=True, exist_ok=True)

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

    await setup_self_signed_certificate(
        server_private_key,
        server_cert,
        server_app_uri,
        host_name,
        [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
        {
            "countryName": "CN",
            "stateOrProvinceName": "AState",
            "localityName": "Foo",
            "organizationName": "Bar Ltd",
        },
    )

    await server.load_certificate(server_cert)
    await server.load_private_key(server_private_key)
    server.set_trust_store(TrustStore([trusted_clients], []))

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

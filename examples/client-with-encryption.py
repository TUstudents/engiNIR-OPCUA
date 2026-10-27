"""
A client with encryption that creates its own certificate and trusts one server certificate explicitly.

The client certificate and private key are generated in examples/certificates/generated on the first run.
The server certificate that server-with-encryption.py generated in the same directory is passed to set_security,
which makes it the one certificate this client trusts. The server only accepts this client after its certificate
was copied into examples/certificates/generated/trusted-clients.
"""

import asyncio
import logging
import socket
import sys
from pathlib import Path

from cryptography.x509.oid import ExtendedKeyUsageOID

sys.path.insert(0, "..")
from enginir_opcua import Client, ua
from enginir_opcua.crypto.cert_gen import setup_self_signed_certificate
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

generated = Path(__file__).parent / "certificates" / "generated"
generated.mkdir(parents=True, exist_ok=True)
cert = generated / "client-certificate-example.der"
private_key = generated / "client-private-key-example.pem"
server_cert = generated / "server-certificate-example.der"


async def task():
    host_name = socket.gethostname()
    client_app_uri = f"urn:{host_name}:foobar:myselfsignedclient"
    url = f"opc.tcp://{host_name}:4840/enginir-opcua/server/"

    await setup_self_signed_certificate(
        private_key,
        cert,
        client_app_uri,
        host_name,
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        {
            "countryName": "CN",
            "stateOrProvinceName": "AState",
            "localityName": "Foo",
            "organizationName": "Bar Ltd",
        },
    )
    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate=str(cert),
        private_key=str(private_key),
        server_certificate=str(server_cert),
    )
    try:
        async with client:
            objects = client.nodes.objects
            child = await objects.get_child(["0:MyObject", "0:MyVariable"])
            print(await child.get_value())
            await child.set_value(42.0)
            print(await child.get_value())
    except ua.UaError as exp:
        _logger.error(exp)


if __name__ == "__main__":
    asyncio.run(task())

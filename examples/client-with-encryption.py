"""
A client with encryption that creates its own certificate and trusts the servers in its PKI directory.

The client uses a PKI directory, examples/certificates/generated/client-pki. On the first run the folders are
created and a self-signed client certificate and its private key are generated in own/. The server certificate
that server-with-encryption.py generated in examples/certificates/generated/server-pki/own/certs has to be copied
into trusted/certs of this directory; a server certificate that is not trusted is kept in rejected/certs. The
server only accepts this client after its certificate was moved to the trusted/certs folder of the server.
"""

import asyncio
import logging
import socket
import sys
from pathlib import Path

sys.path.insert(0, "..")
from enginir_opcua import Client, ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

pki = Path(__file__).parent / "certificates" / "generated" / "client-pki"


async def task():
    host_name = socket.gethostname()
    client_app_uri = f"urn:{host_name}:foobar:myselfsignedclient"
    url = f"opc.tcp://{host_name}:4840/enginir-opcua/server/"

    client = Client(url=url)
    client.application_uri = client_app_uri
    await client.set_pki_directory(pki)
    await client.set_security(SecurityPolicyBasic256Sha256)
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

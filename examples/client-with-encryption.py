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
from enginir_opcua.crypto.truststore import TrustStore

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)

cert_idx = 4
cert_base = Path(__file__).parent
cert = Path(cert_base / f"certificates/peer-certificate-example-{cert_idx}.der")
private_key = Path(cert_base / f"certificates/peer-private-key-example-{cert_idx}.pem")


async def task(loop):
    host_name = socket.gethostname()
    client_app_uri = f"urn:{host_name}:foobar:myselfsignedclient"
    url = "opc.tcp://127.0.0.1:4840/enginir-opcua/server/"

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
        server_certificate="certificate-example.der",
    )

    client.set_trust_store(TrustStore([Path("examples") / "certificates" / "trusted" / "certs"], []))
    try:
        async with client:
            objects = client.nodes.objects
            child = await objects.get_child(["0:MyObject", "0:MyVariable"])
            print(await child.get_value())
            await child.set_value(42)
            print(await child.get_value())
    except ua.UaError as exp:
        _logger.error(exp)


def main():
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(task(loop))
    loop.close()


if __name__ == "__main__":
    main()

import sys

sys.path.insert(0, "..")
import asyncio
import logging
from pathlib import Path

from enginir_opcua import Client
from enginir_opcua.crypto.truststore import TrustStore


async def main():
    client = Client("opc.tcp://localhost:53530/OPCUA/SimulationServer/")
    client.set_trust_store(TrustStore([Path("trusted-server-certificates")], []))
    await client.set_security_string("Basic256Sha256,Sign,my_cert.der,my_private_key.pem")
    client.session_timeout = 2000
    async with client:
        root = client.nodes.root
        objects = client.nodes.objects
        while True:
            print("childs og objects are: ", await objects.get_children())
            await asyncio.sleep(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARN)
    asyncio.run(main())

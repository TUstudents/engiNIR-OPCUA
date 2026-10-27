import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto import security_policies
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.uacrypto import CertProperties

from .conftest import find_free_port
from .pki import (
    BOTH_USAGES,
    CLIENT_APPLICATION_URI,
    SERVER_APPLICATION_URI,
    live_ca,
    live_identity,
    write_trust_directory,
)

_logger = logging.getLogger("enginir_opcua.server.address_space")
_logger.setLevel(logging.WARNING)
pytestmark = pytest.mark.asyncio
uri_crypto = f"opc.tcp://127.0.0.1:{find_free_port()}"


@dataclass
class Chain:
    root: Path
    inter1: Path
    inter2: Path
    client_certificate: Path
    client_key: Path
    server_certificate: Path
    server_key: Path
    trusted: Path


@pytest.fixture(scope="module")
def chain(tmp_path_factory: pytest.TempPathFactory) -> Chain:
    directory = tmp_path_factory.mktemp("chain")
    root = live_ca("Root")
    inter1 = live_ca("Inter 1", issuer=root)
    inter2 = live_ca("Inter 2", issuer=inter1)
    client = live_identity(
        "client", issuer=inter2, uri=CLIENT_APPLICATION_URI, ext_key_usage=BOTH_USAGES, dns_names=("localhost",)
    )
    server = live_identity(
        "server",
        issuer=root,
        uri=SERVER_APPLICATION_URI,
        ext_key_usage=BOTH_USAGES,
        dns_names=("localhost",),
        ip_addresses=("127.0.0.1",),
    )
    client_certificate, client_key = client.write(directory, "client")
    server_certificate, server_key = server.write(directory, "server")
    return Chain(
        root.write(directory, "root")[0],
        inter1.write(directory, "inter1")[0],
        inter2.write(directory, "inter2")[0],
        client_certificate,
        client_key,
        server_certificate,
        server_key,
        write_trust_directory(directory / "trusted", root.certificate),
    )


@pytest.fixture()
async def _server(chain: Chain) -> AsyncIterator[None]:
    srv = Server()
    await srv.init()
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    srv.set_endpoint(uri_crypto)
    await srv.load_certificate(chain.server_certificate)
    await srv.load_private_key(chain.server_key)
    srv.set_trust_store(TrustStore([chain.trusted], []))

    async with srv:
        yield


async def secure_client(chain: Chain, sent_chain: list[Path]) -> Client:
    client = Client(uri_crypto)
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        chain.client_certificate,
        chain.client_key,
        None,
        chain.server_certificate,
        ua.MessageSecurityMode.SignAndEncrypt,
        certificate_chain=sent_chain,
    )
    return client


@pytest.mark.usefixtures("_server")
async def test_cry3_server_builds_the_client_chain_from_the_intermediates_the_client_sent(chain: Chain) -> None:
    """Part 4, 6.1.3 and Part 6, 6.2.6: the intermediates in the OpenSecureChannel header complete the chain."""
    client = await secure_client(chain, [chain.inter2, chain.inter1])
    async with client:
        assert await client.nodes.objects.get_children()


@pytest.mark.usefixtures("_server")
async def test_cry3_server_rejects_the_client_when_the_intermediates_are_missing(chain: Chain) -> None:
    """Part 4, 6.1.3, Table 100: build certificate chain."""
    client = await secure_client(chain, [chain.inter2])
    with pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
        await client.connect()
    client.uaclient.disconnect_socket()


@pytest.mark.usefixtures("_server")
async def test_client_user_cert_with_chain(chain: Chain) -> None:
    """Including the intermediate certificates in the user chain does not break the server."""
    client = await secure_client(chain, [chain.inter2, chain.inter1])
    await client.load_client_certificate(str(chain.client_certificate))
    await client.load_private_key(chain.client_key)
    await client.load_client_chain([CertProperties(chain.inter2), CertProperties(chain.inter1)])

    async with client:
        assert await client.nodes.objects.get_children()

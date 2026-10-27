import logging
import shutil
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.validator import CertificateValidator, Outcome, ValidationContext

from .conftest import find_free_port
from .pki import Peer, generated_pki, live_identity, write_trust_directory

PKI = generated_pki()
SECURE = ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt


class CountingValidator(CertificateValidator):
    def __init__(self, trust_store: TrustStore) -> None:
        super().__init__(trust_store)
        self.contexts: list[ValidationContext] = []

    def validate_application_certificate(self, chain: bytes, context: ValidationContext) -> Outcome:
        self.contexts.append(context)
        return super().validate_application_certificate(chain, context)


def trust_directory(directory: Path, *peers: Peer) -> TrustStore:
    write_trust_directory(directory)
    for peer in peers:
        shutil.copy(peer.certificate, directory / peer.certificate.name)
    return TrustStore([directory], [])


@asynccontextmanager
async def running_server(
    trust_store: TrustStore | None = None,
    server_peer: Peer = PKI.server,
    policies: tuple[ua.SecurityPolicyType, ...] = (SECURE,),
) -> AsyncIterator[Server]:
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    server.set_security_policy(list(policies))
    await server.load_certificate(server_peer.certificate)
    await server.load_private_key(server_peer.key)
    if trust_store is not None:
        server.set_trust_store(trust_store)
    async with server:
        yield server


async def secure_client(
    server: Server, peer: Peer = PKI.peer1, server_peer: Peer | None = None, trust_store: TrustStore | None = None
) -> Client:
    client = Client(server.endpoint.geturl(), timeout=3)
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        peer.certificate,
        peer.key,
        peer.password,
        server_peer.certificate if server_peer else None,
        ua.MessageSecurityMode.SignAndEncrypt,
    )
    if trust_store is not None:
        client.set_trust_store(trust_store)
    return client


async def test_srv3_trusted_client_certificate_connects(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a client certificate in the trusted list opens the channel."""
    async with running_server(trust_directory(tmp_path / "trusted", PKI.peer1)) as server:
        client = await secure_client(server, server_peer=PKI.server)
        async with client:
            assert await client.nodes.objects.get_children()


async def test_srv3_untrusted_client_gets_only_security_checks_failed_and_the_log_has_the_detail(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 4, 6.1.3 and Part 6, 6.7.7: the peer learns nothing about which check failed."""
    async with running_server(trust_directory(tmp_path / "trusted", PKI.peer2)) as server:
        client = await secure_client(server, PKI.peer1, PKI.server)
        with caplog.at_level(logging.WARNING), pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
            await client.connect()
    assert "BadCertificateUntrusted" in caplog.text


async def test_cry1_server_without_a_trust_store_trusts_no_client(caplog: pytest.LogCaptureFixture) -> None:
    """Part 4, 6.1.3: with no trusted certificates configured, nothing is trusted."""
    async with running_server() as server:
        client = await secure_client(server, server_peer=PKI.server)
        with caplog.at_level(logging.WARNING), pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
            await client.connect()
    assert "set_trust_store" in caplog.text


async def test_srv3_validator_runs_once_per_open_and_renew_on_the_server(tmp_path: Path) -> None:
    """Part 4, 6.1.3 and 6.1.7: the certificate is validated at every OpenSecureChannel, renewals included."""
    store = trust_directory(tmp_path / "trusted", PKI.peer1)
    async with running_server(store) as server:
        counting = CountingValidator(store)
        server.set_certificate_validator(counting)
        client = await secure_client(server, server_peer=PKI.server)
        async with client:
            assert len(counting.contexts) == 1
            await client.open_secure_channel(renew=True)
            assert len(counting.contexts) == 2
            assert await client.nodes.objects.get_children()
        assert {context.policy_uri for context in counting.contexts} == {SecurityPolicyBasic256Sha256.URI}


async def test_srv3_renew_closes_the_channel_when_the_client_is_no_longer_trusted(tmp_path: Path) -> None:
    """Part 4, 6.1.7: a certificate that stopped being trusted is refused at the next renewal."""
    directory = tmp_path / "trusted"
    store = trust_directory(directory, PKI.peer1)
    async with running_server(store) as server:
        client = await secure_client(server, server_peer=PKI.server)
        async with client:
            (directory / PKI.peer1.certificate.name).unlink()
            await store.load()
            with pytest.raises(ua.UaError):
                await client.open_secure_channel(renew=True)
        client.uaclient.disconnect_socket()


async def test_policy_none_channel_does_not_call_the_validator(tmp_path: Path) -> None:
    """Part 4, 5.7.2.2: with SecurityPolicy None no certificate is validated."""
    store = trust_directory(tmp_path / "trusted", PKI.peer1)
    async with running_server(store, policies=(ua.SecurityPolicyType.NoSecurity, SECURE)) as server:
        counting = CountingValidator(store)
        server.set_certificate_validator(counting)
        async with Client(server.endpoint.geturl()) as client:
            assert await client.nodes.objects.get_children()
        assert counting.contexts == []


async def test_srv29_create_session_uri_mismatch_is_bad_certificate_uri_invalid(tmp_path: Path) -> None:
    """Part 4, 5.7.2: the ApplicationUri of the ClientDescription has to be in the client certificate."""
    async with running_server(trust_directory(tmp_path / "trusted", PKI.peer1)) as server:
        client = await secure_client(server, server_peer=PKI.server)
        client.application_uri = "urn:somebody:else"
        with pytest.raises(ua.uaerrors.BadCertificateUriInvalid):
            await client.connect()
        client.uaclient.disconnect_socket()


async def test_cli21_client_rejects_an_untrusted_server_certificate_and_names_the_setting(tmp_path: Path) -> None:
    """Part 4, 6.1.3: the client validates the server certificate; with nothing trusted the connection fails."""
    server_store = trust_directory(tmp_path / "server-trusted", PKI.peer1)
    async with running_server(server_store, policies=(ua.SecurityPolicyType.NoSecurity, SECURE)) as server:
        client = await secure_client(server)
        with pytest.raises(ua.uaerrors.BadCertificateUntrusted, match="set_trust_store"):
            await client.connect()
        client.uaclient.disconnect_socket()


async def test_cli21_client_trusts_the_server_certificate_through_its_trust_store(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a server certificate in the client's trusted list is accepted."""
    server_store = trust_directory(tmp_path / "server-trusted", PKI.peer1)
    client_store = trust_directory(tmp_path / "client-trusted", PKI.server)
    async with running_server(server_store, policies=(ua.SecurityPolicyType.NoSecurity, SECURE)) as server:
        client = await secure_client(server, trust_store=client_store)
        async with client:
            assert await client.nodes.objects.get_children()


async def test_cli21_client_validates_the_server_certificate_at_open_and_renew(tmp_path: Path) -> None:
    """Part 4, 6.1.3 and 6.1.7: the server certificate is validated at every OpenSecureChannel response."""
    server_store = trust_directory(tmp_path / "server-trusted", PKI.peer1)
    async with running_server(server_store) as server:
        client = await secure_client(server, server_peer=PKI.server)
        counting = CountingValidator(trust_directory(tmp_path / "client-trusted", PKI.server))
        await counting.trust_store.load()
        client.certificate_validator = counting
        async with client:
            assert len(counting.contexts) == 1
            await client.open_secure_channel(renew=True)
            assert len(counting.contexts) == 2
        assert {context.host_name for context in counting.contexts} == {"127.0.0.1"}


async def test_cli21_client_checks_the_host_name_of_the_server_certificate(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: the host of the URL has to be in the server certificate."""
    elsewhere = live_identity("elsewhere", uri="urn:enginir:opcua:server", dns_names=("plc.example.org",))
    certificate, key = elsewhere.write(tmp_path / "elsewhere", "server")
    server_peer = Peer(elsewhere, certificate, key)
    client_store = TrustStore([write_trust_directory(tmp_path / "client-trusted", elsewhere.certificate)], [])
    async with running_server(trust_directory(tmp_path / "trusted", PKI.peer1), server_peer) as server:
        client = await secure_client(server, trust_store=client_store, server_peer=server_peer)
        with pytest.raises(ua.uaerrors.BadCertificateHostNameInvalid):
            await client.connect()
        client.uaclient.disconnect_socket()


async def test_cli21_pinned_server_certificate_is_trusted_without_a_trust_store(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a server certificate passed explicitly to set_security is the one that is trusted."""
    async with running_server(trust_directory(tmp_path / "trusted", PKI.peer1)) as server:
        client = await secure_client(server, server_peer=PKI.server)
        async with client:
            assert await client.nodes.objects.get_children()


async def test_cli21_pinned_server_certificate_is_not_trusted_for_another_server(tmp_path: Path) -> None:
    """Part 4, 6.1.3: the pin names one certificate, so a server with another certificate is refused."""
    async with running_server(trust_directory(tmp_path / "trusted", PKI.peer1), PKI.server) as server:
        client = await secure_client(server, server_peer=PKI.server_3072)
        with pytest.raises(ua.UaError):
            await client.connect()
        client.uaclient.disconnect_socket()

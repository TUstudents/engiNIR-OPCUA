"""test certificate truststore"""

import datetime
import hashlib
import ipaddress
import logging
import os
import shutil
import stat
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto import pki
from enginir_opcua.crypto.file_journal import FileJournal
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.crypto.truststore import (
    MASK_ALL,
    MASK_TRUSTED_CERTIFICATES,
    TrustLists,
    TrustStore,
)
from enginir_opcua.crypto.validator import CertificateValidator, Outcome, PeerRole, ValidationContext
from enginir_opcua.sync import Client as SyncClient
from enginir_opcua.sync import Server as SyncServer
from enginir_opcua.ua.uaerrors import ConfigurationError
from tests.conftest import find_free_port
from tests.pki import (
    APPLICATION_URI,
    NOW,
    Identity,
    Peer,
    fresh_key,
    generated_pki,
    live_ca,
    live_identity,
    make_ca,
    make_crl,
    make_identity,
    write_crl_directory,
    write_pki_layout,
    write_trust_directory,
)
from tests.waiting import wait_until

CONTEXT = ValidationContext(PeerRole.CLIENT, SecurityPolicyBasic256Sha256.URI)


def validator_for(store: TrustStore, when: datetime.datetime = NOW) -> CertificateValidator:
    return CertificateValidator(store, clock=lambda: when)


async def test_selfsigned_not_in_trust_store(tmp_path: Path) -> None:
    peer = make_identity()
    store = TrustStore([write_trust_directory(tmp_path / "trusted")], [])
    await store.load()
    outcome = validator_for(store).validate_application_certificate(peer.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateUntrusted


async def test_selfsigned_in_trust_store(tmp_path: Path) -> None:
    peer = make_identity()
    store = TrustStore([write_trust_directory(tmp_path / "trusted", peer.certificate)], [])
    await store.load()
    assert validator_for(store).validate_application_certificate(peer.der, CONTEXT).accepted


@pytest.mark.parametrize("trusted", [False, True], ids=["ca_not_in_trust_store", "ca_in_trust_store"])
async def test_ca_in_trust_store(tmp_path: Path, trusted: bool) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore([write_trust_directory(tmp_path / "trusted", *([ca.certificate] if trusted else []))], [])
    await store.load()
    assert validator_for(store).validate_application_certificate(leaf.der, CONTEXT).accepted is trusted


@pytest.mark.parametrize("days", [20 * 365, -20 * 365], ids=["cert_expired", "cert_not_yet_valid"])
async def test_cert_outside_its_validity_period(tmp_path: Path, days: int) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore([write_trust_directory(tmp_path / "trusted", ca.certificate)], [])
    await store.load()
    outcome = validator_for(store, NOW + datetime.timedelta(days=days)).validate_application_certificate(
        leaf.der, CONTEXT
    )
    assert outcome.status == ua.StatusCodes.BadCertificateTimeInvalid


async def test_empty_crl(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore(
        [write_trust_directory(tmp_path / "trusted", ca.certificate)],
        [write_crl_directory(tmp_path / "crl", make_crl(ca))],
    )
    await store.load()
    assert validator_for(store).validate_application_certificate(leaf.der, CONTEXT).accepted


async def test_cert_in_crl(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore(
        [write_trust_directory(tmp_path / "trusted", ca.certificate)],
        [write_crl_directory(tmp_path / "crl", make_crl(ca, revoked=(leaf.certificate.serial_number,)))],
    )
    await store.load()
    outcome = validator_for(store).validate_application_certificate(leaf.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateRevoked


async def test_cry_empty_trust_location_loads_and_trusts_nothing(tmp_path: Path) -> None:
    """Part 4, 6.1.3: with an empty list of trusted certificates, no certificate is trusted."""
    peer = make_identity()
    store = TrustStore([tmp_path], [])
    await store.load()
    assert not validator_for(store).validate_application_certificate(peer.der, CONTEXT).accepted


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


async def test_srv3_cli21_trusted_client_certificate_connects_with_a_pinned_server_certificate(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a client certificate in the trusted list opens the channel, and a server certificate passed
    explicitly to set_security is the one that is trusted."""
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


async def test_cli21_pinned_server_certificate_is_not_trusted_for_another_server(tmp_path: Path) -> None:
    """Part 4, 6.1.3: the pin names one certificate, so a server with another certificate is refused."""
    async with running_server(trust_directory(tmp_path / "trusted", PKI.peer1), PKI.server) as server:
        client = await secure_client(server, server_peer=PKI.server_3072)
        with pytest.raises(ua.UaError):
            await client.connect()
        client.uaclient.disconnect_socket()


async def test_pki_store_reads_trusted_and_issuer_folders(tmp_path: Path) -> None:
    anchor = make_identity("anchor")
    ca = make_ca()
    root = write_pki_layout(tmp_path, trusted=(anchor.certificate,), issuers=(ca.certificate,))
    store = TrustStore.from_pki_directory(root)
    await store.load()
    assert store.snapshot.trusted == (anchor.certificate,)
    assert store.snapshot.issuers == (ca.certificate,)


async def test_pki_store_accepts_leaf_of_issuer_ca_only_with_trusted_anchor(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    root = write_pki_layout(tmp_path, issuers=(ca.certificate,))
    store = TrustStore.from_pki_directory(root)
    await store.load()
    assert validator_for(store).validate_application_certificate(leaf.der, CONTEXT).status == (
        ua.StatusCodes.BadCertificateUntrusted
    )


async def test_pki_store_without_trusted_folder_is_a_configuration_error(tmp_path: Path) -> None:
    store = TrustStore.from_pki_directory(tmp_path)
    with pytest.raises(ConfigurationError):
        await store.load()


async def test_pki_store_without_crl_lists_does_not_check_revocation(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    root = write_pki_layout(tmp_path, trusted=(ca.certificate,))
    store = TrustStore.from_pki_directory(root)
    await store.load()
    assert validator_for(store).validate_application_certificate(leaf.der, CONTEXT).accepted


async def test_pki_trusted_crl_folder_revokes_certificate_of_trusted_ca(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    crl = make_crl(ca, revoked=(leaf.certificate.serial_number,))
    root = write_pki_layout(tmp_path, trusted=(ca.certificate,), trusted_crls=(crl,))
    store = TrustStore.from_pki_directory(root)
    await store.load()
    outcome = validator_for(store).validate_application_certificate(leaf.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateRevoked


async def test_pki_issuer_crl_folder_revokes_certificate_of_issuer_ca(tmp_path: Path) -> None:
    root_ca = make_ca("Root")
    ca = make_ca("Intermediate", issuer=root_ca)
    leaf = make_identity(issuer=ca)
    crl_root = make_crl(root_ca)
    crl_ca = make_crl(ca, revoked=(leaf.certificate.serial_number,))
    root = write_pki_layout(
        tmp_path,
        trusted=(root_ca.certificate,),
        issuers=(ca.certificate,),
        trusted_crls=(crl_root,),
        issuer_crls=(crl_ca,),
    )
    store = TrustStore.from_pki_directory(root)
    await store.load()
    outcome = validator_for(store).validate_application_certificate(leaf.der + ca.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateRevoked


async def test_pki_crl_in_the_wrong_folder_does_not_apply(tmp_path: Path) -> None:
    root_ca = make_ca("Root")
    ca = make_ca("Intermediate", issuer=root_ca)
    leaf = make_identity(issuer=ca)
    crl_root = make_crl(root_ca)
    crl_ca = make_crl(ca, revoked=(leaf.certificate.serial_number,))
    root = write_pki_layout(
        tmp_path,
        trusted=(root_ca.certificate,),
        issuers=(ca.certificate,),
        trusted_crls=(crl_root, crl_ca),
    )
    store = TrustStore.from_pki_directory(root)
    await store.load()
    outcome = validator_for(store).validate_application_certificate(leaf.der + ca.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateRevocationUnknown


async def test_pki_crl_is_matched_to_its_issuer_by_signature(tmp_path: Path) -> None:
    ca = make_ca()
    impostor = make_ca()
    leaf = make_identity(issuer=ca)
    forged = make_crl(ca, revoked=(), signer=impostor)
    root = write_pki_layout(tmp_path, trusted=(ca.certificate,), trusted_crls=(forged,))
    store = TrustStore.from_pki_directory(root)
    await store.load()
    outcome = validator_for(store).validate_application_certificate(leaf.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateRevocationUnknown


async def test_pki_client_keeps_the_crl_folders_of_the_store(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    crl = make_crl(ca, revoked=(leaf.certificate.serial_number,))
    root = write_pki_layout(tmp_path, trusted=(ca.certificate,), trusted_crls=(crl,))
    client = Client("opc.tcp://127.0.0.1:1")
    client.set_trust_store(TrustStore.from_pki_directory(root))
    await client._prepare_certificate_validation()
    assert client._default_validator is not None
    assert client._default_validator.revocation_active


def rejected_files(root: Path) -> list[Path]:
    return sorted((root / "rejected" / "certs").glob("*.der"))


def entry_names(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir())


def thumbprint_name(der: bytes) -> str:
    return f"{hashlib.sha1(der, usedforsecurity=False).hexdigest()}.der"


async def pki_validator(root: Path, **options: object) -> CertificateValidator:
    store = TrustStore.from_pki_directory(root, **options)  # type: ignore[arg-type]
    await store.load()
    return validator_for(store)


def validate_and_keep(validator: CertificateValidator, chain: bytes, peer: str | None = None) -> Outcome:
    outcome = validator.validate_application_certificate(chain, CONTEXT)
    validator.keep_rejected(outcome, peer)
    return outcome


async def test_r25_rejected_leaf_and_chain_are_written_by_thumbprint(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    validator = await pki_validator(write_pki_layout(tmp_path))
    outcome = validate_and_keep(validator, leaf.der + ca.der)
    assert outcome.status == ua.StatusCodes.BadCertificateUntrusted
    names = [path.name for path in rejected_files(tmp_path)]
    assert names == sorted([thumbprint_name(leaf.der), thumbprint_name(ca.der)])
    assert (tmp_path / "rejected" / "certs" / thumbprint_name(leaf.der)).read_bytes() == leaf.der


async def test_r25_accepted_certificate_is_not_written(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path, trusted=(peer.certificate,)))
    assert validate_and_keep(validator, peer.der).accepted
    assert rejected_files(tmp_path) == []


async def test_r25_certificate_is_written_once_per_thumbprint(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path))
    validate_and_keep(validator, peer.der)
    (written,) = rejected_files(tmp_path)
    written.write_bytes(b"marker")
    validate_and_keep(validator, peer.der)
    assert written.read_bytes() == b"marker"
    assert len(rejected_files(tmp_path)) == 1


async def test_r25_store_is_bounded_and_the_oldest_file_goes_first(tmp_path: Path) -> None:
    validator = await pki_validator(write_pki_layout(tmp_path), max_rejected=3)
    peers = [make_identity(f"peer{index}") for index in range(5)]
    for index, peer in enumerate(peers):
        validate_and_keep(validator, peer.der)
        for path in rejected_files(tmp_path):
            if path.name == thumbprint_name(peer.der):
                os.utime(path, (1_000_000 + index, 1_000_000 + index))
    assert [path.name for path in rejected_files(tmp_path)] == sorted(thumbprint_name(p.der) for p in peers[2:])


async def test_r25_nothing_is_written_without_a_rejected_folder(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path, rejected=False))
    assert not validate_and_keep(validator, peer.der).accepted
    assert not (tmp_path / "rejected").exists()


async def test_r25_explicit_locations_have_no_rejected_store(tmp_path: Path) -> None:
    peer = make_identity()
    store = TrustStore([write_trust_directory(tmp_path / "trusted")], [])
    await store.load()
    assert not validator_for(store).validate_application_certificate(peer.der, CONTEXT).accepted
    assert entry_names(tmp_path) == ["trusted"]


async def test_r25_unparsable_data_is_not_written(tmp_path: Path) -> None:
    validator = await pki_validator(write_pki_layout(tmp_path))
    outcome = validate_and_keep(validator, b"\x30\x03\x02\x01\x00")
    assert outcome.status == ua.StatusCodes.BadCertificateInvalid
    assert rejected_files(tmp_path) == []


async def test_r25_write_error_does_not_change_the_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fail(path: Path, data: bytes, mode: int) -> None:
        raise PermissionError("denied")

    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path))
    monkeypatch.setattr("enginir_opcua.crypto.truststore.write_atomic", fail)
    outcome = validate_and_keep(validator, peer.der)
    assert outcome.status == ua.StatusCodes.BadCertificateUntrusted
    assert "denied" in caplog.text


async def test_r25_rejected_certificates_are_never_trusted(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path))
    validate_and_keep(validator, peer.der)
    await validator.trust_store.load()
    assert validator.trust_store.snapshot.trusted == ()
    assert not validate_and_keep(validator, peer.der).accepted


async def test_r25_moving_the_file_to_trusted_certs_trusts_it_after_reload(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path))
    validate_and_keep(validator, peer.der)
    (written,) = rejected_files(tmp_path)
    written.rename(tmp_path / "trusted" / "certs" / written.name)
    await validator.trust_store.load()
    assert validate_and_keep(validator, peer.der).accepted


async def test_cry18_the_validator_alone_writes_nothing_and_only_valid_but_untrusted_certificates_are_kept(
    tmp_path: Path,
) -> None:
    valid = make_identity("valid")
    expired = make_identity(
        "expired", not_before=NOW - datetime.timedelta(days=10), not_after=NOW - datetime.timedelta(days=1)
    )
    validator = await pki_validator(write_pki_layout(tmp_path))
    outcome = validator.validate_application_certificate(valid.der, CONTEXT)
    assert outcome.untrusted_chain == (valid.der,)
    assert rejected_files(tmp_path) == []
    stale = validator.validate_application_certificate(expired.der, CONTEXT)
    assert stale.untrusted_chain == ()
    validator.keep_rejected(stale)
    assert rejected_files(tmp_path) == []
    validator.keep_rejected(outcome)
    assert [path.name for path in rejected_files(tmp_path)] == [thumbprint_name(valid.der)]


async def test_cry18_one_peer_cannot_evict_the_certificates_of_another(tmp_path: Path) -> None:
    store = TrustStore.from_pki_directory(write_pki_layout(tmp_path), max_rejected=4, max_rejected_per_peer=2)
    await store.load()
    honest = [make_identity(f"honest{index}") for index in range(2)]
    for identity in honest:
        store.record_rejected([identity.der], "10.0.0.1")
    for index in range(10):
        store.record_rejected([make_identity(f"flood{index}").der], "10.0.0.2")
    kept = {path.name for path in rejected_files(tmp_path)}
    assert {thumbprint_name(identity.der) for identity in honest} <= kept
    assert len(kept) == 4


async def test_cry18_the_total_bound_removes_from_the_peer_with_the_most_files(tmp_path: Path) -> None:
    store = TrustStore.from_pki_directory(write_pki_layout(tmp_path), max_rejected=3, max_rejected_per_peer=3)
    await store.load()
    single = make_identity("single")
    store.record_rejected([single.der], "10.0.0.1")
    for index in range(4):
        store.record_rejected([make_identity(f"many{index}").der], "10.0.0.2")
    names = {path.name for path in rejected_files(tmp_path)}
    assert thumbprint_name(single.der) in names
    assert len(names) == 3


async def test_r25_server_keeps_the_certificate_of_a_refused_client(tmp_path: Path) -> None:
    pki = generated_pki()
    root = write_pki_layout(tmp_path)
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await server.load_certificate(pki.server.certificate)
    await server.load_private_key(pki.server.key)
    server.set_trust_store(TrustStore.from_pki_directory(root))
    async with server:
        client = Client(server.endpoint.geturl(), timeout=3)
        await client.set_security(
            SecurityPolicyBasic256Sha256, pki.peer1.certificate, pki.peer1.key, None, pki.server.certificate
        )
        with pytest.raises(ua.UaError):
            await client.connect()
    await wait_until(lambda: bool(rejected_files(root)))
    assert [path.name for path in rejected_files(root)] == [thumbprint_name(pki.peer1.identity.der)]
    store = server.iserver.trust_store
    assert store is not None
    assert set(store._rejected_peers.values()) == {"127.0.0.1"}


async def test_r25_client_keeps_the_certificate_of_a_refused_server(tmp_path: Path) -> None:
    pki = generated_pki()
    root = write_pki_layout(tmp_path)
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await server.load_certificate(pki.server.certificate)
    await server.load_private_key(pki.server.key)
    server.set_trust_store(pki.trust_store())
    async with server:
        client = Client(server.endpoint.geturl(), timeout=3)
        client.set_trust_store(TrustStore.from_pki_directory(root))
        await client.set_security(SecurityPolicyBasic256Sha256, pki.peer1.certificate, pki.peer1.key)
        with pytest.raises(ua.UaError):
            await client.connect()
    await wait_until(lambda: bool(rejected_files(root)))
    assert [path.name for path in rejected_files(root)] == [thumbprint_name(pki.server.identity.der)]


def posix_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


async def prepared_server(root: Path, port: int | None = None, **options: object) -> Server:
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port or find_free_port()}")
    server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await server.set_pki_directory(root, **options)  # type: ignore[arg-type]
    return server


async def test_pki_server_creates_the_folders_and_a_certificate_on_first_start(tmp_path: Path) -> None:
    root = tmp_path / "pki"
    server = await prepared_server(root)
    for folder in ("own/certs", "own/private", "trusted/certs", "trusted/crl", "issuer/certs", "issuer/crl"):
        assert (root / folder).is_dir()
    assert (root / "rejected" / "certs").is_dir()
    certificate = server.iserver.certificate
    assert certificate is not None and server.iserver.private_key is not None
    assert (
        certificate.public_bytes(serialization.Encoding.DER)
        == (root / "own" / "certs" / "application.der").read_bytes()
    )
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is False
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert server.get_application_uri() in names.get_values_for_type(x509.UniformResourceIdentifier)
    assert "localhost" in names.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("127.0.0.1") in names.get_values_for_type(x509.IPAddress)
    assert server.iserver.trust_store is not None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
async def test_pki_generated_key_and_folders_are_private(tmp_path: Path) -> None:
    root = tmp_path / "pki"
    await prepared_server(root)
    assert posix_mode(root / "own" / "private") == 0o700
    assert posix_mode(root / "own" / "private" / "application.pem") == 0o600


async def test_pki_existing_certificate_is_never_replaced(tmp_path: Path) -> None:
    root = tmp_path / "pki"
    await prepared_server(root)
    certificate = (root / "own" / "certs" / "application.der").read_bytes()
    key = (root / "own" / "private" / "application.pem").read_bytes()
    server = await prepared_server(root)
    assert (root / "own" / "certs" / "application.der").read_bytes() == certificate
    assert (root / "own" / "private" / "application.pem").read_bytes() == key
    assert server.iserver.certificate is not None
    assert server.iserver.certificate.public_bytes(serialization.Encoding.DER) == certificate


async def test_pki_existing_certificate_with_its_chain_is_loaded(tmp_path: Path) -> None:
    root_ca = live_ca("Root")
    ca = live_ca("Intermediate", issuer=root_ca)
    own = live_identity("own", issuer=ca, key=fresh_key(), uri="urn:enginir:opcua:server")
    (tmp_path / "own" / "certs").mkdir(parents=True)
    (tmp_path / "own" / "private").mkdir(parents=True)
    (tmp_path / "own" / "certs" / "own.der").write_bytes(own.der)
    (tmp_path / "own" / "certs" / "ca.der").write_bytes(ca.der)
    (tmp_path / "own" / "certs" / "root.der").write_bytes(root_ca.der)
    (tmp_path / "own" / "private" / "own.pem").write_bytes(own.key_pem)
    server = await prepared_server(tmp_path)
    assert server.iserver.certificate == own.certificate
    assert server.iserver.certificate_chain == [ca.certificate]


async def test_pki_without_create_a_missing_certificate_is_an_error(tmp_path: Path) -> None:
    root = tmp_path / "pki"
    (root / "trusted" / "certs").mkdir(parents=True)
    server = Server()
    await server.init()
    with pytest.raises(ConfigurationError):
        await server.set_pki_directory(root, create=False)
    assert not (root / "own").exists()


async def test_pki_certificate_without_its_key_is_an_error(tmp_path: Path) -> None:
    peer = live_identity()
    (tmp_path / "own" / "certs").mkdir(parents=True)
    (tmp_path / "own" / "certs" / "own.der").write_bytes(peer.der)
    server = Server()
    await server.init()
    with pytest.raises(ConfigurationError):
        await server.set_pki_directory(tmp_path)


async def test_pki_key_that_matches_no_certificate_is_an_error(tmp_path: Path) -> None:
    peer, other = live_identity(), live_identity(key=fresh_key())
    (tmp_path / "own" / "certs").mkdir(parents=True)
    (tmp_path / "own" / "private").mkdir(parents=True)
    (tmp_path / "own" / "certs" / "own.der").write_bytes(peer.der)
    (tmp_path / "own" / "private" / "own.pem").write_bytes(other.key_pem)
    server = Server()
    await server.init()
    with pytest.raises(ConfigurationError):
        await server.set_pki_directory(tmp_path)


async def test_pki_client_without_directory_needs_explicit_certificate() -> None:
    client = Client("opc.tcp://127.0.0.1:1")
    with pytest.raises(ConfigurationError):
        await client.set_security(SecurityPolicyBasic256Sha256)


async def test_pki_server_and_client_connect_after_trusting_each_other(tmp_path: Path) -> None:
    server = await prepared_server(tmp_path / "server")
    client = Client(server.endpoint.geturl(), timeout=3)
    await client.set_pki_directory(tmp_path / "client")
    shutil.copy(tmp_path / "client" / "own" / "certs" / "application.der", tmp_path / "server" / "trusted" / "certs")
    shutil.copy(tmp_path / "server" / "own" / "certs" / "application.der", tmp_path / "client" / "trusted" / "certs")
    async with server:
        await client.set_security(SecurityPolicyBasic256Sha256)
        async with client:
            assert await client.nodes.objects.get_children()


async def test_pki_moving_a_rejected_certificate_and_reloading_trusts_it(tmp_path: Path) -> None:
    server = await prepared_server(tmp_path / "server")
    client = Client(server.endpoint.geturl(), timeout=3)
    await client.set_pki_directory(tmp_path / "client")
    shutil.copy(tmp_path / "server" / "own" / "certs" / "application.der", tmp_path / "client" / "trusted" / "certs")
    async with server:
        await client.set_security(SecurityPolicyBasic256Sha256)
        with pytest.raises(ua.UaError):
            await client.connect()
        await wait_until(lambda: bool(rejected_files(tmp_path / "server")))
        (rejected,) = rejected_files(tmp_path / "server")
        rejected.rename(tmp_path / "server" / "trusted" / "certs" / rejected.name)
        await server.reload_trust_store()
        async with client:
            assert await client.nodes.objects.get_children()


def test_pki_sync_server_and_client_have_the_directory_methods(tmp_path: Path) -> None:
    server = SyncServer()
    client = SyncClient("opc.tcp://127.0.0.1:1", tloop=server.tloop)
    try:
        server.set_pki_directory(tmp_path / "server")
        client.set_pki_directory(tmp_path / "client")
        server.reload_trust_store()
    finally:
        server.tloop.stop()
    assert (tmp_path / "server" / "own" / "certs" / "application.der").is_file()
    assert (tmp_path / "client" / "own" / "certs" / "application.der").is_file()


def put_certificate(root: Path, name: str, identity: Identity) -> None:
    (root / "own" / "certs").mkdir(parents=True, exist_ok=True)
    (root / "own" / "certs" / f"{name}.der").write_bytes(identity.der)


def put_key(root: Path, name: str, identity: Identity) -> None:
    (root / "own" / "private").mkdir(parents=True, exist_ok=True)
    (root / "own" / "private" / f"{name}.pem").write_bytes(identity.key_pem)


async def test_cry21_the_newest_certificate_with_a_key_wins_over_file_order(tmp_path: Path) -> None:
    old = make_identity("old", not_before=NOW - datetime.timedelta(days=60), not_after=NOW + datetime.timedelta(days=1))
    new = make_identity("new", not_before=NOW - datetime.timedelta(days=1))
    root = tmp_path
    put_certificate(root, "a_old", old)
    put_key(root, "a_old", old)
    put_certificate(root, "z_new", new)
    put_key(root, "z_new", new)
    credentials = await pki.load_own_credentials(
        root, application_uri=APPLICATION_URI, host_names=[], usage=pki.SERVER_USAGE, create=False
    )
    assert credentials.certificate == new.certificate
    assert credentials.private_key.public_key() == new.key.public_key()


async def test_cry21_a_key_without_a_certificate_is_ignored_when_another_key_matches(tmp_path: Path) -> None:
    root = tmp_path
    identity = make_identity("only")
    put_certificate(root, "only", identity)
    put_key(root, "z_only", identity)
    fresh_key_pem = make_identity("stray").key_pem
    (root / "own" / "private" / "a_stray.pem").write_bytes(fresh_key_pem)
    credentials = await pki.load_own_credentials(
        root, application_uri=APPLICATION_URI, host_names=[], usage=pki.SERVER_USAGE, create=False
    )
    assert credentials.certificate == identity.certificate


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
async def test_pending_keys_are_private_replaced_and_discarded(tmp_path: Path) -> None:
    first, second = fresh_key(), fresh_key()
    pki.save_pending_key(tmp_path, "group one/type", first)
    pending = tmp_path / "own" / "pending"
    assert stat.S_IMODE(pending.stat().st_mode) == 0o700
    (written,) = list(pending.iterdir())
    assert written.name == "group_one_type.pem"
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    pki.save_pending_key(tmp_path, "group one/type", second)
    loaded = pki.load_pending_key(tmp_path, "group one/type")
    assert loaded is not None and loaded.public_key() == second.public_key()
    pki.discard_pending_key(tmp_path, "group one/type")
    assert pki.load_pending_key(tmp_path, "group one/type") is None


async def test_write_own_credentials_replaces_the_pair_and_a_rollback_restores_it(tmp_path: Path) -> None:
    old = make_identity("old")
    root = tmp_path
    put_certificate(root, "application", old)
    put_key(root, "application", old)
    extra = make_identity("extra-old")
    put_certificate(root, "spare", extra)
    put_key(root, "spare", extra)
    new = make_identity("new")
    journal = FileJournal()
    pki.write_own_credentials(root, new.certificate, [], new.key, extra.certificate, journal)
    credentials = await pki.load_own_credentials(
        root, application_uri=APPLICATION_URI, host_names=[], usage=pki.SERVER_USAGE, create=False
    )
    assert credentials.certificate == new.certificate
    assert not (root / "own" / "certs" / "spare.der").exists()
    assert not (root / "own" / "private" / "spare.pem").exists()
    journal.rollback()
    restored = await pki.load_own_credentials(
        root, application_uri=APPLICATION_URI, host_names=[], usage=pki.SERVER_USAGE, create=False
    )
    assert restored.certificate in (old.certificate, extra.certificate)
    assert (root / "own" / "certs" / "spare.der").exists()
    assert (root / "own" / "certs" / "application.der").read_bytes() == old.der


async def test_trust_store_generation_counts_loads_and_lists_are_read_back(tmp_path: Path) -> None:
    ca = make_ca()
    peer = make_identity("peer")
    crl = make_crl(ca)
    store = TrustStore.from_pki_directory(
        write_pki_layout(tmp_path, trusted=(peer.certificate,), issuers=(ca.certificate,), trusted_crls=(crl,))
    )
    await store.load()
    first = store.generation
    lists = store.read_lists()
    assert lists.trusted_certificates == (peer.der,)
    assert lists.issuer_certificates == (ca.der,)
    assert lists.trusted_crls == (crl.public_bytes(serialization.Encoding.DER),)
    assert lists.issuer_crls == ()
    await store.load()
    assert store.generation == first + 1


async def test_write_lists_replaces_only_the_masked_lists_and_rolls_back(tmp_path: Path) -> None:
    ca = make_ca()
    keep, drop, add = make_identity("keep"), make_identity("drop"), make_identity("add")
    store = TrustStore.from_pki_directory(
        write_pki_layout(tmp_path, trusted=(keep.certificate, drop.certificate), issuers=(ca.certificate,))
    )
    await store.load()
    journal = FileJournal()
    store.write_lists(TrustLists(trusted_certificates=(keep.der, add.der)), MASK_TRUSTED_CERTIFICATES, journal)
    await store.load()
    assert set(store.read_lists().trusted_certificates) == {keep.der, add.der}
    assert store.read_lists().issuer_certificates == (ca.der,)
    journal.rollback()
    await store.load()
    assert set(store.read_lists().trusted_certificates) == {keep.der, drop.der}


async def test_write_certificate_and_remove_certificate_files_with_their_crls(tmp_path: Path) -> None:
    ca = make_ca()
    crl = make_crl(ca)
    peer = make_identity("peer")
    store = TrustStore.from_pki_directory(write_pki_layout(tmp_path, trusted=(ca.certificate,), trusted_crls=(crl,)))
    await store.load()
    journal = FileJournal()
    store.write_certificate(peer.der, True, journal)
    await store.load()
    assert peer.der in store.read_lists().trusted_certificates
    store.remove_certificate_files(ca.der, True, journal)
    await store.load()
    lists = store.read_lists()
    assert ca.der not in lists.trusted_certificates
    assert lists.trusted_crls == ()


async def test_write_lists_needs_a_pki_directory(tmp_path: Path) -> None:
    store = TrustStore([write_trust_directory(tmp_path / "trusted")], [])
    with pytest.raises(ConfigurationError):
        store.write_lists(TrustLists(), MASK_ALL, FileJournal())


async def test_rejected_certificates_are_read_newest_first(tmp_path: Path) -> None:
    store = TrustStore.from_pki_directory(write_pki_layout(tmp_path))
    first, second = make_identity("first"), make_identity("second")
    store.record_rejected([first.der])
    os.utime(tmp_path / "rejected" / "certs" / thumbprint_name(first.der), (1_000_000, 1_000_000))
    store.record_rejected([second.der])
    assert store.rejected_certificates() == [second.der, first.der]
    store.remove_rejected(second.der)
    assert store.rejected_certificates() == [first.der]


async def test_cry32_a_generated_key_is_encrypted_with_the_password(tmp_path: Path) -> None:
    pki.create_directories(tmp_path)
    created = await pki.load_own_credentials(
        tmp_path,
        application_uri=APPLICATION_URI,
        host_names=["localhost"],
        usage=pki.SERVER_USAGE,
        password="key password",
    )
    (key_file,) = list((tmp_path / "own" / "private").iterdir())
    assert b"ENCRYPTED" in key_file.read_bytes()
    reloaded = await pki.load_own_credentials(
        tmp_path, application_uri=APPLICATION_URI, host_names=[], usage=pki.SERVER_USAGE, password="key password"
    )
    assert reloaded.private_key.public_key() == created.private_key.public_key()
    with pytest.raises(TypeError):
        await pki.load_own_credentials(tmp_path, application_uri=APPLICATION_URI, host_names=[], usage=pki.SERVER_USAGE)

"""test the PKI directory layout: the store, the rejected store and set_pki_directory"""

import hashlib
import os
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.validator import CertificateValidator, PeerRole, ValidationContext
from enginir_opcua.ua.uaerrors import ConfigurationError

from .conftest import find_free_port
from .pki import NOW, generated_pki, make_ca, make_crl, make_identity, write_pki_layout, write_trust_directory

CONTEXT = ValidationContext(PeerRole.CLIENT, SecurityPolicyBasic256Sha256.URI)


def validator_for(store: TrustStore) -> CertificateValidator:
    return CertificateValidator(store, clock=lambda: NOW)


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


async def test_r25_rejected_leaf_and_chain_are_written_by_thumbprint(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    validator = await pki_validator(write_pki_layout(tmp_path))
    outcome = validator.validate_application_certificate(leaf.der + ca.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateUntrusted
    names = [path.name for path in rejected_files(tmp_path)]
    assert names == sorted([thumbprint_name(leaf.der), thumbprint_name(ca.der)])
    assert (tmp_path / "rejected" / "certs" / thumbprint_name(leaf.der)).read_bytes() == leaf.der


async def test_r25_accepted_certificate_is_not_written(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path, trusted=(peer.certificate,)))
    assert validator.validate_application_certificate(peer.der, CONTEXT).accepted
    assert rejected_files(tmp_path) == []


async def test_r25_certificate_is_written_once_per_thumbprint(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path))
    validator.validate_application_certificate(peer.der, CONTEXT)
    (written,) = rejected_files(tmp_path)
    written.write_bytes(b"marker")
    validator.validate_application_certificate(peer.der, CONTEXT)
    assert written.read_bytes() == b"marker"
    assert len(rejected_files(tmp_path)) == 1


async def test_r25_store_is_bounded_and_the_oldest_file_goes_first(tmp_path: Path) -> None:
    validator = await pki_validator(write_pki_layout(tmp_path), max_rejected=3)
    peers = [make_identity(f"peer{index}") for index in range(5)]
    for index, peer in enumerate(peers):
        validator.validate_application_certificate(peer.der, CONTEXT)
        for path in rejected_files(tmp_path):
            if path.name == thumbprint_name(peer.der):
                os.utime(path, (1_000_000 + index, 1_000_000 + index))
    assert [path.name for path in rejected_files(tmp_path)] == sorted(thumbprint_name(p.der) for p in peers[2:])


async def test_r25_nothing_is_written_without_a_rejected_folder(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path, rejected=False))
    assert not validator.validate_application_certificate(peer.der, CONTEXT).accepted
    assert not (tmp_path / "rejected").exists()


async def test_r25_explicit_locations_have_no_rejected_store(tmp_path: Path) -> None:
    peer = make_identity()
    store = TrustStore([write_trust_directory(tmp_path / "trusted")], [])
    await store.load()
    assert not validator_for(store).validate_application_certificate(peer.der, CONTEXT).accepted
    assert entry_names(tmp_path) == ["trusted"]


async def test_r25_unparsable_data_is_not_written(tmp_path: Path) -> None:
    validator = await pki_validator(write_pki_layout(tmp_path))
    outcome = validator.validate_application_certificate(b"\x30\x03\x02\x01\x00", CONTEXT)
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
    outcome = validator.validate_application_certificate(peer.der, CONTEXT)
    assert outcome.status == ua.StatusCodes.BadCertificateUntrusted
    assert "denied" in caplog.text


async def test_r25_rejected_certificates_are_never_trusted(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path))
    validator.validate_application_certificate(peer.der, CONTEXT)
    await validator.trust_store.load()
    assert validator.trust_store.snapshot.trusted == ()
    assert not validator.validate_application_certificate(peer.der, CONTEXT).accepted


async def test_r25_moving_the_file_to_trusted_certs_trusts_it_after_reload(tmp_path: Path) -> None:
    peer = make_identity()
    validator = await pki_validator(write_pki_layout(tmp_path))
    validator.validate_application_certificate(peer.der, CONTEXT)
    (written,) = rejected_files(tmp_path)
    written.rename(tmp_path / "trusted" / "certs" / written.name)
    await validator.trust_store.load()
    assert validator.validate_application_certificate(peer.der, CONTEXT).accepted


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
    assert [path.name for path in rejected_files(root)] == [thumbprint_name(pki.peer1.identity.der)]


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
    assert [path.name for path in rejected_files(root)] == [thumbprint_name(pki.server.identity.der)]

"""test the PKI directory layout: the store, the rejected store and set_pki_directory"""

from pathlib import Path

import pytest

from enginir_opcua import Client, ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.validator import CertificateValidator, PeerRole, ValidationContext
from enginir_opcua.ua.uaerrors import ConfigurationError

from .pki import NOW, make_ca, make_crl, make_identity, write_pki_layout

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

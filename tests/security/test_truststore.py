"""test certificate truststore"""

import datetime
from pathlib import Path

from enginir_opcua import ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.validator import CertificateValidator, PeerRole, ValidationContext
from tests.pki import NOW, make_ca, make_crl, make_identity, write_crl_directory, write_trust_directory

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


async def test_ca_not_in_trust_store(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore([write_trust_directory(tmp_path / "trusted")], [])
    await store.load()
    assert not validator_for(store).validate_application_certificate(leaf.der, CONTEXT).accepted


async def test_ca_in_trust_store(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore([write_trust_directory(tmp_path / "trusted", ca.certificate)], [])
    await store.load()
    assert validator_for(store).validate_application_certificate(leaf.der, CONTEXT).accepted


async def test_cert_expired(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore([write_trust_directory(tmp_path / "trusted", ca.certificate)], [])
    await store.load()
    outcome = validator_for(store, NOW + datetime.timedelta(days=20 * 365)).validate_application_certificate(
        leaf.der, CONTEXT
    )
    assert outcome.status == ua.StatusCodes.BadCertificateTimeInvalid


async def test_cert_not_yet_valid(tmp_path: Path) -> None:
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    store = TrustStore([write_trust_directory(tmp_path / "trusted", ca.certificate)], [])
    await store.load()
    outcome = validator_for(store, NOW - datetime.timedelta(days=20 * 365)).validate_application_certificate(
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

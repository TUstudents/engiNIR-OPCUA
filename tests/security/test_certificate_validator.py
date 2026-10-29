import datetime
import logging
from collections.abc import Iterable
from pathlib import Path

import pytest
from cryptography.x509.oid import ExtendedKeyUsageOID

from enginir_opcua import ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256, SecurityPolicyBasic256Sha256
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.validator import (
    CertificateValidator,
    Outcome,
    PeerRole,
    Step,
    Suppression,
    ValidationContext,
)
from enginir_opcua.ua.uaerrors import ConfigurationError
from tests.pki import (
    APPLICATION_URI,
    NOW,
    Identity,
    application_key_usage,
    chain_bytes,
    fresh_key,
    make_ca,
    make_crl,
    make_identity,
    new_key,
    sha1_signed,
    write_crl_directory,
    write_trust_directory,
)

POLICY = SecurityPolicyBasic256Sha256.URI
CLIENT = ValidationContext(PeerRole.CLIENT, POLICY)
SERVER = ValidationContext(PeerRole.SERVER, POLICY, host_name="localhost")
SERVER_AUTH = (ExtendedKeyUsageOID.SERVER_AUTH,)


async def make_validator(
    tmp_path: Path,
    trusted: Iterable[Identity] = (),
    issuers: Iterable[Identity] = (),
    crls: Iterable[object] = (),
    issuer_crls: Iterable[object] = (),
    **options: object,
) -> CertificateValidator:
    locations: dict[str, list[Path]] = {"trust_locations": [], "issuer_locations": [], "crl_locations": []}
    locations["trust_locations"].append(write_trust_directory(tmp_path / "trusted", *[i.certificate for i in trusted]))
    locations["issuer_locations"].append(write_trust_directory(tmp_path / "issuers", *[i.certificate for i in issuers]))
    if crls or issuer_crls:
        locations["crl_locations"].append(write_crl_directory(tmp_path / "crl", *crls, *issuer_crls))  # type: ignore[arg-type]
    store = TrustStore(**locations)
    await store.load()
    return CertificateValidator(store, clock=lambda: NOW, **options)  # type: ignore[arg-type]


def expect(outcome: Outcome, status: int, step: Step) -> None:
    assert not outcome.accepted, "the certificate was accepted"
    assert outcome.status == status
    assert outcome.step == step


async def test_cry1_trusted_self_signed_certificate_is_accepted(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a certificate in the trusted list is trusted."""
    peer = make_identity()
    validator = await make_validator(tmp_path, trusted=[peer])
    assert validator.validate_application_certificate(peer.der, CLIENT).accepted


async def test_cry1_no_store_means_nothing_trusted_and_the_detail_names_the_setting(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: trust list check."""
    peer = make_identity()
    validator = await make_validator(tmp_path)
    outcome = validator.validate_application_certificate(peer.der, CLIENT)
    expect(outcome, ua.StatusCodes.BadCertificateUntrusted, Step.TRUST)
    assert "trust store" in outcome.detail


def test_cry1_validator_without_a_store_is_a_configuration_error() -> None:
    """Part 4, 6.1.3: a validator that would accept everything cannot be built by accident."""
    with pytest.raises(ConfigurationError, match="trust store"):
        CertificateValidator(None)  # type: ignore[arg-type]


async def test_cry1_revocation_checking_without_crl_location_is_a_configuration_error(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: revocation check."""
    store = TrustStore([write_trust_directory(tmp_path / "trusted")], [])
    await store.load()
    with pytest.raises(ConfigurationError, match="crl"):
        CertificateValidator(store, check_revocation=True)


@pytest.mark.parametrize("name", ["trusted", "uri", "chain", "structure", "signature"])
async def test_cry1_unsuppressible_step_is_a_configuration_error(tmp_path: Path, name: str) -> None:
    """Part 4, 6.1.3, Table 100: only the steps the table marks suppressible can be suppressed."""
    store = TrustStore([write_trust_directory(tmp_path / "trusted")], [])
    await store.load()
    with pytest.raises(ConfigurationError, match=name):
        CertificateValidator(store, suppress=[name])


async def test_cry1_self_signed_with_wrong_signature_is_rejected_even_if_trusted(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: signature check."""
    peer = make_identity()
    tampered = bytearray(peer.der)
    tampered[-5] ^= 0xFF
    directory = write_trust_directory(tmp_path / "trusted")
    (directory / "tampered.der").write_bytes(bytes(tampered))
    store = TrustStore([directory], [])
    await store.load()
    validator = CertificateValidator(store, clock=lambda: NOW)
    expect(
        validator.validate_application_certificate(bytes(tampered), CLIENT),
        ua.StatusCodes.BadCertificateInvalid,
        Step.SIGNATURE,
    )


async def test_cry3_selfsigned_ca_false_in_trusted_store_is_an_anchor(tmp_path: Path) -> None:
    """Part 4, 6.1.3 and Part 6, 6.2.2: an application certificate with cA FALSE is trusted when placed in the list."""
    peer = make_identity(ca=False)
    assert peer.certificate.issuer == peer.certificate.subject
    validator = await make_validator(tmp_path, trusted=[peer])
    assert validator.validate_application_certificate(peer.der, CLIENT).accepted


async def test_cry3_issuer_in_issuer_list_is_not_an_anchor(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a certificate that is only in the issuer list does not make its issued certificates trusted."""
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    validator = await make_validator(tmp_path, issuers=[ca])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT), ua.StatusCodes.BadCertificateUntrusted, Step.TRUST
    )


async def test_cry3_intermediate_sent_by_peer_builds_a_chain(tmp_path: Path) -> None:
    """Part 4, 6.1.3 and Part 6, 6.2.6: the peer appends its intermediate CAs after its certificate."""
    root = make_ca("Root")
    intermediate = make_ca("Intermediate", issuer=root)
    leaf = make_identity(issuer=intermediate)
    validator = await make_validator(tmp_path, trusted=[root])
    outcome = validator.validate_application_certificate(chain_bytes(leaf, intermediate), CLIENT)
    assert outcome.accepted
    assert outcome.leaf is not None
    assert outcome.leaf.serial_number == leaf.certificate.serial_number


async def test_cry3_intermediate_in_the_issuer_store_builds_a_chain(tmp_path: Path) -> None:
    """Part 4, 6.1.3: the issuer list supplies CAs the peer did not send."""
    root = make_ca("Root")
    intermediate = make_ca("Intermediate", issuer=root)
    leaf = make_identity(issuer=intermediate)
    validator = await make_validator(tmp_path, trusted=[root], issuers=[intermediate])
    assert validator.validate_application_certificate(leaf.der, CLIENT).accepted


async def test_cry3_missing_intermediate_gives_chain_incomplete(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: build certificate chain."""
    root = make_ca("Root")
    intermediate = make_ca("Intermediate", issuer=root)
    leaf = make_identity(issuer=intermediate)
    validator = await make_validator(tmp_path, trusted=[root])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateChainIncomplete,
        Step.CHAIN,
    )


async def test_cry3_leaf_trusted_directly_needs_no_issuer(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a CA-issued certificate the administrator placed in the trusted list is an anchor."""
    root = make_ca("Root")
    leaf = make_identity(issuer=root)
    validator = await make_validator(tmp_path, trusted=[leaf])
    assert validator.validate_application_certificate(leaf.der, CLIENT).accepted


async def test_cry3_certificate_issued_by_a_leaf_certificate_is_not_a_chain(tmp_path: Path) -> None:
    """Part 6, 6.2.6: an issuer in the chain must be a CA."""
    root = make_ca("Root")
    fake_ca = make_identity("Fake CA", issuer=root)
    leaf = make_identity(issuer=fake_ca)
    validator = await make_validator(tmp_path, trusted=[root])
    expect(
        validator.validate_application_certificate(chain_bytes(leaf, fake_ca), CLIENT),
        ua.StatusCodes.BadCertificateChainIncomplete,
        Step.CHAIN,
    )


async def test_cry3_path_length_is_enforced(tmp_path: Path) -> None:
    """Part 6, 6.2.6: path length constraints of the CAs apply."""
    root = make_ca("Root", path_length=0)
    intermediate = make_ca("Intermediate", issuer=root)
    leaf = make_identity(issuer=intermediate)
    validator = await make_validator(tmp_path, trusted=[root])
    expect(
        validator.validate_application_certificate(chain_bytes(leaf, intermediate), CLIENT),
        ua.StatusCodes.BadCertificateChainIncomplete,
        Step.CHAIN,
    )


async def test_cry3_crl_of_another_issuer_does_not_revoke(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a revocation list applies only to the certificates of its own issuer."""
    ca = make_ca()
    other_ca = make_ca("Other CA")
    leaf = make_identity(issuer=ca)
    validator = await make_validator(
        tmp_path, trusted=[ca], crls=[make_crl(ca), make_crl(other_ca, revoked=(leaf.certificate.serial_number,))]
    )
    assert validator.validate_application_certificate(leaf.der, CLIENT).accepted


async def test_cry3_crl_of_the_issuer_revokes(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: revocation check."""
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    validator = await make_validator(
        tmp_path, trusted=[ca], crls=[make_crl(ca, revoked=(leaf.certificate.serial_number,))]
    )
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateRevoked,
        Step.REVOCATION,
    )


async def test_cry3_crl_with_bad_signature_is_ignored(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a revocation list must be signed by its issuer, otherwise no list was found."""
    ca = make_ca()
    attacker = make_ca("Attacker")
    leaf = make_identity(issuer=ca)
    forged = make_crl(ca, revoked=(leaf.certificate.serial_number,), signer=attacker)
    validator = await make_validator(tmp_path, trusted=[ca], crls=[forged])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateRevocationUnknown,
        Step.REVOCATION_LIST,
    )


async def test_cry3_missing_crl_gives_revocation_unknown(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: find revocation list."""
    ca = make_ca()
    other = make_ca("Other")
    leaf = make_identity(issuer=ca)
    validator = await make_validator(tmp_path, trusted=[ca], crls=[make_crl(other)])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateRevocationUnknown,
        Step.REVOCATION_LIST,
    )


async def test_cry3_stale_crl_gives_revocation_unknown(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: find revocation list."""
    ca = make_ca()
    leaf = make_identity(issuer=ca)
    stale = make_crl(ca, last_update=NOW - datetime.timedelta(days=10), next_update=NOW - datetime.timedelta(days=3))
    validator = await make_validator(tmp_path, trusted=[ca], crls=[stale])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateRevocationUnknown,
        Step.REVOCATION_LIST,
    )


async def test_cry3_suppressed_revocation_unknown_is_accepted_and_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 4, 6.1.3, Table 100 and Part 12, 7.8.2.10: the suppression is explicit and logged."""
    ca = make_ca()
    other = make_ca("Other")
    leaf = make_identity(issuer=ca)
    validator = await make_validator(
        tmp_path, trusted=[ca], crls=[make_crl(other)], suppress=[Suppression.REVOCATION_UNKNOWN]
    )
    with caplog.at_level(logging.WARNING):
        outcome = validator.validate_application_certificate(leaf.der, CLIENT)
    assert outcome.accepted
    assert [(item.step, item.status) for item in outcome.suppressed] == [
        (Step.REVOCATION_LIST, ua.StatusCodes.BadCertificateRevocationUnknown)
    ]
    assert "revocation_unknown" in caplog.text


async def test_cry2_revoked_intermediate_rejects_leaf(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: revocation is checked for every CA of the chain."""
    root = make_ca("Root")
    intermediate = make_ca("Intermediate", issuer=root)
    leaf = make_identity(issuer=intermediate)
    validator = await make_validator(
        tmp_path,
        trusted=[root],
        crls=[make_crl(root, revoked=(intermediate.certificate.serial_number,)), make_crl(intermediate)],
    )
    outcome = validator.validate_application_certificate(chain_bytes(leaf, intermediate), CLIENT)
    expect(outcome, ua.StatusCodes.BadCertificateIssuerRevoked, Step.REVOCATION)


async def test_cry2_issuer_without_crl_uses_the_issuer_code(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: the issuer variant of find revocation list."""
    root = make_ca("Root")
    intermediate = make_ca("Intermediate", issuer=root)
    leaf = make_identity(issuer=intermediate)
    validator = await make_validator(tmp_path, trusted=[root], crls=[make_crl(intermediate)])
    outcome = validator.validate_application_certificate(chain_bytes(leaf, intermediate), CLIENT)
    expect(outcome, ua.StatusCodes.BadCertificateIssuerRevocationUnknown, Step.REVOCATION_LIST)


async def test_cry2_host_name_mismatch_on_the_client(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: host name."""
    server = make_identity(dns_names=("plc.example.org",), ext_key_usage=SERVER_AUTH)
    validator = await make_validator(tmp_path, trusted=[server])
    expect(
        validator.validate_application_certificate(server.der, SERVER),
        ua.StatusCodes.BadCertificateHostNameInvalid,
        Step.HOST_NAME,
    )
    matching = ValidationContext(PeerRole.SERVER, POLICY, host_name="PLC.example.org")
    assert validator.validate_application_certificate(server.der, matching).accepted


async def test_cry2_ip_address_host_matches_ip_san_only(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: host name."""
    server = make_identity(dns_names=("127.0.0.1",), ip_addresses=("10.0.0.5",), ext_key_usage=SERVER_AUTH)
    validator = await make_validator(tmp_path, trusted=[server])
    dns_only = ValidationContext(PeerRole.SERVER, POLICY, host_name="127.0.0.1")
    expect(
        validator.validate_application_certificate(server.der, dns_only),
        ua.StatusCodes.BadCertificateHostNameInvalid,
        Step.HOST_NAME,
    )
    by_ip = ValidationContext(PeerRole.SERVER, POLICY, host_name="10.0.0.5")
    assert validator.validate_application_certificate(server.der, by_ip).accepted


async def test_cry2_host_name_suppression(tmp_path: Path) -> None:
    """Part 12, 7.8.2.10: SuppressHostNameInvalid."""
    server = make_identity(dns_names=("plc.example.org",), ext_key_usage=SERVER_AUTH)
    validator = await make_validator(tmp_path, trusted=[server], suppress=[Suppression.HOST_NAME_INVALID])
    outcome = validator.validate_application_certificate(server.der, SERVER)
    assert outcome.accepted
    assert [item.step for item in outcome.suppressed] == [Step.HOST_NAME]


async def test_cry2_host_name_is_not_checked_for_a_client_peer(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: host name applies to server certificates."""
    client = make_identity(dns_names=("elsewhere",))
    validator = await make_validator(tmp_path, trusted=[client])
    context = ValidationContext(PeerRole.CLIENT, POLICY, host_name="localhost")
    assert validator.validate_application_certificate(client.der, context).accepted


async def test_cry2_expired_leaf_and_not_yet_valid(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: validity period."""
    expired = make_identity(not_before=NOW - datetime.timedelta(days=60), not_after=NOW - datetime.timedelta(days=30))
    future = make_identity(not_before=NOW + datetime.timedelta(days=1), not_after=NOW + datetime.timedelta(days=30))
    validator = await make_validator(tmp_path, trusted=[expired, future])
    expect(
        validator.validate_application_certificate(expired.der, CLIENT),
        ua.StatusCodes.BadCertificateTimeInvalid,
        Step.VALIDITY,
    )
    expect(
        validator.validate_application_certificate(future.der, CLIENT),
        ua.StatusCodes.BadCertificateTimeInvalid,
        Step.VALIDITY,
    )


async def test_cry2_issuer_expired_gives_issuer_time_invalid(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: the issuer variant of the validity period."""
    root = make_ca("Root", not_before=NOW - datetime.timedelta(days=60), not_after=NOW - datetime.timedelta(days=30))
    leaf = make_identity(issuer=root)
    validator = await make_validator(tmp_path, trusted=[root])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateIssuerTimeInvalid,
        Step.VALIDITY,
    )


async def test_cry2_expired_suppression(tmp_path: Path) -> None:
    """Part 12, 7.8.2.10: SuppressCertificateExpired."""
    expired = make_identity(not_before=NOW - datetime.timedelta(days=60), not_after=NOW - datetime.timedelta(days=30))
    validator = await make_validator(tmp_path, trusted=[expired], suppress=[Suppression.CERTIFICATE_EXPIRED])
    assert validator.validate_application_certificate(expired.der, CLIENT).accepted


async def test_cry2_steps_run_in_table_order(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: the trust list check comes before the validity period."""
    expired = make_identity(not_before=NOW - datetime.timedelta(days=60), not_after=NOW - datetime.timedelta(days=30))
    validator = await make_validator(tmp_path)
    expect(
        validator.validate_application_certificate(expired.der, CLIENT),
        ua.StatusCodes.BadCertificateUntrusted,
        Step.TRUST,
    )


async def test_cry2_missing_key_usage_is_use_not_allowed(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: certificate usage; Part 6, 6.2.2."""
    peer = make_identity(key_usage=None)
    validator = await make_validator(tmp_path, trusted=[peer])
    expect(
        validator.validate_application_certificate(peer.der, CLIENT),
        ua.StatusCodes.BadCertificateUseNotAllowed,
        Step.USAGE,
    )


async def test_cry2_wrong_extended_key_usage_for_the_role(tmp_path: Path) -> None:
    """Part 6, 6.2.2: a client certificate carries clientAuth, a server certificate serverAuth."""
    server_only = make_identity(ext_key_usage=SERVER_AUTH)
    validator = await make_validator(tmp_path, trusted=[server_only])
    expect(
        validator.validate_application_certificate(server_only.der, CLIENT),
        ua.StatusCodes.BadCertificateUseNotAllowed,
        Step.USAGE,
    )
    assert validator.validate_application_certificate(server_only.der, SERVER).accepted


async def test_cry2_usage_suppression(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: certificate usage is suppressible."""
    peer = make_identity(key_usage=None)
    validator = await make_validator(tmp_path, trusted=[peer], suppress=[Suppression.USAGE])
    assert validator.validate_application_certificate(peer.der, CLIENT).accepted


async def test_cry2_issuer_without_key_cert_sign_uses_the_issuer_code(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: the issuer variant of certificate usage."""
    root = make_ca("Root", key_usage=None)
    leaf = make_identity(issuer=root)
    validator = await make_validator(tmp_path, trusted=[root])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateIssuerUseNotAllowed,
        Step.USAGE,
    )


async def test_cry17_application_type_is_not_checked(tmp_path: Path) -> None:
    """Part 4, 6.1.3: the table has no step that compares an ApplicationType with the certificate."""
    both = make_identity(ext_key_usage=(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH))
    validator = await make_validator(tmp_path, trusted=[both])
    assert validator.validate_application_certificate(both.der, CLIENT).accepted
    assert validator.validate_application_certificate(both.der, SERVER).accepted


async def test_srv29_uri_mismatch_is_bad_certificate_uri_invalid(tmp_path: Path) -> None:
    """Part 4, 5.7.2 and 6.1.3, Table 100: URI."""
    peer = make_identity(uri="urn:other")
    validator = await make_validator(tmp_path, trusted=[peer])
    context = ValidationContext(PeerRole.CLIENT, POLICY, expected_application_uri=APPLICATION_URI)
    expect(
        validator.validate_application_certificate(peer.der, context), ua.StatusCodes.BadCertificateUriInvalid, Step.URI
    )
    assert validator.validate_application_certificate(peer.der, CLIENT).accepted
    assert validator.check_application_uri(peer.certificate, "urn:other").accepted
    expect(
        validator.check_application_uri(peer.certificate, APPLICATION_URI),
        ua.StatusCodes.BadCertificateUriInvalid,
        Step.URI,
    )


async def test_cry2_certificate_without_uri_is_invalid(tmp_path: Path) -> None:
    """Part 6, 6.2.2, Table 50: the URI entry of the subject alternative name is required."""
    peer = make_identity(uri=None)
    validator = await make_validator(tmp_path, trusted=[peer])
    expect(
        validator.validate_application_certificate(peer.der, CLIENT),
        ua.StatusCodes.BadCertificateInvalid,
        Step.STRUCTURE,
    )


@pytest.mark.parametrize("garbage", [b"", b"\x00" * 10, b"\x30\x82\x00\x10abc", b"not a certificate"])
async def test_cry_structure_garbage_is_invalid(tmp_path: Path, garbage: bytes) -> None:
    """Part 4, 6.1.3, Table 100: certificate structure; the validator never raises for a bad certificate."""
    validator = await make_validator(tmp_path)
    expect(
        validator.validate_application_certificate(garbage, CLIENT),
        ua.StatusCodes.BadCertificateInvalid,
        Step.STRUCTURE,
    )


async def test_cry_structure_trailing_bytes_are_invalid(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: certificate structure."""
    peer = make_identity()
    validator = await make_validator(tmp_path, trusted=[peer])
    expect(
        validator.validate_application_certificate(peer.der + b"\x00\x01", CLIENT),
        ua.StatusCodes.BadCertificateInvalid,
        Step.STRUCTURE,
    )


async def test_cry_structure_without_basic_constraints_is_invalid(tmp_path: Path) -> None:
    """Part 6, 6.2.2, Table 50: the basic constraints extension shall be present."""
    peer = make_identity(basic_constraints=False)
    validator = await make_validator(tmp_path, trusted=[peer])
    expect(
        validator.validate_application_certificate(peer.der, CLIENT),
        ua.StatusCodes.BadCertificateInvalid,
        Step.STRUCTURE,
    )


async def test_cry_chain_longer_than_the_limit_is_incomplete(tmp_path: Path) -> None:
    """Part 6, 6.2.6: chains are bounded."""
    peer = make_identity()
    validator = await make_validator(tmp_path, trusted=[peer])
    expect(
        validator.validate_application_certificate(peer.der * 11, CLIENT),
        ua.StatusCodes.BadCertificateChainIncomplete,
        Step.CHAIN,
    )


async def test_cry5_1024_bit_certificate_fails_the_policy_check(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100 and Part 6, 6.1, Table 49: policy check."""
    small = make_identity(key=fresh_key(1024))
    validator = await make_validator(tmp_path, trusted=[small])
    expect(
        validator.validate_application_certificate(small.der, CLIENT),
        ua.StatusCodes.BadCertificatePolicyCheckFailed,
        Step.POLICY,
    )


async def test_cry5_1024_bit_certificate_is_fine_for_basic256(tmp_path: Path) -> None:
    """Part 6, 6.1, Table 49: Basic256 allows 1024 bits."""
    small = sha1_signed(make_identity(key=fresh_key(1024)))
    validator = await make_validator(tmp_path, trusted=[small])
    context = ValidationContext(PeerRole.CLIENT, SecurityPolicyBasic256.URI)
    assert validator.validate_application_certificate(small.der, context).accepted


async def test_cry5_oversized_key_fails_the_policy_check(tmp_path: Path) -> None:
    """Part 6, 6.1, Table 49: the maximum applies too."""
    big = make_identity(key=new_key(3072))
    validator = await make_validator(tmp_path, trusted=[big])
    context = ValidationContext(PeerRole.CLIENT, SecurityPolicyBasic256.URI)
    expect(
        validator.validate_application_certificate(big.der, context),
        ua.StatusCodes.BadCertificatePolicyCheckFailed,
        Step.POLICY,
    )
    assert validator.validate_application_certificate(big.der, CLIENT).accepted


async def test_cry5_sha1_certificate_fails_under_sha256_policy(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: policy check covers the certificate signature algorithm."""
    legacy = sha1_signed(make_identity())
    validator = await make_validator(tmp_path, trusted=[legacy])
    expect(
        validator.validate_application_certificate(legacy.der, CLIENT),
        ua.StatusCodes.BadCertificatePolicyCheckFailed,
        Step.POLICY,
    )


async def test_cry5_issuer_with_sha1_signature_fails_the_policy_check(tmp_path: Path) -> None:
    """Part 6, 6.1, Table 49: the limits apply to all certificates of the chain."""
    root = sha1_signed(make_ca("Root"))
    leaf = make_identity(issuer=root)
    validator = await make_validator(tmp_path, trusted=[root])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificatePolicyCheckFailed,
        Step.POLICY,
    )


async def test_cry5_policy_none_skips_the_policy_check(tmp_path: Path) -> None:
    """Part 4, 6.1.3: the policy check needs a SecurityPolicy other than None."""
    small = make_identity(key=fresh_key(1024))
    validator = await make_validator(tmp_path, trusted=[small])
    assert validator.validate_application_certificate(small.der, ValidationContext(PeerRole.CLIENT, None)).accepted


async def test_cry5_policy_check_suppression(tmp_path: Path) -> None:
    """Part 4, 6.1.3, Table 100: the policy check is suppressible."""
    small = make_identity(key=fresh_key(1024))
    validator = await make_validator(tmp_path, trusted=[small], suppress=[Suppression.POLICY_CHECK])
    outcome = validator.validate_application_certificate(small.der, CLIENT)
    assert outcome.accepted
    assert outcome.suppressed[0].step == Step.POLICY


async def test_cry11_ca_true_application_certificate_accepted_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 6, 6.2.2: cA TRUE is accepted for backward compatibility with a warning."""
    peer = make_identity(ca=True, key_usage=application_key_usage(key_cert_sign=True))
    validator = await make_validator(tmp_path, trusted=[peer])
    with caplog.at_level(logging.WARNING):
        assert validator.validate_application_certificate(peer.der, CLIENT).accepted
    assert "cA" in caplog.text


async def test_cry11_ca_true_rejected_when_option_off(tmp_path: Path) -> None:
    """Part 6, 6.2.2: cA TRUE is only tolerated."""
    peer = make_identity(ca=True)
    validator = await make_validator(tmp_path, trusted=[peer], accept_ca_application_certificates=False)
    expect(
        validator.validate_application_certificate(peer.der, CLIENT),
        ua.StatusCodes.BadCertificateInvalid,
        Step.STRUCTURE,
    )


async def test_cry11_ca_true_issued_leaf_rejected_without_revocation_checking(tmp_path: Path) -> None:
    """Part 6, 6.2.2: cA TRUE should not be accepted when revocation checking is off, unless the certificate is trusted."""
    root = make_ca("Root")
    leaf = make_identity(issuer=root, ca=True)
    validator = await make_validator(tmp_path, trusted=[root])
    expect(
        validator.validate_application_certificate(leaf.der, CLIENT),
        ua.StatusCodes.BadCertificateInvalid,
        Step.STRUCTURE,
    )


async def test_cry3_pinned_certificate_is_trusted_but_still_checked(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a pinned certificate is an anchor and goes through the other steps."""
    expired = make_identity(not_before=NOW - datetime.timedelta(days=60), not_after=NOW - datetime.timedelta(days=30))
    fresh = make_identity()
    validator = await make_validator(tmp_path)
    store = validator.trust_store
    store.pin(expired.certificate)
    store.pin(fresh.certificate)
    assert validator.validate_application_certificate(fresh.der, CLIENT).accepted
    expect(
        validator.validate_application_certificate(expired.der, CLIENT),
        ua.StatusCodes.BadCertificateTimeInvalid,
        Step.VALIDITY,
    )


async def test_cry4_non_certificate_files_are_ignored_and_a_bad_file_does_not_abort_the_load(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 12, 7.8.2.8: the trust lists hold certificates; other files are not part of them."""
    peer = make_identity()
    directory = write_trust_directory(tmp_path / "trusted", peer.certificate)
    (directory / "header.txt").write_text("this file mentions der and pem")
    (directory / "notes-pem.md").write_text("notes")
    (directory / "broken.der").write_bytes(b"\x30\x03abc")
    store = TrustStore([directory], [])
    with caplog.at_level(logging.WARNING):
        await store.load()
    assert "broken.der" in caplog.text
    assert "header.txt" not in caplog.text
    validator = CertificateValidator(store, clock=lambda: NOW)
    assert validator.validate_application_certificate(peer.der, CLIENT).accepted


async def test_cry4_missing_location_is_a_configuration_error(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a configured but missing trust location is a configuration problem."""
    store = TrustStore([tmp_path / "missing"], [])
    with pytest.raises(ConfigurationError, match="missing"):
        await store.load()


async def test_cry4_rejected_peer_is_logged_in_one_line_without_a_traceback(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 4, 6.1.3: rejecting a peer is routine and needs no stack trace."""
    peer = make_identity()
    validator = await make_validator(tmp_path)
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        validator.validate_application_certificate(peer.der, CLIENT)
    records = [record for record in caplog.records if record.levelno >= logging.WARNING]
    assert len(records) == 1
    assert records[0].exc_info is None
    assert "\n" not in records[0].getMessage()
    assert records[0].name.startswith("enginir_opcua")


async def test_cry3_reload_swaps_the_snapshot(tmp_path: Path) -> None:
    """Part 4, 6.1.3: a changed trust list applies to the next validation."""
    peer = make_identity()
    directory = write_trust_directory(tmp_path / "trusted")
    store = TrustStore([directory], [])
    await store.load()
    validator = CertificateValidator(store, clock=lambda: NOW)
    old_snapshot = store.snapshot
    assert not validator.validate_application_certificate(peer.der, CLIENT).accepted
    write_trust_directory(directory, peer.certificate)
    await store.load()
    assert validator.validate_application_certificate(peer.der, CLIENT).accepted
    assert store.snapshot is not old_snapshot

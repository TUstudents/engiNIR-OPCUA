import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from enginir_opcua import ua
from enginir_opcua.crypto import uacrypto
from enginir_opcua.crypto.cert_gen import generate_private_key, generate_self_signed_app_certificate

from .harness import EXAMPLES

LEAF = (EXAMPLES / "certificate-example.der").read_bytes()
SECOND = (EXAMPLES / "certificates" / "peer-certificate-example-1.der").read_bytes()
APP_URI = "urn:foobar:myserver"


def _certificate(days: int = 1) -> x509.Certificate:
    names: list[x509.GeneralName] = [x509.UniformResourceIdentifier(APP_URI), x509.DNSName("myhost")]
    return generate_self_signed_app_certificate(
        generate_private_key(), "myserver", {"organizationName": "Bar Ltd"}, names, extended=[], days=days
    )


def test_cry10_check_certificate_returns_no_problems_for_a_matching_certificate() -> None:
    assert uacrypto.check_certificate(_certificate(), APP_URI, "myhost") == []


def test_cry10_check_certificate_returns_the_problems_found() -> None:
    problems = uacrypto.check_certificate(_certificate(), "urn:other", "otherhost")
    assert len(problems) == 2
    assert all(isinstance(problem, str) for problem in problems)


@pytest.mark.parametrize(
    "data",
    [b"\x30", b"\x30\x82", b"\x30\x82\x10", b"\x30\x82\x10\x00abc", b"\x30\x84\xff\xff\xff\xff", b"\x31\x00", b"junk"],
)
def test_cry10_x509_from_der_rejects_malformed_input_with_ua_error(data: bytes) -> None:
    with pytest.raises(ua.UaError):
        uacrypto.x509_from_der(data)


def test_cry10_x509_from_der_truncated_certificate_is_a_ua_error() -> None:
    with pytest.raises(ua.UaError):
        uacrypto.x509_from_der(LEAF[:-10])


def test_cry10_x509_from_der_returns_the_first_certificate_of_a_chain() -> None:
    certificate = uacrypto.x509_from_der(LEAF + SECOND)
    assert certificate is not None
    assert certificate.public_bytes(serialization.Encoding.DER) == LEAF


def test_cry10_split_certificate_chain_returns_every_certificate_leaf_first() -> None:
    assert uacrypto.split_certificate_chain(LEAF + SECOND) == [LEAF, SECOND]
    assert uacrypto.split_certificate_chain(LEAF) == [LEAF]


def test_cry10_split_certificate_chain_rejects_trailing_junk() -> None:
    with pytest.raises(ua.UaError):
        uacrypto.split_certificate_chain(LEAF + b"\x00\x01")

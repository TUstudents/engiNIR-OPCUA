import atexit
import datetime
import ipaddress
import shutil
import socket
import tempfile
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from enginir_opcua.crypto.truststore import TrustStore

NOW = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.UTC)
APPLICATION_URI = "urn:test:application"


@dataclass(frozen=True)
class Identity:
    certificate: x509.Certificate
    key: rsa.RSAPrivateKey

    @property
    def der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def key_pem(self) -> bytes:
        return self.encrypted_key_pem(None)

    def encrypted_key_pem(self, password: bytes | None) -> bytes:
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)

    def write(self, directory: Path, name: str, password: bytes | None = None) -> tuple[Path, Path]:
        directory.mkdir(parents=True, exist_ok=True)
        cert_path = directory / f"{name}.der"
        key_path = directory / f"{name}.pem"
        cert_path.write_bytes(self.der)
        key_path.write_bytes(self.encrypted_key_pem(password))
        return cert_path, key_path


@cache
def new_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def fresh_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def make_identity(
    common_name: str = "test",
    *,
    issuer: Identity | None = None,
    key: rsa.RSAPrivateKey | None = None,
    uri: str | None = APPLICATION_URI,
    dns_names: tuple[str, ...] = ("localhost",),
    ip_addresses: tuple[str, ...] = (),
    ca: bool = False,
    path_length: int | None = None,
    key_usage: x509.KeyUsage | bool | None = True,
    ext_key_usage: tuple[x509.ObjectIdentifier, ...] | None = (ExtendedKeyUsageOID.CLIENT_AUTH,),
    basic_constraints: bool = True,
    subject_alt_name: bool = True,
    authority_key_id: bool = True,
    not_before: datetime.datetime = NOW - datetime.timedelta(days=1),
    not_after: datetime.datetime = NOW + datetime.timedelta(days=30),
    hash_algorithm: hashes.HashAlgorithm | None = None,
    serial_number: int | None = None,
    issuer_name_override: x509.Name | None = None,
) -> Identity:
    key = key or fresh_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signer_key = issuer.key if issuer else key
    issuer_name = issuer.certificate.subject if issuer else subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name_override or issuer_name)
        .public_key(key.public_key())
        .serial_number(serial_number or x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if authority_key_id:
        authority_key = issuer.certificate.public_key() if issuer else key.public_key()
        assert isinstance(authority_key, rsa.RSAPublicKey)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key), False)
    if basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if subject_alt_name:
        names: list[x509.GeneralName] = []
        if uri is not None:
            names.append(x509.UniformResourceIdentifier(uri))
        names.extend(x509.DNSName(name) for name in dns_names)
        names.extend(x509.IPAddress(ipaddress.ip_address(address)) for address in ip_addresses)
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if key_usage is True:
        key_usage = ca_key_usage() if ca else application_key_usage()
    if isinstance(key_usage, x509.KeyUsage):
        builder = builder.add_extension(key_usage, critical=False)
    if ext_key_usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(ext_key_usage)), critical=False)
    certificate = builder.sign(signer_key, hash_algorithm or hashes.SHA256())
    return Identity(certificate, key)


def application_key_usage(key_cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=True,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def make_ca(common_name: str = "Test CA", *, issuer: Identity | None = None, path_length: int | None = None, **kwargs):
    kwargs.setdefault("uri", None)
    kwargs.setdefault("dns_names", ())
    kwargs.setdefault("ext_key_usage", None)
    return make_identity(common_name, issuer=issuer, ca=True, path_length=path_length, **kwargs)


def make_crl(
    issuer: Identity,
    revoked: tuple[int, ...] = (),
    *,
    signer: Identity | None = None,
    last_update: datetime.datetime = NOW - datetime.timedelta(hours=1),
    next_update: datetime.datetime | None = NOW + datetime.timedelta(days=7),
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.certificate.subject)
        .last_update(last_update)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
    )
    if next_update is not None:
        builder = builder.next_update(next_update)
    for serial in revoked:
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(last_update).build()
        builder = builder.add_revoked_certificate(entry)
    return builder.sign((signer or issuer).key, hashes.SHA256())


def write_trust_directory(directory: Path, *certificates: x509.Certificate) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for index, certificate in enumerate(certificates):
        (directory / f"cert{index}.der").write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    return directory


def write_crl_directory(directory: Path, *crls: x509.CertificateRevocationList) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for index, crl in enumerate(crls):
        (directory / f"list{index}.crl").write_bytes(crl.public_bytes(serialization.Encoding.DER))
    return directory


def chain_bytes(*identities: Identity) -> bytes:
    return b"".join(identity.der for identity in identities)


SHA256_WITH_RSA = bytes.fromhex("2a864886f70d01010b")
SHA1_WITH_RSA = bytes.fromhex("2a864886f70d010105")


def sha1_signed(identity: Identity, signer: Identity | None = None) -> Identity:
    """The same certificate signed with RSA and SHA-1, which the certificate builder of the library refuses to do."""
    swapped = identity.der.replace(SHA256_WITH_RSA, SHA1_WITH_RSA)
    tbs = x509.load_der_x509_certificate(swapped).tbs_certificate_bytes
    signature = (signer or identity).key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    signature_size = len(x509.load_der_x509_certificate(swapped).signature)
    assert len(signature) == signature_size
    return Identity(x509.load_der_x509_certificate(swapped[:-signature_size] + signature), identity.key)


CLIENT_APPLICATION_URI = "urn:enginir:opcua:client"
SERVER_APPLICATION_URI = "urn:enginir:opcua:server"
BOTH_USAGES = (ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH)


def live_validity() -> dict[str, datetime.datetime]:
    now = datetime.datetime.now(datetime.UTC)
    return {"not_before": now - datetime.timedelta(days=1), "not_after": now + datetime.timedelta(days=365)}


def live_identity(common_name: str = "test", **kwargs: Any) -> Identity:
    return make_identity(common_name, **{**live_validity(), **kwargs})


def live_ca(common_name: str = "Test CA", **kwargs: Any) -> Identity:
    return make_ca(common_name, **{**live_validity(), **kwargs})


@dataclass(frozen=True)
class Peer:
    identity: Identity
    certificate: Path
    key: Path
    password: bytes | None = None


class GeneratedPki:
    """Certificates for the tests that connect with security, generated once per test run and removed at exit."""

    def __init__(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="enginir-test-pki-"))
        atexit.register(shutil.rmtree, self.directory, ignore_errors=True)
        self.trusted = self.directory / "trusted"
        self.trusted.mkdir()
        self.server = self.issue("server", SERVER_APPLICATION_URI)
        self.server_3072 = self.issue("server-3072", SERVER_APPLICATION_URI, bits=3072)
        self.peer1 = self.issue("peer1", CLIENT_APPLICATION_URI)
        self.peer2 = self.issue("peer2", CLIENT_APPLICATION_URI)
        self.peer3 = self.issue("peer3", CLIENT_APPLICATION_URI)
        self.peer_encrypted = self.issue("peer-encrypted", CLIENT_APPLICATION_URI, password=b"password")

    def issue(self, name: str, uri: str, *, bits: int = 2048, password: bytes | None = None) -> Peer:
        identity = live_identity(
            name,
            key=fresh_key(bits),
            uri=uri,
            dns_names=("localhost", socket.gethostname()),
            ip_addresses=("127.0.0.1",),
            ext_key_usage=BOTH_USAGES,
        )
        certificate, key = identity.write(self.directory, name, password)
        shutil.copy(certificate, self.trusted / certificate.name)
        return Peer(identity, certificate, key, password)

    def trust_store(self) -> TrustStore:
        return TrustStore([self.trusted], [])


@cache
def generated_pki() -> GeneratedPki:
    return GeneratedPki()

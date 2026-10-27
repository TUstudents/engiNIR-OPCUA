"""
The PKI directory of an application: the folders, and the application certificate in its own/ folder.

    own/certs      application certificate and the intermediate CA certificates of its chain
    own/private    private key
    trusted/certs  trusted certificates (anchors), trusted/crl their revocation lists
    issuer/certs   CA certificates for chains, issuer/crl their revocation lists
    rejected/certs certificates of peers that failed validation
"""

import ipaddress
import logging
import socket
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

import anyio
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID

from enginir_opcua.crypto import cert_gen, uacrypto
from enginir_opcua.crypto.truststore import CERTIFICATE_EXTENSIONS
from enginir_opcua.ua.uaerrors import ConfigurationError

_logger = logging.getLogger(__name__)

CERTIFICATE_NAME = "application.der"
KEY_NAME = "application.pem"
KEY_EXTENSIONS = frozenset({".pem", ".key"})
WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::"})


@dataclass(frozen=True)
class OwnCredentials:
    certificate: x509.Certificate
    chain: list[x509.Certificate]
    private_key: RSAPrivateKey


def create_directories(root: Path, *, own: bool = True) -> None:
    """Create the folders of the layout. The private folder is created readable by its owner only."""
    folders = ["trusted/certs", "trusted/crl", "issuer/certs", "issuer/crl", "rejected/certs"]
    if own:
        folders.append("own/certs")
    for folder in folders:
        (root / folder).mkdir(parents=True, exist_ok=True)
    if own:
        private = root / "own" / "private"
        existed = private.is_dir()
        private.mkdir(parents=True, exist_ok=True)
        if not existed:
            private.chmod(0o700)


def host_name_entries(host_names: Iterable[str | None]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    for host_name in host_names:
        if host_name is None or host_name in WILDCARD_HOSTS:
            continue
        try:
            entry: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host_name))
        except ValueError:
            entry = x509.DNSName(host_name)
        if entry not in entries:
            entries.append(entry)
    return entries


def default_host_names(*others: str | None) -> list[str | None]:
    return [socket.gethostname(), "localhost", *others]


def _files(folder: Path, extensions: frozenset[str]) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted(entry for entry in folder.iterdir() if entry.suffix.lower() in extensions and entry.is_file())


def _same_key(certificate: x509.Certificate, key: RSAPrivateKey) -> bool:
    encoding, format = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    return certificate.public_key().public_bytes(encoding, format) == key.public_key().public_bytes(encoding, format)


def _chain_of(leaf: x509.Certificate, others: list[x509.Certificate]) -> list[x509.Certificate]:
    chain: list[x509.Certificate] = []
    current = leaf
    while current.subject != current.issuer:
        issuer = next((c for c in others if c.subject == current.issuer and c not in chain and c != leaf), None)
        if issuer is None:
            break
        if issuer.subject != issuer.issuer:
            chain.append(issuer)
        current = issuer
    return chain


async def load_own_credentials(
    root: Path,
    *,
    application_uri: str,
    host_names: Sequence[str | None],
    usage: list[x509.ObjectIdentifier],
    password: str | bytes | None = None,
    create: bool = True,
) -> OwnCredentials:
    """
    Load the application certificate, its chain and its key from own/. When own/certs holds no certificate and
    create is set, a self-signed application certificate and its key are generated there, readable by the owner
    only for the key. An existing certificate is never replaced.
    """
    certificate_files = await anyio.to_thread.run_sync(_files, root / "own" / "certs", CERTIFICATE_EXTENSIONS)
    key_files = await anyio.to_thread.run_sync(_files, root / "own" / "private", KEY_EXTENSIONS)
    if not certificate_files:
        if not create:
            raise ConfigurationError(
                f"{root / 'own' / 'certs'} holds no application certificate; "
                "put one there with its key in own/private, or let the library generate one (create=True)"
            )
        return await _generate(root, key_files, application_uri, host_names, usage, password)
    if not key_files:
        raise ConfigurationError(f"{root / 'own' / 'private'} holds no private key for the certificate in own/certs")
    key = await uacrypto.load_private_key(key_files[0], password)
    if not isinstance(key, RSAPrivateKey):
        raise ConfigurationError(f"The private key {key_files[0]} is not an RSA key")
    certificates: list[x509.Certificate] = []
    for file_name in certificate_files:
        certificates.extend(await uacrypto.load_certificates(file_name))
    leaf = next((certificate for certificate in certificates if _same_key(certificate, key)), None)
    if leaf is None:
        raise ConfigurationError(f"No certificate in {root / 'own' / 'certs'} belongs to the key {key_files[0]}")
    return OwnCredentials(leaf, _chain_of(leaf, certificates), key)


async def _generate(
    root: Path,
    key_files: list[Path],
    application_uri: str,
    host_names: Sequence[str | None],
    usage: list[x509.ObjectIdentifier],
    password: str | bytes | None,
) -> OwnCredentials:
    if key_files:
        loaded = await uacrypto.load_private_key(key_files[0], password)
        if not isinstance(loaded, RSAPrivateKey):
            raise ConfigurationError(f"The private key {key_files[0]} is not an RSA key")
        key = loaded
    else:
        key = cert_gen.generate_private_key()
        await cert_gen.write_private_key(root / "own" / "private" / KEY_NAME, key)
    alternative_names: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(application_uri),
        *host_name_entries(host_names),
    ]
    certificate = cert_gen.generate_self_signed_app_certificate(key, application_uri, {}, alternative_names, usage)
    await cert_gen.write_certificate(root / "own" / "certs" / CERTIFICATE_NAME, certificate)
    _logger.info("Generated the application certificate %s", root / "own" / "certs" / CERTIFICATE_NAME)
    return OwnCredentials(certificate, [], key)


SERVER_USAGE = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
CLIENT_USAGE = [ExtendedKeyUsageOID.CLIENT_AUTH]

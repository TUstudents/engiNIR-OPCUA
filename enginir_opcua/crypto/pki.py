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
import re
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
from enginir_opcua.crypto.file_journal import FileJournal
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
    Load the application certificate, its chain and its key from own/. The certificate is the one whose key is in
    own/private; when several certificates match a key, the one that became valid last. When own/certs holds no
    certificate and create is set, a self-signed application certificate and its key are generated there, readable
    by the owner only for the key. An existing certificate is never replaced.
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
    keys: list[tuple[Path, RSAPrivateKey]] = []
    for key_file in key_files:
        key = await uacrypto.load_private_key(key_file, password)
        if isinstance(key, RSAPrivateKey):
            keys.append((key_file, key))
        elif len(key_files) == 1:
            raise ConfigurationError(f"The private key {key_file} is not an RSA key")
        else:
            _logger.warning("Ignoring the private key %s, it is not an RSA key", key_file)
    if not keys:
        raise ConfigurationError(f"{root / 'own' / 'private'} holds no RSA private key")
    certificates: list[x509.Certificate] = []
    for file_name in certificate_files:
        certificates.extend(await uacrypto.load_certificates(file_name))
    matching = [(certificate, key) for certificate in certificates for _, key in keys if _same_key(certificate, key)]
    if not matching:
        names = ", ".join(str(key_file) for key_file, _ in keys)
        raise ConfigurationError(f"No certificate in {root / 'own' / 'certs'} belongs to the key {names}")
    leaf, key = max(matching, key=lambda pair: pair[0].not_valid_before_utc)
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
        await cert_gen.write_private_key(root / "own" / "private" / KEY_NAME, key, password)
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


def _pending_path(root: Path, name: str) -> Path:
    return root / "own" / "pending" / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}.pem"


def save_pending_key(root: Path, name: str, key: RSAPrivateKey, journal: FileJournal | None = None) -> None:
    """Keep a new private key until its certificate arrives. One key per name; an earlier one is replaced."""
    journal = journal or FileJournal()
    journal.create_directory(root / "own" / "pending", 0o700)
    journal.write(_pending_path(root, name), cert_gen.dump_private_key_as_pem(key), 0o600)


def load_pending_key(root: Path, name: str) -> RSAPrivateKey | None:
    path = _pending_path(root, name)
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), None)
    except (FileNotFoundError, ValueError):
        return None
    return key if isinstance(key, RSAPrivateKey) else None


def discard_pending_key(root: Path, name: str, journal: FileJournal | None = None) -> None:
    (journal or FileJournal()).remove(_pending_path(root, name))


def write_own_credentials(
    root: Path,
    certificate: x509.Certificate,
    chain: Sequence[x509.Certificate],
    key: RSAPrivateKey,
    previous: x509.Certificate | None,
    journal: FileJournal,
) -> None:
    """
    Make a certificate, its chain and its key the application credentials: the key, then the certificate, are
    written over `application.pem` and `application.der`, and the files of the previous certificate and of its key
    are removed. Blocking; undo through the journal.
    """
    certificates, private = root / "own" / "certs", root / "own" / "private"
    journal.create_directory(certificates)
    journal.create_directory(private, 0o700)
    journal.write(private / KEY_NAME, cert_gen.dump_private_key_as_pem(key), 0o600)
    journal.write(certificates / CERTIFICATE_NAME, certificate.public_bytes(serialization.Encoding.DER), 0o644)
    for intermediate in chain:
        der = intermediate.public_bytes(serialization.Encoding.DER)
        journal.write(certificates / f"{uacrypto.certificate_thumbprint(der).hex()}.der", der, 0o644)
    if previous is None:
        return
    for entry in _files(certificates, CERTIFICATE_EXTENSIONS):
        if entry.name == CERTIFICATE_NAME:
            continue
        try:
            if previous in _load_certificates_sync(entry):
                journal.remove(entry)
        except ValueError:
            continue
    for entry in _files(private, KEY_EXTENSIONS):
        if entry.name == KEY_NAME:
            continue
        try:
            old = serialization.load_pem_private_key(entry.read_bytes(), None)
        except (ValueError, TypeError):
            continue
        if isinstance(old, RSAPrivateKey) and _same_key(previous, old):
            journal.remove(entry)


def _load_certificates_sync(path: Path) -> list[x509.Certificate]:
    content = path.read_bytes()
    if path.suffix.lower() == ".pem":
        return x509.load_pem_x509_certificates(content)
    return [x509.load_der_x509_certificate(content)]

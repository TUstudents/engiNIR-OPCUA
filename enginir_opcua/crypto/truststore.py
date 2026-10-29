"""
The stores a certificate validator decides over:
- trusted certificates (anchors, whether or not they are CA certificates)
- issuer certificates (CAs needed to build a chain, not anchors by themselves)
- certificate revocation lists, for all CAs or only for the trusted or only for the issuer CAs

A load builds a new immutable snapshot and installs it with one assignment.
"""

import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path

import anyio
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from enginir_opcua.crypto.cert_gen import write_atomic
from enginir_opcua.crypto.uacrypto import certificate_thumbprint, get_content
from enginir_opcua.ua.uaerrors import ConfigurationError

_logger = logging.getLogger(__name__)

CERTIFICATE_EXTENSIONS = frozenset({".der", ".cer", ".crt", ".pem"})
CRL_EXTENSIONS = frozenset({".crl", ".der", ".pem"})
DEFAULT_MAX_REJECTED = 100
DEFAULT_MAX_REJECTED_PER_PEER = 10


def _der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


@dataclass(frozen=True)
class StoreSnapshot:
    trusted: tuple[x509.Certificate, ...] = ()
    issuers: tuple[x509.Certificate, ...] = ()
    crls: tuple[x509.CertificateRevocationList, ...] = ()
    pinned: tuple[x509.Certificate, ...] = ()
    trusted_crls: tuple[x509.CertificateRevocationList, ...] = ()
    issuer_crls: tuple[x509.CertificateRevocationList, ...] = ()

    @property
    def has_revocation_lists(self) -> bool:
        return bool(self.crls or self.trusted_crls or self.issuer_crls)

    @cached_property
    def trusted_der(self) -> frozenset[bytes]:
        return frozenset(_der(certificate) for certificate in (*self.trusted, *self.pinned))

    def is_trusted(self, certificate: x509.Certificate) -> bool:
        return _der(certificate) in self.trusted_der


class TrustStore:
    """
    Locations of trusted certificates, issuer certificates and revocation lists.

    Each location is a directory. Certificates and lists are DER or PEM files. Files with other
    extensions are ignored, and a file that does not parse is skipped with a warning.
    """

    def __init__(
        self,
        trust_locations: Sequence[Path] = (),
        crl_locations: Sequence[Path] = (),
        issuer_locations: Sequence[Path] = (),
        *,
        trusted_crl_locations: Sequence[Path] = (),
        issuer_crl_locations: Sequence[Path] = (),
        rejected_location: Path | None = None,
        max_rejected: int = DEFAULT_MAX_REJECTED,
        max_rejected_per_peer: int = DEFAULT_MAX_REJECTED_PER_PEER,
    ) -> None:
        """
        Args:
            trust_locations: directories with trusted certificates (anchors).
            crl_locations: directories with certificate revocation lists, for trusted and issuer certificates.
            issuer_locations: directories with CA certificates needed for chains, which are not anchors.
            trusted_crl_locations: directories with revocation lists that only apply to trusted CA certificates.
            issuer_crl_locations: directories with revocation lists that only apply to issuer CA certificates.
            rejected_location: directory that receives the certificates of peers that failed validation, never read
                for validation.
            max_rejected: the most files kept in rejected_location. When it is exceeded the oldest file of the peer
                with the most files is removed.
            max_rejected_per_peer: the most files one peer address may keep in rejected_location.
        """
        self._trust_locations: list[Path] = [Path(location) for location in trust_locations]
        self._crl_locations: list[Path] = [Path(location) for location in crl_locations]
        self._issuer_locations: list[Path] = [Path(location) for location in issuer_locations]
        self._trusted_crl_locations: list[Path] = [Path(location) for location in trusted_crl_locations]
        self._issuer_crl_locations: list[Path] = [Path(location) for location in issuer_crl_locations]
        self._rejected_location: Path | None = Path(rejected_location) if rejected_location else None
        self._max_rejected = max_rejected
        self._max_rejected_per_peer = max_rejected_per_peer
        self._rejected_peers: dict[str, str] = {}
        self._rejected_lock = threading.Lock()
        self._snapshot = StoreSnapshot()
        self._pinned: tuple[x509.Certificate, ...] = ()

    @property
    def trust_locations(self) -> list[Path]:
        return self._trust_locations

    @property
    def crl_locations(self) -> list[Path]:
        return self._crl_locations

    @property
    def issuer_locations(self) -> list[Path]:
        return self._issuer_locations

    @property
    def trusted_crl_locations(self) -> list[Path]:
        return self._trusted_crl_locations

    @property
    def issuer_crl_locations(self) -> list[Path]:
        return self._issuer_crl_locations

    @property
    def rejected_location(self) -> Path | None:
        return self._rejected_location

    @property
    def max_rejected(self) -> int:
        return self._max_rejected

    @property
    def has_crl_locations(self) -> bool:
        return bool(self._crl_locations or self._trusted_crl_locations or self._issuer_crl_locations)

    @property
    def has_revocation_lists(self) -> bool:
        """True when revocation lists are configured explicitly or a PKI directory holds at least one."""
        return bool(self._crl_locations) or self._snapshot.has_revocation_lists

    @classmethod
    def from_pki_directory(
        cls,
        root: str | Path,
        *,
        max_rejected: int = DEFAULT_MAX_REJECTED,
        max_rejected_per_peer: int = DEFAULT_MAX_REJECTED_PER_PEER,
    ) -> "TrustStore":
        """
        A store over the folders of a PKI directory: trusted/certs and trusted/crl, issuer/certs and issuer/crl,
        and rejected/certs for the certificates that failed validation. trusted/certs has to exist. The other
        folders are used when they exist.
        """
        base = Path(root)
        issuer_certs, trusted_crl, issuer_crl, rejected = (
            base / "issuer" / "certs",
            base / "trusted" / "crl",
            base / "issuer" / "crl",
            base / "rejected" / "certs",
        )
        return cls(
            [base / "trusted" / "certs"],
            [],
            [issuer_certs] if issuer_certs.is_dir() else [],
            trusted_crl_locations=[trusted_crl] if trusted_crl.is_dir() else [],
            issuer_crl_locations=[issuer_crl] if issuer_crl.is_dir() else [],
            rejected_location=rejected if rejected.is_dir() else None,
            max_rejected=max_rejected,
            max_rejected_per_peer=max_rejected_per_peer,
        )

    def copy(self) -> "TrustStore":
        """A store with the same locations and the certificates of none: it has to be loaded."""
        return TrustStore(
            self._trust_locations,
            self._crl_locations,
            self._issuer_locations,
            trusted_crl_locations=self._trusted_crl_locations,
            issuer_crl_locations=self._issuer_crl_locations,
            rejected_location=self._rejected_location,
            max_rejected=self._max_rejected,
            max_rejected_per_peer=self._max_rejected_per_peer,
        )

    def record_rejected(self, certificates: Sequence[bytes], peer: str | None = None) -> None:
        """
        Keep DER certificates of a peer that was refused in the rejected location, one file per thumbprint and only
        when the file does not exist yet, the first of the sequence (the leaf) last. `peer` is the address the
        certificates came from: one peer keeps at most max_rejected_per_peer files, and when the folder is full the
        peer with the most files loses its oldest. Errors are logged.
        """
        location = self._rejected_location
        if location is None:
            return
        try:
            with self._rejected_lock:
                if not location.is_dir():
                    return
                for der in reversed(certificates):
                    name = f"{certificate_thumbprint(der).hex()}.der"
                    target = location / name
                    if not target.exists():
                        write_atomic(target, der, 0o644)
                        if peer is not None:
                            self._rejected_peers[name] = peer
                self._prune_rejected(location)
        except OSError as exc:
            _logger.warning("Could not keep a rejected certificate in %s: %s", location, exc)

    def _prune_rejected(self, location: Path) -> None:
        files = sorted(
            (entry for entry in location.iterdir() if entry.suffix == ".der" and entry.is_file()),
            key=lambda entry: (entry.stat().st_mtime_ns, entry.name),
        )
        groups: dict[str | None, list[Path]] = {}
        for entry in files:
            groups.setdefault(self._rejected_peers.get(entry.name), []).append(entry)
        for peer, entries in groups.items():
            if peer is not None:
                for entry in entries[: max(len(entries) - self._max_rejected_per_peer, 0)]:
                    entry.unlink(missing_ok=True)
                    self._rejected_peers.pop(entry.name, None)
                del entries[: max(len(entries) - self._max_rejected_per_peer, 0)]
        total = sum(len(entries) for entries in groups.values())
        while total > self._max_rejected:
            peer = max(
                (key for key in groups if groups[key]),
                key=lambda key: (len(groups[key]), -groups[key][0].stat().st_mtime_ns),
            )
            victim = groups[peer].pop(0)
            victim.unlink(missing_ok=True)
            self._rejected_peers.pop(victim.name, None)
            total -= 1

    @property
    def snapshot(self) -> StoreSnapshot:
        return self._snapshot

    def pin(self, certificate: x509.Certificate) -> None:
        """Trust a certificate given explicitly by the application, in memory only."""
        if certificate in self._pinned:
            return
        self._pinned = (*self._pinned, certificate)
        self._snapshot = replace(self._snapshot, pinned=self._pinned)

    async def load(self) -> None:
        """(Re)load the certificates and revocation lists, and replace the snapshot when all locations are readable."""
        trusted = await self._load_certificates(self._trust_locations)
        issuers = await self._load_certificates(self._issuer_locations)
        crls = await self._load_crls(self._crl_locations)
        trusted_crls = await self._load_crls(self._trusted_crl_locations)
        issuer_crls = await self._load_crls(self._issuer_crl_locations)
        self._snapshot = StoreSnapshot(
            tuple(trusted), tuple(issuers), tuple(crls), self._pinned, tuple(trusted_crls), tuple(issuer_crls)
        )

    @staticmethod
    async def _files(location: Path, extensions: frozenset[str]) -> list[Path]:
        if not await anyio.Path(location).is_dir():
            raise ConfigurationError(f"Trust store location {location} does not exist or is not a directory")
        names = [Path(entry) async for entry in anyio.Path(location).iterdir()]
        return sorted(name for name in names if name.suffix.lower() in extensions and name.is_file())

    async def _load_certificates(self, locations: Sequence[Path]) -> list[x509.Certificate]:
        certificates: list[x509.Certificate] = []
        for location in locations:
            for file_name in await self._files(location, CERTIFICATE_EXTENSIONS):
                try:
                    certificates.extend(await self._load_certificate_file(file_name))
                except (ValueError, OSError) as exc:
                    _logger.warning("Skipping %s, it does not hold a certificate: %s", file_name, exc)
        return certificates

    async def _load_crls(self, locations: Sequence[Path]) -> list[x509.CertificateRevocationList]:
        crls: list[x509.CertificateRevocationList] = []
        for location in locations:
            for file_name in await self._files(location, CRL_EXTENSIONS):
                try:
                    crls.append(await self._load_crl(file_name))
                except (ValueError, OSError) as exc:
                    _logger.warning("Skipping %s, it does not hold a revocation list: %s", file_name, exc)
        return crls

    @staticmethod
    async def _load_certificate_file(file_name: Path) -> list[x509.Certificate]:
        content = await get_content(file_name)
        if file_name.suffix.lower() == ".pem":
            return x509.load_pem_x509_certificates(content)
        return [x509.load_der_x509_certificate(content)]

    @staticmethod
    async def _load_crl(crl_file_name: Path) -> x509.CertificateRevocationList:
        content = await get_content(crl_file_name)
        if crl_file_name.suffix.lower() == ".pem":
            return x509.load_pem_x509_crl(content)
        return x509.load_der_x509_crl(content)

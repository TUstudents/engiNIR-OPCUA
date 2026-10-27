"""
Certificate validation for the peer of a secure channel.

One validator implements the steps of OPC 10000-4, 6.1.3 (Table 100) in their order. Each step has its own
StatusCode. Only the steps the table marks as suppressible can be suppressed, by name, and every suppression is
logged and reported in the outcome.
"""

import ipaddress
import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from enginir_opcua import ua
from enginir_opcua.crypto.security_policies import SecurityPolicy, SecurityPolicyNone, policy_class_for_uri
from enginir_opcua.crypto.truststore import StoreSnapshot, TrustStore
from enginir_opcua.crypto.uacrypto import split_certificate_chain
from enginir_opcua.ua.uaerrors import ConfigurationError, UaError, UaStatusCodeError

_logger = logging.getLogger(__name__)

ApplicationHook = Callable[[x509.Certificate, ua.ApplicationDescription], Awaitable[None]]
"""Extra check that runs after the validator accepted a certificate. It can only reject, by raising a ServiceError."""

DEFAULT_MAX_CHAIN_LENGTH = 10


class PeerRole(Enum):
    CLIENT = "client"
    SERVER = "server"
    USER = "user"


class Step(Enum):
    STRUCTURE = "structure"
    CHAIN = "chain"
    SIGNATURE = "signature"
    POLICY = "policy"
    TRUST = "trust"
    VALIDITY = "validity"
    HOST_NAME = "host_name"
    URI = "uri"
    USAGE = "usage"
    REVOCATION_LIST = "revocation_list"
    REVOCATION = "revocation"


class Suppression(Enum):
    """The errors of Table 100 that may be suppressed. The names follow OPC 10000-12, 7.8.2.10, Table 36."""

    CERTIFICATE_EXPIRED = "certificate_expired"
    ISSUER_CERTIFICATE_EXPIRED = "issuer_certificate_expired"
    HOST_NAME_INVALID = "host_name_invalid"
    REVOCATION_UNKNOWN = "revocation_unknown"
    ISSUER_REVOCATION_UNKNOWN = "issuer_revocation_unknown"
    POLICY_CHECK = "policy_check"
    USAGE = "usage"


@dataclass(frozen=True)
class ValidationContext:
    peer_role: PeerRole
    policy_uri: str | None = None
    expected_application_uri: str | None = None
    host_name: str | None = None


@dataclass(frozen=True)
class SuppressedError:
    step: Step
    status: int
    subject: str


@dataclass(frozen=True)
class Outcome:
    accepted: bool
    leaf: x509.Certificate | None = None
    suppressed: tuple[SuppressedError, ...] = ()
    status: int = ua.StatusCodes.Good
    step: Step | None = None
    subject: str = ""
    detail: str = ""

    def raise_for_status(self) -> None:
        if not self.accepted:
            raise UaStatusCodeError(self.status, self.detail)


class _Rejected(Exception):
    def __init__(self, status: int, step: Step, subject: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.step = step
        self.subject = subject
        self.detail = detail


def _subject(certificate: x509.Certificate) -> str:
    return certificate.subject.rfc4514_string() or f"serial {certificate.serial_number:x}"


def _der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def _is_self_issued(certificate: x509.Certificate) -> bool:
    return certificate.subject == certificate.issuer


def _extension[T: x509.ExtensionType](certificate: x509.Certificate, extension_type: type[T]) -> T | None:
    try:
        return certificate.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def _signed_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    public_key = issuer.public_key()
    hash_algorithm = certificate.signature_hash_algorithm
    if not isinstance(public_key, rsa.RSAPublicKey) or hash_algorithm is None:
        return False
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_algorithm_parameters,  # type: ignore[arg-type]
            hash_algorithm,
        )
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False
    return True


def _key_ids_match(issuer: x509.Certificate, authority_key_id: x509.AuthorityKeyIdentifier | None) -> bool:
    subject_key_id = _extension(issuer, x509.SubjectKeyIdentifier)
    if authority_key_id is None or authority_key_id.key_identifier is None or subject_key_id is None:
        return True
    return authority_key_id.key_identifier == subject_key_id.digest


def _is_ca(certificate: x509.Certificate) -> bool:
    constraints = _extension(certificate, x509.BasicConstraints)
    return constraints is not None and constraints.ca


def _host_matches(leaf: x509.Certificate, host_name: str) -> bool:
    alternative_names = _extension(leaf, x509.SubjectAlternativeName)
    if alternative_names is None:
        return False
    try:
        address = ipaddress.ip_address(host_name)
    except ValueError:
        wanted = host_name.casefold()
        return any(name.casefold() == wanted for name in alternative_names.get_values_for_type(x509.DNSName))
    return address in alternative_names.get_values_for_type(x509.IPAddress)


def _oneline(text: str) -> str:
    return " ".join(text.split())


class _Validation:
    def __init__(
        self, validator: "CertificateValidator", context: ValidationContext, snapshot: StoreSnapshot, now: datetime
    ) -> None:
        self.validator = validator
        self.context = context
        self.snapshot = snapshot
        self.now = now
        self.chain: list[x509.Certificate] = []
        self.suppressed: list[SuppressedError] = []

    def run(self, data: bytes) -> x509.Certificate:
        received = self.parse(data)
        self.check_structure(received)
        self.build_chain(received)
        self.check_signatures()
        self.check_policy()
        self.check_trust()
        self.check_validity()
        self.check_host_name()
        if self.context.expected_application_uri is not None:
            check_uri(self.chain[0], self.context.expected_application_uri)
        self.check_usage()
        self.check_revocation()
        return self.chain[0]

    def reject(self, status: int, step: Step, certificate: x509.Certificate | None, detail: str) -> _Rejected:
        subject = _subject(certificate) if certificate is not None else ""
        return _Rejected(status, step, subject, _oneline(detail))

    def fail_or_suppress(
        self,
        status: int,
        step: Step,
        certificate: x509.Certificate,
        detail: str,
        suppression: Suppression | None,
    ) -> None:
        if suppression is not None and suppression in self.validator.suppressions:
            _logger.warning(
                "Suppressed %s for certificate %s: %s (option %s)",
                ua.StatusCode(status).name,
                _subject(certificate),
                _oneline(detail),
                suppression.value,
            )
            self.suppressed.append(SuppressedError(step, status, _subject(certificate)))
            return
        raise self.reject(status, step, certificate, detail)

    def parse(self, data: bytes) -> list[x509.Certificate]:
        try:
            pieces = split_certificate_chain(bytes(data))
        except UaError as exc:
            raise self.reject(ua.StatusCodes.BadCertificateInvalid, Step.STRUCTURE, None, str(exc)) from exc
        if not pieces:
            raise self.reject(ua.StatusCodes.BadCertificateInvalid, Step.STRUCTURE, None, "No certificate was sent")
        if len(pieces) > self.validator.max_chain_length:
            raise self.reject(
                ua.StatusCodes.BadCertificateChainIncomplete,
                Step.CHAIN,
                None,
                f"The chain has {len(pieces)} certificates, at most {self.validator.max_chain_length} are accepted",
            )
        certificates: list[x509.Certificate] = []
        for piece in pieces:
            try:
                certificates.append(x509.load_der_x509_certificate(piece))
            except ValueError as exc:
                raise self.reject(
                    ua.StatusCodes.BadCertificateInvalid, Step.STRUCTURE, None, f"Certificate does not parse: {exc}"
                ) from exc
        return certificates

    def check_structure(self, received: list[x509.Certificate]) -> None:
        for index, certificate in enumerate(received):
            problem = self.structure_problem(certificate, index == 0)
            if problem:
                raise self.reject(ua.StatusCodes.BadCertificateInvalid, Step.STRUCTURE, certificate, problem)
        leaf = received[0]
        constraints = _extension(leaf, x509.BasicConstraints)
        if constraints is not None and constraints.ca:
            if self.context.peer_role is PeerRole.USER:
                raise self.reject(
                    ua.StatusCodes.BadCertificateInvalid,
                    Step.STRUCTURE,
                    leaf,
                    "The user certificate is marked as a CA (cA TRUE)",
                )
            self.check_ca_application_certificate(leaf)

    def structure_problem(self, certificate: x509.Certificate, is_leaf: bool) -> str | None:
        if certificate.version != x509.Version.v3:
            return "The certificate is not an X.509 version 3 certificate"
        if not isinstance(certificate.public_key(), rsa.RSAPublicKey):
            return "The certificate does not hold an RSA public key"
        if _extension(certificate, x509.BasicConstraints) is None:
            return "The certificate has no basic constraints extension"
        if not is_leaf or self.context.peer_role is PeerRole.USER:
            return None
        alternative_names = _extension(certificate, x509.SubjectAlternativeName)
        if alternative_names is None:
            return "The certificate has no subject alternative name extension"
        uris = alternative_names.get_values_for_type(x509.UniformResourceIdentifier)
        if not uris:
            return "The certificate has no application URI in its subject alternative name"
        if len(uris) > 1:
            _logger.warning(
                "Certificate %s has %d application URIs, it should have one", _subject(certificate), len(uris)
            )
        if not _is_self_issued(certificate) and _extension(certificate, x509.AuthorityKeyIdentifier) is None:
            return "The certificate is issued by a CA and has no authority key identifier"
        return None

    def check_ca_application_certificate(self, leaf: x509.Certificate) -> None:
        validator = self.validator
        if not validator.accept_ca_application_certificates:
            raise self.reject(
                ua.StatusCodes.BadCertificateInvalid,
                Step.STRUCTURE,
                leaf,
                "The application certificate is marked as a CA (cA TRUE) and such certificates are not accepted",
            )
        if not (validator.revocation_active or self.snapshot.is_trusted(leaf)):
            raise self.reject(
                ua.StatusCodes.BadCertificateInvalid,
                Step.STRUCTURE,
                leaf,
                "The application certificate is marked as a CA (cA TRUE), it is only accepted when it is trusted "
                "directly or revocation checking is on",
            )
        _logger.warning("Accepting application certificate %s although it is marked as a CA (cA TRUE)", _subject(leaf))

    def find_issuer(self, current: x509.Certificate, candidates: list[x509.Certificate]) -> x509.Certificate | None:
        authority_key_id = _extension(current, x509.AuthorityKeyIdentifier)
        in_chain = {_der(certificate) for certificate in self.chain}
        for candidate in candidates:
            if (
                candidate.subject == current.issuer
                and _der(candidate) not in in_chain
                and _is_ca(candidate)
                and _key_ids_match(candidate, authority_key_id)
                and _signed_by(current, candidate)
            ):
                return candidate
        return None

    def build_chain(self, received: list[x509.Certificate]) -> None:
        candidates = [*received[1:], *self.snapshot.issuers, *self.snapshot.trusted, *self.snapshot.pinned]
        self.chain = [received[0]]
        while True:
            current = self.chain[-1]
            if self.snapshot.is_trusted(current) or _is_self_issued(current):
                break
            issuer = self.find_issuer(current, candidates)
            if issuer is None:
                raise self.reject(
                    ua.StatusCodes.BadCertificateChainIncomplete,
                    Step.CHAIN,
                    current,
                    f"The issuer {current.issuer.rfc4514_string()} of the certificate is not known",
                )
            self.chain.append(issuer)
            if len(self.chain) > self.validator.max_chain_length:
                raise self.reject(
                    ua.StatusCodes.BadCertificateChainIncomplete,
                    Step.CHAIN,
                    current,
                    "The certificate chain is too long",
                )
        self.check_path_lengths()

    def check_path_lengths(self) -> None:
        for index in range(1, len(self.chain)):
            constraints = _extension(self.chain[index], x509.BasicConstraints)
            if constraints is None or constraints.path_length is None:
                continue
            below = sum(1 for certificate in self.chain[1:index] if not _is_self_issued(certificate))
            if below > constraints.path_length:
                raise self.reject(
                    ua.StatusCodes.BadCertificateChainIncomplete,
                    Step.CHAIN,
                    self.chain[index],
                    "The path length of the CA certificate is exceeded",
                )

    def check_signatures(self) -> None:
        for index, certificate in enumerate(self.chain):
            if index + 1 < len(self.chain):
                signer = self.chain[index + 1]
            elif _is_self_issued(certificate):
                signer = certificate
            else:
                continue
            if not _signed_by(certificate, signer):
                raise self.reject(
                    ua.StatusCodes.BadCertificateInvalid,
                    Step.SIGNATURE,
                    certificate,
                    "The signature of the certificate does not verify",
                )

    def check_policy(self) -> None:
        policy_uri = self.context.policy_uri
        if not policy_uri or policy_uri == SecurityPolicyNone.URI:
            return
        policy = policy_class_for_uri(policy_uri)
        for index, certificate in enumerate(self.chain):
            issuer = self.chain[index + 1] if index + 1 < len(self.chain) else None
            for problem in self.policy_problems(certificate, issuer, policy):
                self.fail_or_suppress(
                    ua.StatusCodes.BadCertificatePolicyCheckFailed,
                    Step.POLICY,
                    certificate,
                    problem,
                    Suppression.POLICY_CHECK,
                )

    @staticmethod
    def policy_problems(
        certificate: x509.Certificate, issuer: x509.Certificate | None, policy: type[SecurityPolicy] | None
    ) -> list[str]:
        if policy is None:
            return ["The SecurityPolicy is not known"]
        problems: list[str] = []
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            return ["The certificate does not hold an RSA public key"]
        bits = public_key.key_size
        if not policy.min_asymmetric_key_length <= bits <= policy.max_asymmetric_key_length:
            problems.append(
                f"The key has {bits} bits, the policy allows {policy.min_asymmetric_key_length} to "
                f"{policy.max_asymmetric_key_length}"
            )
        hash_algorithm = certificate.signature_hash_algorithm
        if hash_algorithm is None or hash_algorithm.name not in policy.certificate_hash_algorithms:
            problems.append(
                f"The certificate is signed with {hash_algorithm.name if hash_algorithm else 'an unknown hash'}, "
                f"the policy requires one of {', '.join(policy.certificate_hash_algorithms)}"
            )
        if not isinstance(certificate.signature_algorithm_parameters, padding.PKCS1v15):
            problems.append("The certificate is not signed with RSA PKCS#1 v1.5")
        issuer_key = issuer.public_key() if issuer is not None else None
        if isinstance(issuer_key, rsa.RSAPublicKey) and bits > issuer_key.key_size:
            problems.append("The key of the certificate is longer than the key of its issuer")
        return problems

    def check_trust(self) -> None:
        if any(self.snapshot.is_trusted(certificate) for certificate in self.chain):
            return
        end = self.chain[-1]
        if not self.snapshot.trusted and not self.snapshot.pinned:
            detail = (
                "No certificate is trusted because the trust store is empty; "
                "add the certificate to a trusted location of the trust store (set_trust_store)"
            )
        else:
            detail = f"The certificate {_subject(end)} and its issuers are not in the trusted list"
        raise self.reject(ua.StatusCodes.BadCertificateUntrusted, Step.TRUST, self.chain[0], detail)

    def check_validity(self) -> None:
        for index, certificate in enumerate(self.chain):
            if certificate.not_valid_before_utc <= self.now <= certificate.not_valid_after_utc:
                continue
            leaf = index == 0
            self.fail_or_suppress(
                ua.StatusCodes.BadCertificateTimeInvalid if leaf else ua.StatusCodes.BadCertificateIssuerTimeInvalid,
                Step.VALIDITY,
                certificate,
                f"The certificate is valid from {certificate.not_valid_before_utc} to {certificate.not_valid_after_utc}",
                Suppression.CERTIFICATE_EXPIRED if leaf else Suppression.ISSUER_CERTIFICATE_EXPIRED,
            )

    def check_host_name(self) -> None:
        host_name = self.context.host_name
        if self.context.peer_role is not PeerRole.SERVER or host_name is None:
            return
        if not _host_matches(self.chain[0], host_name):
            self.fail_or_suppress(
                ua.StatusCodes.BadCertificateHostNameInvalid,
                Step.HOST_NAME,
                self.chain[0],
                f"The host name {host_name} is not in the subject alternative name of the certificate",
                Suppression.HOST_NAME_INVALID,
            )

    def check_usage(self) -> None:
        for index, certificate in enumerate(self.chain):
            leaf = index == 0
            for problem, critical in self.usage_problems(certificate, leaf):
                self.fail_or_suppress(
                    ua.StatusCodes.BadCertificateUseNotAllowed
                    if leaf
                    else ua.StatusCodes.BadCertificateIssuerUseNotAllowed,
                    Step.USAGE,
                    certificate,
                    problem,
                    None if critical else Suppression.USAGE,
                )

    def usage_problems(self, certificate: x509.Certificate, leaf: bool) -> list[tuple[str, bool]]:
        key_usage_extension = certificate.extensions
        try:
            key_usage_entry = key_usage_extension.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound:
            return [("The certificate has no key usage extension", False)]
        key_usage = key_usage_entry.value
        critical = key_usage_entry.critical
        if not leaf:
            return [] if key_usage.key_cert_sign else [("The CA certificate may not sign certificates", critical)]
        problems: list[tuple[str, bool]] = []
        if self.context.peer_role is PeerRole.USER:
            if not key_usage.digital_signature:
                problems.append(("The key usage of the certificate lacks digitalSignature", critical))
            return problems
        for name, allowed in (
            ("digitalSignature", key_usage.digital_signature),
            ("nonRepudiation", key_usage.content_commitment),
            ("keyEncipherment", key_usage.key_encipherment),
            ("dataEncipherment", key_usage.data_encipherment),
        ):
            if not allowed:
                problems.append((f"The key usage of the certificate lacks {name}", critical))
        extended = _extension(certificate, x509.ExtendedKeyUsage)
        wanted = (
            ExtendedKeyUsageOID.SERVER_AUTH
            if self.context.peer_role is PeerRole.SERVER
            else ExtendedKeyUsageOID.CLIENT_AUTH
        )
        if extended is None or wanted not in extended:
            problems.append((f"The extended key usage of the certificate lacks {wanted._name}", False))
        return problems

    def matching_crls(
        self, certificate: x509.Certificate, issuer: x509.Certificate
    ) -> list[x509.CertificateRevocationList]:
        authority_key_id = None
        matches: list[x509.CertificateRevocationList] = []
        for crl in self.snapshot.crls:
            if crl.issuer != certificate.issuer or _extension_of_crl(crl, x509.DeltaCRLIndicator) is not None:
                continue
            authority_key_id = _extension_of_crl(crl, x509.AuthorityKeyIdentifier)
            if not _key_ids_match(issuer, authority_key_id):
                continue
            issuer_key = issuer.public_key()
            if not isinstance(issuer_key, rsa.RSAPublicKey) or not crl.is_signature_valid(issuer_key):
                _logger.warning(
                    "Ignoring a revocation list of %s: its signature does not verify", crl.issuer.rfc4514_string()
                )
                continue
            next_update = crl.next_update_utc
            if crl.last_update_utc <= self.now and (next_update is None or self.now <= next_update):
                matches.append(crl)
        return matches

    def check_revocation(self) -> None:
        if not self.validator.revocation_active:
            return
        found: dict[int, list[x509.CertificateRevocationList]] = {}
        for index, certificate in enumerate(self.chain):
            if index + 1 >= len(self.chain) or _is_self_issued(certificate):
                continue
            crls = self.matching_crls(certificate, self.chain[index + 1])
            if crls:
                found[index] = crls
                continue
            leaf = index == 0
            self.fail_or_suppress(
                ua.StatusCodes.BadCertificateRevocationUnknown
                if leaf
                else ua.StatusCodes.BadCertificateIssuerRevocationUnknown,
                Step.REVOCATION_LIST,
                certificate,
                f"No current revocation list of {certificate.issuer.rfc4514_string()} was found",
                Suppression.REVOCATION_UNKNOWN if leaf else Suppression.ISSUER_REVOCATION_UNKNOWN,
            )
        for index, crls in found.items():
            certificate = self.chain[index]
            if any(crl.get_revoked_certificate_by_serial_number(certificate.serial_number) for crl in crls):
                raise self.reject(
                    ua.StatusCodes.BadCertificateRevoked if index == 0 else ua.StatusCodes.BadCertificateIssuerRevoked,
                    Step.REVOCATION,
                    certificate,
                    f"The certificate with serial number {certificate.serial_number:x} is revoked",
                )


def _extension_of_crl[T: x509.ExtensionType](crl: x509.CertificateRevocationList, extension_type: type[T]) -> T | None:
    try:
        return crl.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def check_uri(leaf: x509.Certificate, application_uri: str) -> None:
    alternative_names = _extension(leaf, x509.SubjectAlternativeName)
    uris = alternative_names.get_values_for_type(x509.UniformResourceIdentifier) if alternative_names else []
    if application_uri not in uris:
        raise _Rejected(
            ua.StatusCodes.BadCertificateUriInvalid,
            Step.URI,
            _subject(leaf),
            f"The application URI {application_uri} is not in the subject alternative name of the certificate",
        )


def _rejected(rejection: _Rejected, suppressed: tuple[SuppressedError, ...]) -> Outcome:
    _logger.warning(
        "Rejected certificate %s: %s at step %s: %s",
        rejection.subject or "(unparsed)",
        ua.StatusCode(rejection.status).name,
        rejection.step.value,
        rejection.detail,
    )
    return Outcome(False, None, suppressed, rejection.status, rejection.step, rejection.subject, rejection.detail)


def check_application_uri(certificate: x509.Certificate, application_uri: str) -> Outcome:
    try:
        check_uri(certificate, application_uri)
    except _Rejected as rejection:
        return _rejected(rejection, ())
    return Outcome(True, certificate)


class CertificateValidator:
    """
    Validates the certificate chain of a peer against a trust store, as Table 100 of OPC 10000-4, 6.1.3 prescribes.

    The validator never raises for a bad certificate: it returns a rejected Outcome with the StatusCode of the failing
    step. Mistakes in the configuration raise ConfigurationError when the validator is built.
    """

    def __init__(
        self,
        trust_store: TrustStore,
        *,
        suppress: Iterable[Suppression | str] = (),
        check_revocation: bool | None = None,
        accept_ca_application_certificates: bool = True,
        max_chain_length: int = DEFAULT_MAX_CHAIN_LENGTH,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """
        Args:
            trust_store: the trusted, issuer and revocation lists. It has to be loaded before the first validation.
            suppress: errors to accept, by name (see Suppression); asking for any other step is a ConfigurationError.
            check_revocation: None checks revocation when the trust store has a CRL location, True requires a
                CRL location, False turns the revocation steps off.
            accept_ca_application_certificates: accept application certificates marked cA TRUE (Part 6, 6.2.2).
            max_chain_length: the longest certificate chain that is accepted.
            clock: the current time in UTC, for tests.
        """
        if trust_store is None:
            raise ConfigurationError(
                "A certificate validator needs a trust store; without one nothing can be trusted. "
                "Configure the trust store of the server or client (set_trust_store)"
            )
        self._trust_store = trust_store
        self.suppressions: frozenset[Suppression] = frozenset(self._suppression(item) for item in suppress)
        if check_revocation and not trust_store.crl_locations:
            raise ConfigurationError("Revocation checking needs at least one crl location in the trust store")
        self.revocation_active: bool = bool(trust_store.crl_locations) if check_revocation is None else check_revocation
        if not self.revocation_active:
            _logger.warning("Revocation of certificates is not checked: no crl location is configured")
        self.accept_ca_application_certificates = accept_ca_application_certificates
        self.max_chain_length = max_chain_length
        self._clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def _suppression(item: Suppression | str) -> Suppression:
        try:
            return Suppression(item)
        except ValueError as exc:
            names = ", ".join(suppression.value for suppression in Suppression)
            raise ConfigurationError(f"The step {item!r} cannot be suppressed; only these can: {names}") from exc

    @property
    def trust_store(self) -> TrustStore:
        return self._trust_store

    def validate_application_certificate(self, chain: bytes, context: ValidationContext) -> Outcome:
        """Validate the certificate a peer sent, followed by any intermediate CA certificates it appended."""
        validation = _Validation(self, context, self._trust_store.snapshot, self._clock())
        try:
            leaf = validation.run(chain)
        except _Rejected as rejection:
            return self._rejected(rejection, tuple(validation.suppressed))
        return Outcome(True, leaf, tuple(validation.suppressed))

    def validate_user_certificate(self, chain: bytes, policy_uri: str | None) -> Outcome:
        """
        Validate the certificate of an X509 identity token, followed by any intermediate CA certificates, against
        the trust store of this validator (the user trust list). The application URI and host name steps are
        skipped and only digitalSignature is required of the key usage (Part 6, 6.2.3).
        """
        return self.validate_application_certificate(chain, ValidationContext(PeerRole.USER, policy_uri))

    def check_application_uri(self, certificate: x509.Certificate, application_uri: str) -> Outcome:
        """Check that the certificate holds the ApplicationUri of the application description."""
        return check_application_uri(certificate, application_uri)

    @staticmethod
    def _rejected(rejection: _Rejected, suppressed: tuple[SuppressedError, ...]) -> Outcome:
        return _rejected(rejection, suppressed)

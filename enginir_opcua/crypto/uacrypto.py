import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import anyio
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..ua.uaerrors import DecryptionError, SignatureError, UaError

_logger = logging.getLogger(__name__)


@dataclass
class CertProperties:
    path_or_content: bytes | Path | str
    extension: str | None = None
    password: str | bytes | None = None


async def get_content(path_or_content: str | bytes | Path) -> bytes:
    if isinstance(path_or_content, bytes):
        return path_or_content

    async with await anyio.open_file(path_or_content, mode="rb") as f:
        return await f.read()


def _is_pem_format(path_or_content: bytes | str | Path, extension: str | None) -> bool:
    """Determine if the content should be loaded as PEM format.

    If an explicit extension is provided, it takes precedence over
    the file extension inferred from the path.
    """
    if extension is not None:
        return extension.lower() == "pem"
    if isinstance(path_or_content, str):
        return Path(path_or_content).suffix.lower() == ".pem"
    if isinstance(path_or_content, Path):
        return path_or_content.suffix.lower() == ".pem"
    return False


async def load_certificate(path_or_content: bytes | str | Path, extension: str | None = None) -> x509.Certificate:
    content = await get_content(path_or_content)
    if _is_pem_format(path_or_content, extension):
        return x509.load_pem_x509_certificate(content, default_backend())
    return x509.load_der_x509_certificate(content, default_backend())


DER_SEQUENCE_TAG = 0x30
MAX_DER_LENGTH_BYTES = 4


def _der_sequence_size(data: bytes, offset: int) -> int:
    if offset + 2 > len(data) or data[offset] != DER_SEQUENCE_TAG:
        raise UaError("Certificate data does not start with a DER sequence")
    length_byte = data[offset + 1]
    if length_byte < 0x80:
        header_size, content_size = 2, length_byte
    else:
        length_size = length_byte & 0x7F
        if not 0 < length_size <= MAX_DER_LENGTH_BYTES or offset + 2 + length_size > len(data):
            raise UaError("Certificate data has a malformed DER length")
        header_size = 2 + length_size
        content_size = int.from_bytes(data[offset + 2 : offset + header_size], "big")
    size = header_size + content_size
    if offset + size > len(data):
        raise UaError("Certificate data is shorter than its DER length")
    return size


def split_certificate_chain(data: bytes) -> list[bytes]:
    """Split concatenated DER certificates, leaf first. Raises UaError on malformed input."""
    certificates: list[bytes] = []
    offset = 0
    while offset < len(data):
        size = _der_sequence_size(data, offset)
        certificates.append(data[offset : offset + size])
        offset += size
    return certificates


def x509_from_der(data: bytes | None) -> x509.Certificate | None:
    """Load the leaf certificate of DER data that may hold a chain. None for empty data, UaError if malformed."""
    if not data:
        return None
    leaf = data[: _der_sequence_size(data, 0)]
    try:
        return x509.load_der_x509_certificate(leaf, default_backend())
    except ValueError as exc:
        raise UaError("Malformed DER certificate") from exc


async def load_private_key(
    path_or_content: str | Path | bytes,
    password: str | bytes | None = None,
    extension: str | None = None,
) -> PrivateKeyTypes:
    if isinstance(password, str):
        password = password.encode("utf-8")

    content = await get_content(path_or_content)
    if _is_pem_format(path_or_content, extension):
        return serialization.load_pem_private_key(content, password=password, backend=default_backend())
    return serialization.load_der_private_key(content, password=password, backend=default_backend())


def der_from_x509(certificate: x509.Certificate | None) -> bytes:
    if certificate is None:
        return b""
    return certificate.public_bytes(serialization.Encoding.DER)


def pem_from_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """dumps a private key in PEM format

    Args:
        private_key (rsa.RSAPrivateKey): The privatekey to dump

    Returns:
        bytes: The private as PEM/PKCS8 format
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def sign_sha1(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())


def sign_sha256(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def sign_pss_sha256(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def _verify(
    certificate: x509.Certificate,
    data: bytes,
    signature: bytes,
    rsa_padding: padding.AsymmetricPadding,
    algorithm: hashes.HashAlgorithm,
) -> None:
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SignatureError("certificate does not hold an RSA public key")
    try:
        public_key.verify(signature, data, rsa_padding, algorithm)
    except InvalidSignature as exc:
        raise SignatureError("signature does not match the data") from exc


def verify_sha1(certificate: x509.Certificate, data: bytes, signature: bytes) -> None:
    _verify(certificate, data, signature, padding.PKCS1v15(), hashes.SHA1())


def verify_sha256(certificate: x509.Certificate, data: bytes, signature: bytes) -> None:
    _verify(certificate, data, signature, padding.PKCS1v15(), hashes.SHA256())


def verify_pss_sha256(certificate: x509.Certificate, data: bytes, signature: bytes) -> None:
    _verify(
        certificate,
        data,
        signature,
        padding.PSS(mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def encrypt_rsa_oaep(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    )
    return ciphertext


def encrypt_rsa_oaep_sha256(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return ciphertext


def encrypt_rsa15(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    ciphertext = public_key.encrypt(data, padding.PKCS1v15())
    return ciphertext


def _decrypt_rsa(private_key: rsa.RSAPrivateKey, data: bytes, rsa_padding: padding.AsymmetricPadding) -> bytes:
    try:
        return private_key.decrypt(bytes(data), rsa_padding)
    except ValueError as exc:
        raise DecryptionError("RSA decryption failed") from exc


def decrypt_rsa_oaep(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return _decrypt_rsa(
        private_key, data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    )


def decrypt_rsa_oaep_sha256(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return _decrypt_rsa(
        private_key,
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def decrypt_rsa15(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return _decrypt_rsa(private_key, data, padding.PKCS1v15())


def cipher_aes_cbc(key: bytes, init_vec: bytes) -> Cipher[modes.CBC]:
    return Cipher(algorithms.AES(key), modes.CBC(init_vec), default_backend())


def cipher_encrypt(cipher: Cipher[modes.CBC], data: bytes) -> bytes:
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def cipher_decrypt(cipher: Cipher[modes.CBC], data: bytes) -> bytes:
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(data) + decryptor.finalize()
    except ValueError as exc:
        raise DecryptionError("AES decryption failed") from exc


def hmac_sha1(key: bytes, message: bytes) -> bytes:
    hasher = hmac.HMAC(key, hashes.SHA1(), backend=default_backend())
    hasher.update(message)
    return hasher.finalize()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    hasher = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hasher.update(message)
    return hasher.finalize()


def sha1_size() -> int:
    return hashes.SHA1.digest_size


def sha256_size() -> int:
    return hashes.SHA256.digest_size


def p_sha1(secret: bytes, seed: bytes, sizes: tuple[int, ...] = ()) -> tuple[bytes, ...]:
    """
    Derive one or more keys from secret and seed.
    (See specs part 6, 6.7.5 and RFC 2246 - TLS v1.0)
    Lengths of keys will match sizes argument
    """
    full_size = 0
    for size in sizes:
        full_size += size

    result = b""
    accum = seed
    while len(result) < full_size:
        accum = hmac_sha1(secret, accum)
        result += hmac_sha1(secret, accum + seed)

    parts = []
    for size in sizes:
        parts.append(result[:size])
        result = result[size:]
    return tuple(parts)


def p_sha256(secret: bytes, seed: bytes, sizes: tuple[int, ...] = ()) -> tuple[bytes, ...]:
    """
    Derive one or more keys from secret and seed.
    (See specs part 6, 6.7.5 and RFC 2246 - TLS v1.0)
    Lengths of keys will match sizes argument
    """
    full_size = 0
    for size in sizes:
        full_size += size

    result = b""
    accum = seed
    while len(result) < full_size:
        accum = hmac_sha256(secret, accum)
        result += hmac_sha256(secret, accum + seed)

    parts = []
    for size in sizes:
        parts.append(result[:size])
        result = result[size:]
    return tuple(parts)


def x509_name_to_string(name: x509.Name) -> str:
    parts = [f"{attr.oid._name}={attr.value!s}" for attr in name]
    return ", ".join(parts)


def x509_to_string(cert: x509.Certificate) -> str:
    """
    Convert x509 certificate to human-readable string
    """
    if cert.subject == cert.issuer:
        issuer = " (self-signed)"
    else:
        issuer = f", issuer: {x509_name_to_string(cert.issuer)}"
    return f"{x509_name_to_string(cert.subject)}{issuer}, {cert.not_valid_before_utc} - {cert.not_valid_after_utc}"


def check_certificate(cert: x509.Certificate, application_uri: str, hostname: str | None = None) -> list[str]:
    """Log and return the problems of a certificate for an application URI and host name. Empty when it is fine."""
    problems: list[str] = []
    now = datetime.now(UTC)
    if cert.not_valid_after_utc < now:
        problems.append(f"certificate is no longer valid: valid until {cert.not_valid_after_utc}")
        _logger.error("certificate is no longer valid: valid until %s", cert.not_valid_after_utc)
    if cert.not_valid_before_utc > now:
        problems.append(f"certificate is not yet valid: valid after {cert.not_valid_before_utc}")
        _logger.error("certificate is not yet valid: valid after %s", cert.not_valid_before_utc)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_uri = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if application_uri not in san_uri:
            problems.append(f"certificate does not contain the application uri ({application_uri})")
            _logger.warning(
                "certificate does not contain the application uri (%s). "
                "Most applications will reject a connection without it.",
                application_uri,
            )
        if hostname is not None:
            san_dns_names = [name.casefold() for name in san.value.get_values_for_type(x509.DNSName)]
            if hostname.casefold() not in san_dns_names:
                problems.append(f"certificate does not contain the hostname {hostname} in DNSNames")
                _logger.warning(
                    "certificate does not contain the hostname in DNSNames %s. Some applications will check this.",
                    hostname,
                )
    except x509.ExtensionNotFound:
        problems.append("certificate has no SubjectAlternativeName")
        _logger.warning("certificate has no SubjectAlternativeName, which is needed for application verification!")
    return problems

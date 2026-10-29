"""
crypothelper contains helper functions to isolate the lower level cryto stuff from the GDS client.
"""

import datetime
import logging
import os
import secrets
from pathlib import Path

import anyio
from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES as OID_NAMES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.extensions import _key_identifier_from_public_key as key_identifier_from_public_key
from cryptography.x509.oid import NameOID

from enginir_opcua.crypto.uacrypto import check_certificate, load_certificate, load_private_key

_logger = logging.getLogger(__name__)

ONE_DAY = datetime.timedelta(1, 0, 0)
""" Shorthand for delta of 1 day """

OID_NAME_MAP: dict[str, x509.ObjectIdentifier] = {name: oid for oid, name in OID_NAMES.items()}
""" Create lookup table for x509.ObjectIdentifier based on textual name, by swapping key<>value of the available mapping"""


def _names_to_nameattributes(names: dict[str, str]) -> list[x509.NameAttribute]:
    """Convert a dict with key/value of an x509.NameAttribute list

    Args:
        names (dict[str,str]): key is the textual name of a NameOID, value is the of the attribute

    Returns:
        list[x509.NameAttribute]: Coverted list with NameAttributes
    """
    return [x509.NameAttribute(OID_NAME_MAP[key], value) for key, value in names.items()]


def generate_private_key() -> rsa.RSAPrivateKey:
    """Generate a private key for certifacte signing and requesting

    Returns:
        rsa.RSAPrivateKey: The generated private key
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return private_key


def dump_private_key_as_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """dumps a private key in PEM format

    Args:
        private_key (rsa.RSAPrivateKey): The privatekey to dump

    Returns:
        bytes: The private as PEM/PKCS8 format
    """
    return private_key.private_bytes(
        encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )


def generate_self_signed_app_certificate(
    private_key: rsa.RSAPrivateKey,
    common_name: str,
    names: dict[str, str],
    subject_alt_names: list[x509.GeneralName],
    extended: list[x509.ObjectIdentifier],
    days: int = 365,
) -> x509.Certificate:
    """Generate a self signed certificate for OPC UA client/server application that is according to OPC 10000-4 6.1 / OPC 10000-6 6.2.2

    Args:
        private_key (rsa.RSAPrivateKey): private key used to sign the certificate
        common_name (str): common name (CN) for the subject, matches to the applications name
        names (dict[str,str]): additional fields (like O,C,L) for the subject
        subject_alt_names (list[x509.GeneralName]): uri,dns ip entires
        extended (list[x509.ObjectIdentifier]): Indicates use of certificate (ExtendedKeyUsageOID.CLIENT_AUTH and/or ExtendedKeyUsageOID.SERVER_AUTH).
                                                When empty assumes to generate a CA
        days (int, optional): How long the certificate is valid. Defaults to 365.

    Returns:
        x509.Certificate: The generated certificate.
    """
    generate_ca = len(extended) == 0
    name_attributes: list[x509.NameAttribute] = _names_to_nameattributes(names)
    name_attributes.insert(0, x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    public_key = private_key.public_key()
    serial_number: int = x509.random_serial_number()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name(name_attributes))
    builder = builder.issuer_name(x509.Name(name_attributes))
    builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + (ONE_DAY * days))
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier_from_public_key(private_key.public_key()),
            [x509.DirectoryName(x509.Name(name_attributes))],
            serial_number,
        ),
        critical=False,
    )
    builder = builder.add_extension(x509.SubjectAlternativeName(subject_alt_names), critical=False)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=generate_ca, path_length=0 if generate_ca else None), critical=False
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=not (generate_ca),
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=generate_ca,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )
    if not generate_ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage(extended), critical=False)

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    return certificate


def generate_app_certificate_signing_request(
    private_key: rsa.RSAPrivateKey,
    common_name: str,
    names: dict[str, str],
    subject_alt_names: list[x509.GeneralName],
    extended: list[x509.ObjectIdentifier],
) -> x509.CertificateSigningRequest:
    """Generate a certificate signing request for a OPC UA client/server application that is according to OPC 10000-4 6.1 / OPC 10000-6 6.2.2

    Args:
        private_key (rsa.RSAPrivateKey): private key used to sign the certificate
        common_name (str): common name (CN) for the subject, matches to the applications name
        names (dict[str,str]): additional fields (like O,C,L) for the subject
        subject_alt_names (list[x509.GeneralName]): uri,dns ip entires
        extended (list[x509.ObjectIdentifier]): Indicates use of certificate (ExtendedKeyUsageOID.CLIENT_AUTH and/or ExtendedKeyUsageOID.SERVER_AUTH)

    Returns:
        x509.CertificateSigningRequest: The generated certificate signing request
    """

    name_attributes: list[x509.NameAttribute] = _names_to_nameattributes(names)
    name_attributes.insert(0, x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return generate_signing_request(private_key, x509.Name(name_attributes), subject_alt_names, extended)


SUBJECT_NAME_OIDS: dict[str, x509.ObjectIdentifier] = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "DC": NameOID.DOMAIN_COMPONENT,
    "L": NameOID.LOCALITY_NAME,
    "S": NameOID.STATE_OR_PROVINCE_NAME,
    "C": NameOID.COUNTRY_NAME,
}


def parse_subject_name(text: str) -> x509.Name:
    """
    Parse the subject of OPC 10000-12, 7.9.4: name=value pairs separated by "/", with the names CN, O, OU, DC, L, S
    or C; a value that holds "/" or "=" is enclosed in double quotes.
    :raises ValueError: for anything else
    """
    pairs: list[str] = []
    current: list[str] = []
    quoted = False
    for character in text:
        if character == '"':
            quoted = not quoted
            current.append(character)
        elif character == "/" and not quoted:
            pairs.append("".join(current))
            current = []
        else:
            current.append(character)
    if quoted:
        raise ValueError("unterminated quote in the subject name")
    pairs.append("".join(current))
    attributes: list[x509.NameAttribute] = []
    for pair in pairs:
        if not pair:
            continue
        name, separator, value = pair.partition("=")
        oid = SUBJECT_NAME_OIDS.get(name.strip())
        if not separator or oid is None:
            raise ValueError(f"{pair!r} is not a name=value pair with a known name")
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if not value:
            raise ValueError(f"the value of {name} is empty")
        attributes.append(x509.NameAttribute(oid, value))
    if not attributes:
        raise ValueError("the subject name is empty")
    return x509.Name(attributes)


def generate_signing_request(
    private_key: rsa.RSAPrivateKey,
    subject: x509.Name,
    subject_alt_names: list[x509.GeneralName],
    extended: list[x509.ObjectIdentifier],
) -> x509.CertificateSigningRequest:
    """A certificate signing request for an application with the SAN, key usage and extended key usage of OPC 10000-6, 6.2.2."""
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    builder = builder.add_extension(x509.SubjectAlternativeName(subject_alt_names), critical=False)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=False,
    )

    builder = builder.add_extension(x509.ExtendedKeyUsage(extended), critical=False)
    csr = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    return csr


def sign_certificate_request(
    csr: x509.CertificateSigningRequest, issuer: x509.Certificate, private_key: rsa.RSAPrivateKey, days=365
) -> x509.Certificate:
    """Create certficate based on certificate signing request and ca

    Args:
        csr (x509.CertificateSigningRequest): certificate signing request
        issuer (x509.Certificate): certificate used a CA
        private_key (rsa.RSAPrivateKey): private key of the issuer
        days (int, optional): Days valid. Defaults to 365.

    Returns:
        x509.Certificate: Signed certificate
    """
    public_key = csr.public_key()
    serial_number: int = x509.random_serial_number()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(issuer.subject)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + (ONE_DAY * days))
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier_from_public_key(issuer.public_key()),
            [x509.DirectoryName(issuer.subject)],
            issuer.serial_number,
        ),
        critical=False,
    )
    builder = builder.add_extension(
        csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical=False
    )
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
    builder = builder.add_extension(csr.extensions.get_extension_for_class(x509.KeyUsage).value, critical=False)
    builder = builder.add_extension(csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value, critical=False)

    certificate: x509.Certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    return certificate


def write_atomic(path: Path, data: bytes, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


async def write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    """Write a private key as unencrypted PKCS8 PEM that only its owner can read, with a rename at the end."""
    await anyio.to_thread.run_sync(write_atomic, path, dump_private_key_as_pem(private_key), 0o600)


async def write_certificate(path: Path, certificate: x509.Certificate) -> None:
    """Write a certificate as DER with a rename at the end."""
    await anyio.to_thread.run_sync(write_atomic, path, certificate.public_bytes(Encoding.DER), 0o644)


def _generated_by_setup(certificate: x509.Certificate, app_uri: str) -> bool:
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return certificate.subject == certificate.issuer and any(name.value == app_uri for name in common_names)


async def setup_self_signed_certificate(
    key_file: Path,
    cert_file: Path,
    app_uri: str,
    host_name: str,
    cert_use: list[x509.ObjectIdentifier],
    subject_attrs: dict[str, str],
):
    """Convenient helper for generating a key and or basic certificate if needed:
    - The key/certificate doesn't exists (when key is missing, the certificate is generated again)
    - The certificate was generated by this function and no longer fits

    A certificate that this function did not generate, and any certificate issued by a CA, is never replaced:
    the problems found are logged and the files stay as they are. The key is written readable by its owner only.

    The certificate is generated to be valid for one year.

    Args:
        key_file (Path): file with should contain key in PEM format
        cert_file (Path): file that should contains the certificate in DER formar
        app_uri (str): app uri for client or server
        host_name (str): hostname used in certificate sub alternative names
        cert_use (list[x509.ObjectIdentifier]): constains the use of the cert (ExtendedKeyUsageOID.CLIENT_AUTH and or ExtendedKeyUsageOID.SERVER_AUTH)
        subject_attrs (dict[str, str]): subject fields
    """
    key_exists = await anyio.Path(key_file).is_file()
    cert_exists = await anyio.Path(cert_file).is_file()

    existing: x509.Certificate | None = None
    if cert_exists:
        existing = await load_certificate(cert_file)
        if not _generated_by_setup(existing, app_uri):
            problems = check_certificate(existing, app_uri, host_name)
            _logger.warning(
                "Keeping the certificate %s, it was not generated here%s",
                cert_file,
                f": {'; '.join(problems)}" if problems else "",
            )
            return

    generate_cert = not key_exists or existing is None
    key: RSAPrivateKey
    if key_exists:
        key = await load_private_key(key_file)
    else:
        key = generate_private_key()
        await write_private_key(key_file, key)

    if existing is not None and not generate_cert:
        problems = check_certificate(existing, app_uri, host_name)
        generate_cert = bool(problems)
        if generate_cert:
            _logger.warning("Replacing the certificate %s that was generated here: %s", cert_file, "; ".join(problems))

    if generate_cert:
        subject_alt_names: list[x509.GeneralName] = [
            x509.UniformResourceIdentifier(app_uri),
            x509.DNSName(f"{host_name}"),
        ]

        cert = generate_self_signed_app_certificate(
            key, app_uri, subject_attrs, subject_alt_names, extended=cert_use, days=365
        )
        await write_certificate(cert_file, cert)

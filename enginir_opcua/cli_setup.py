"""
The commands of the quick setup: init, trust, pki list, pair and user add|list|remove (see docs/usage/quick-setup.rst).
"""

import argparse
import asyncio
import dataclasses
import getpass
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509

from enginir_opcua.config import (
    ClientConfig,
    ServerConfig,
    default_application_uri,
)
from enginir_opcua.crypto import cert_gen, pki, users_file
from enginir_opcua.crypto.truststore import CERTIFICATE_EXTENSIONS, TrustStore
from enginir_opcua.crypto.uacrypto import certificate_thumbprint
from enginir_opcua.tools import Command, ToolError, UsageError, register, say, warn

DEFAULT_PKI = "./pki"
MIN_THUMBPRINT_DIGITS = 8
SUBJECT_WIDTH = 60
PAIR_WARNING = (
    "warning: pair makes both applications trust each other's certificate without anyone checking who holds the "
    "key. Use it for development on one machine only; on a network exchange the certificates yourself and use "
    "enginir-opcua trust"
)


def cert_gen_der(certificate: x509.Certificate) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return certificate.public_bytes(Encoding.DER)


def _thumbprint(certificate: x509.Certificate) -> str:
    return certificate_thumbprint(cert_gen_der(certificate)).hex()


def _subject(certificate: x509.Certificate) -> str:
    return certificate.subject.rfc4514_string() or f"serial {certificate.serial_number:x}"


def _expiry(certificate: x509.Certificate) -> str:
    now = datetime.now(UTC)
    date = f"{certificate.not_valid_after_utc:%Y-%m-%d}"
    if certificate.not_valid_after_utc < now:
        return f"EXPIRED {date}"
    if certificate.not_valid_before_utc > now:
        return f"NOT YET VALID {certificate.not_valid_before_utc:%Y-%m-%d}"
    return date


def _load_certificate_file(path: Path) -> x509.Certificate:
    content = path.read_bytes()
    try:
        if content.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(content)
        return x509.load_der_x509_certificate(content)
    except ValueError:
        raise ToolError(f"{path} is not a certificate") from None


def _pki_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pki", default=DEFAULT_PKI, metavar="DIR", help=f"PKI directory. Default: {DEFAULT_PKI}")


def _require_pki(directory: Path) -> Path:
    if not (directory / "trusted" / "certs").is_dir():
        raise ToolError(f"{directory} is not a PKI directory; create one with enginir-opcua init")
    return directory


def _certificates(folder: Path) -> list[tuple[Path, x509.Certificate]]:
    found: list[tuple[Path, x509.Certificate]] = []
    if not folder.is_dir():
        return found
    for entry in sorted(folder.iterdir()):
        if (entry.name.startswith(".") and entry.suffix == ".tmp") or not entry.is_file():
            continue
        if entry.suffix.lower() not in CERTIFICATE_EXTENSIONS:
            continue
        try:
            found.append((entry, _load_certificate_file(entry)))
        except (ToolError, OSError):
            warn(f"warning: {entry} does not hold a certificate; skipped")
    return found


def _own_certificate(directory: Path) -> x509.Certificate:
    folder = directory / "own" / "certs"
    certificates = _certificates(folder)
    if not certificates:
        raise ToolError(f"{directory}: no application certificate in own/certs; create it with enginir-opcua init")
    return max((certificate for _, certificate in certificates), key=lambda c: c.not_valid_before_utc)


def _write_trusted(directory: Path, certificate: x509.Certificate) -> tuple[Path, bool]:
    target = directory / "trusted" / "certs" / f"{_thumbprint(certificate)}.der"
    if target.exists():
        return target, False
    cert_gen.write_atomic(target, cert_gen_der(certificate), 0o644)
    return target, True


def _normalise_thumbprint(text: str) -> str:
    digits = text.replace(":", "").replace(" ", "").lower()
    if not re.fullmatch(r"[0-9a-f]+", digits) or len(digits) < MIN_THUMBPRINT_DIGITS:
        raise ToolError(
            f"{text!r} is neither a certificate file nor a thumbprint of at least {MIN_THUMBPRINT_DIGITS} hex digits"
        )
    return digits


def _kind_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("kind", choices=["server", "client"], help="Which application the configuration is for")
    parser.add_argument("directory", metavar="DIR", help="Directory for the PKI directory (DIR/pki) and the config")
    parser.add_argument(
        "--endpoint", "--url", dest="address", metavar="URL", help="Endpoint URL of the server, or URL of the server"
    )
    parser.add_argument("--profile", choices=["secure", "development"], default="secure", help="Default: secure")
    parser.add_argument("--name", help="Application name")
    parser.add_argument("--application-uri", metavar="URI", help="ApplicationUri; default is derived from the host")
    parser.add_argument("--force", action="store_true", help="Replace an existing configuration file")


def _init(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    root = directory / "pki"
    config_path = directory / f"{args.kind}.toml"
    if config_path.exists() and not args.force:
        raise ToolError(
            f"{config_path} already exists; use --force to replace it. The PKI directory and its certificate are "
            "never replaced"
        )
    fields: dict[str, object] = {
        "profile": args.profile,
        "pki": str(root),
        "application_uri": args.application_uri or default_application_uri(args.kind),
    }
    if args.name:
        fields["name"] = args.name
    if args.kind == "server":
        if args.address:
            fields["endpoint"] = args.address
        server_config = ServerConfig(**fields)  # type: ignore[arg-type]
        config: ServerConfig | ClientConfig = server_config
        host = urlparse(server_config.endpoint).hostname
        usage = pki.SERVER_USAGE
    else:
        if args.address:
            fields["url"] = args.address
        config = ClientConfig(**fields)  # type: ignore[arg-type]
        host = None
        usage = pki.CLIENT_USAGE
    config.validate()
    existed = root.exists()
    certificate_existed = bool(_certificates(root / "own" / "certs"))
    directory.mkdir(parents=True, exist_ok=True)
    pki.create_directories(root)
    credentials = asyncio.run(
        pki.load_own_credentials(
            root,
            application_uri=config.application_uri,
            host_names=pki.default_host_names(host),
            usage=usage,
            create=True,
        )
    )
    say(f"{'kept' if existed else 'created':<8} {root}")
    certificate_file = root / "own" / "certs" / pki.CERTIFICATE_NAME
    say(
        f"{'kept' if certificate_existed else 'created':<8} {certificate_file}  "
        f"thumbprint {_thumbprint(credentials.certificate)}  expires {credentials.certificate.not_valid_after_utc:%Y-%m-%d}"
    )
    dataclasses.replace(config, pki="pki").dump(config_path)
    say(f"{'created':<8} {config_path}")
    if args.kind == "server":
        say(f"{'next':<8} enginir-opcua user add {directory / 'users.toml'} <name> --role user")
    return 0


def _find_rejected(directory: Path, digits: str) -> tuple[Path, x509.Certificate]:
    folder = directory / "rejected" / "certs"
    matches = [(path, cert) for path, cert in _certificates(folder) if _thumbprint(cert).startswith(digits)]
    if not matches:
        raise ToolError(
            f"no certificate with thumbprint {digits!r} in {folder}; list them with enginir-opcua pki list --pki {directory}"
        )
    if len(matches) > 1:
        listing = ", ".join(_thumbprint(cert) for _, cert in matches)
        raise ToolError(f"thumbprint prefix {digits!r} matches {len(matches)} certificates: {listing}")
    return matches[0]


def _trust(args: argparse.Namespace) -> int:
    directory = _require_pki(Path(args.pki))
    candidate = Path(args.certificate)
    source: Path | None = None
    if candidate.is_file():
        certificate = _load_certificate_file(candidate)
    else:
        source, certificate = _find_rejected(directory, _normalise_thumbprint(args.certificate))
    target, written = _write_trusted(directory, certificate)
    if source is not None:
        source.unlink(missing_ok=True)
    thumbprint = _thumbprint(certificate)
    if not written:
        say(f"already trusted  {thumbprint}  {_subject(certificate)}  in {target.parent}")
        return 0
    say(f"trusted  {thumbprint}  {_subject(certificate)}  expires {_expiry(certificate)}  in {target.parent}")
    if certificate.not_valid_after_utc < datetime.now(UTC):
        warn(
            f"warning: the certificate expired on {certificate.not_valid_after_utc:%Y-%m-%d}; "
            "validation will still refuse it"
        )
    if _is_ca(certificate):
        warn("note: this is a CA certificate; every certificate it issued will be trusted")
    warn("note: a running server or client picks the certificate up at its next connection attempt")
    TrustStore.reload_pki_directory(directory)
    return 0


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _pki_list(args: argparse.Namespace) -> int:
    directory = _require_pki(Path(args.pki))
    printed = False
    for label, folder in (
        ("own", "own/certs"),
        ("trusted", "trusted/certs"),
        ("issuer", "issuer/certs"),
        ("rejected", "rejected/certs"),
    ):
        entries = sorted(_certificates(directory / folder), key=lambda item: item[1].not_valid_after_utc, reverse=True)
        for _, certificate in entries:
            subject = _subject(certificate)
            if len(subject) > SUBJECT_WIDTH:
                subject = subject[: SUBJECT_WIDTH - 3] + "..."
            say(f"{label:<8} {_thumbprint(certificate)}  {subject:<{SUBJECT_WIDTH}}  expires {_expiry(certificate)}")
            printed = True
    if not printed:
        say("no certificates")
    counts = {
        name: len([p for p in (directory / name).glob("*") if p.is_file() and not p.name.startswith(".")])
        if (directory / name).is_dir()
        else 0
        for name in ("trusted/crl", "issuer/crl")
    }
    say(f"trusted/crl: {counts['trusted/crl']} lists   issuer/crl: {counts['issuer/crl']} lists")
    return 0


def _pki_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="pki_command", metavar="SUBCOMMAND", required=True)
    listing = sub.add_parser("list", help="List the certificates of a PKI directory")
    _pki_argument(listing)
    listing.set_defaults(handler=_pki_list)


def _trust_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "certificate", metavar="THUMBPRINT_OR_FILE", help="Thumbprint of a rejected certificate, or a file"
    )
    _pki_argument(parser)


def _pair_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("server_pki", metavar="SERVER_PKI")
    parser.add_argument("client_pki", metavar="CLIENT_PKI")


def _pair(args: argparse.Namespace) -> int:
    warn(PAIR_WARNING)
    first, second = Path(args.server_pki), Path(args.client_pki)
    for directory in (first, second):
        _require_pki(directory)
    certificates = {first: _own_certificate(first), second: _own_certificate(second)}
    for directory, other in ((first, second), (second, first)):
        certificate = certificates[other]
        target, _ = _write_trusted(directory, certificate)
        say(f"trusted  {_thumbprint(certificate)}  {_subject(certificate)}  in {target.parent}")
    for directory in (first, second):
        TrustStore.reload_pki_directory(directory)
    return 0


def _user_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="user_command", metavar="SUBCOMMAND", required=True)
    add = sub.add_parser("add", help="Add a user to a users file; asks for the password")
    add.add_argument("file", metavar="FILE")
    add.add_argument("name")
    add.add_argument("--role", required=True, choices=list(users_file.ROLES))
    add.add_argument("--replace", action="store_true", help="Set a new password for an existing user")
    add.add_argument("--password-stdin", action="store_true", help="Read the password from one line of standard input")
    add.set_defaults(handler=_user_add)
    listing = sub.add_parser("list", help="List the users of a users file")
    listing.add_argument("file", metavar="FILE")
    listing.set_defaults(handler=_user_list)
    remove = sub.add_parser("remove", help="Remove a user from a users file")
    remove.add_argument("file", metavar="FILE")
    remove.add_argument("name")
    remove.set_defaults(handler=_user_remove)


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise ToolError("the two passwords do not match")
    return first


def _user_add(args: argparse.Namespace) -> int:
    path = Path(args.file)
    records = users_file.read_users(path) if path.exists() else []
    if any(record.name == args.name for record in records) and not args.replace:
        raise ToolError(f"user {args.name!r} already exists in {path}; use --replace to set a new password")
    problem = users_file._check_name(args.name)
    if problem:
        raise ToolError(f"user name: {problem}")
    password = _read_password(args)
    users_file.check_password_rules(password)
    record = users_file.UserRecord(args.name, args.role, users_file.hash_password(password))
    if any(r.name == args.name for r in records):
        records = [record if r.name == args.name else r for r in records]
    else:
        records.append(record)
    users_file.write_users(path, records)
    say(f"added user {args.name!r} (role {args.role}) to {path}")
    return 0


def _user_list(args: argparse.Namespace) -> int:
    for record in users_file.read_users(Path(args.file)):
        say(f"{record.name} {record.role}")
    return 0


def _user_remove(args: argparse.Namespace) -> int:
    path = Path(args.file)
    records = users_file.read_users(path)
    if not any(record.name == args.name for record in records):
        raise ToolError(f"no user {args.name!r} in {path}")
    users_file.write_users(path, [r for r in records if r.name != args.name])
    say(f"removed user {args.name!r} from {path}")
    return 0


def _dispatch(args: argparse.Namespace) -> int:
    handler = getattr(args, "handler", None)
    if handler is None:
        raise UsageError("a sub-command is needed")
    result: int = handler(args)
    return result


for _command in (
    Command(
        "init",
        "Create a PKI directory with an application certificate and a commented configuration file",
        _kind_arguments,
        _init,
        client_options=False,
    ),
    Command(
        "trust",
        "Trust a certificate: move a rejected one by thumbprint, or add a file, to trusted/certs",
        _trust_arguments,
        _trust,
        client_options=False,
    ),
    Command("pki", "Look at a PKI directory (pki list)", _pki_arguments, _dispatch, client_options=False),
    Command(
        "pair",
        "Make two PKI directories on this machine trust each other (development only)",
        _pair_arguments,
        _pair,
        client_options=False,
    ),
    Command("user", "Manage a users file (user add, list, remove)", _user_arguments, _dispatch, client_options=False),
):
    register(_command)

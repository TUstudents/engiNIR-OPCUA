"""
The users file: names, roles and scrypt password hashes, in TOML or JSON, and the password hash itself.

    scrypt$<N>$<r>$<p>$<salt, base64>$<key, base64>
"""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from enginir_opcua.crypto.cert_gen import write_atomic
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.ua.uaerrors import ConfigurationError

FORMAT_VERSION = 1
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LENGTH = 16
KEY_LENGTH = 32
MIN_N, MAX_N = 2**14, 2**20
MAX_R, MAX_P = 32, 16
MIN_KEY, MAX_KEY = 16, 64
MIN_PASSWORD_BYTES, MAX_PASSWORD_BYTES = 8, 1024
MAX_NAME_LENGTH = 64
ROLES: dict[str, UserRole] = {
    "user": UserRole.User,
    "admin": UserRole.Admin,
    "security_admin": UserRole.SecurityAdmin,
}
HEADER = (
    "# Users of an enginir-opcua server: name, role and a salted scrypt hash of the password.\n"
    "# The file is written by `enginir-opcua user add|remove`; comments are not kept. No password is stored.\n"
)


@dataclass(frozen=True)
class ScryptHash:
    """The parts of a stored password hash: the scrypt parameters N, r and p, the salt and the derived key."""

    n: int
    r: int
    p: int
    salt: bytes
    key: bytes


@dataclass(frozen=True)
class UserRecord:
    """One user of a users file: the name, the role and the stored password hash."""

    name: str
    role: str
    password_hash: str


def _maxmem(n: int, r: int) -> int:
    return 128 * n * r + 1024 * 1024


def hash_password(password: str) -> str:
    """Hash a password with scrypt and a random salt, in the form ``scrypt$N$r$p$salt$key`` that users files store."""
    salt = secrets.token_bytes(SALT_LENGTH)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=_maxmem(SCRYPT_N, SCRYPT_R),
        dklen=KEY_LENGTH,
    )
    encode = base64.b64encode
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${encode(salt).decode()}${encode(key).decode()}"


def parse_hash(stored: str) -> ScryptHash:
    """Split a stored hash into its parts; raises ConfigurationError when it is malformed or its parameters are out of the accepted range."""
    parts = stored.split("$") if isinstance(stored, str) else []
    if len(parts) != 6 or parts[0] != "scrypt":
        raise ConfigurationError("password_hash is not a scrypt hash: expected scrypt$N$r$p$salt$key")
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt, key = base64.b64decode(parts[4], validate=True), base64.b64decode(parts[5], validate=True)
    except (ValueError, binascii.Error):
        raise ConfigurationError(
            "password_hash is not a scrypt hash: a parameter or the salt or key is not valid"
        ) from None
    if not (MIN_N <= n <= MAX_N and n & (n - 1) == 0 and 1 <= r <= MAX_R and 1 <= p <= MAX_P):
        raise ConfigurationError(
            f"password_hash is not an accepted scrypt hash: N must be a power of two from {MIN_N} to {MAX_N}, "
            f"r from 1 to {MAX_R} and p from 1 to {MAX_P}"
        )
    if len(salt) < SALT_LENGTH or not MIN_KEY <= len(key) <= MAX_KEY:
        raise ConfigurationError(
            f"password_hash is not an accepted scrypt hash: the salt needs at least {SALT_LENGTH} bytes and the "
            f"key {MIN_KEY} to {MAX_KEY}"
        )
    return ScryptHash(n, r, p, salt, key)


def verify_password(password: str, stored: str) -> bool:
    """Whether ``password`` matches the stored hash; the comparison takes the same time whatever the result."""
    parsed = parse_hash(stored)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=parsed.salt,
        n=parsed.n,
        r=parsed.r,
        p=parsed.p,
        maxmem=_maxmem(parsed.n, parsed.r),
        dklen=len(parsed.key),
    )
    return hmac.compare_digest(key, parsed.key)


@cache
def dummy_hash() -> str:
    return hash_password(secrets.token_hex(8))


def check_password_rules(password: str) -> None:
    """Raise ConfigurationError unless the password is 8 to 1024 bytes long in UTF-8."""
    size = len(password.encode("utf-8"))
    if not MIN_PASSWORD_BYTES <= size <= MAX_PASSWORD_BYTES:
        raise ConfigurationError(
            f"password: must be {MIN_PASSWORD_BYTES} to {MAX_PASSWORD_BYTES} bytes long, got {size}"
        )


def _check_name(name: Any) -> str | None:
    if not isinstance(name, str) or not name:
        return "name must be a non-empty string"
    if len(name) > MAX_NAME_LENGTH or name != name.strip() or any(ord(c) < 32 or ord(c) == 127 for c in name):
        return f"name must be at most {MAX_NAME_LENGTH} characters, without control characters or leading and trailing spaces"
    return None


def _record(entry: Any, number: int, seen: set[str], source: Path) -> UserRecord:
    name = entry.get("name") if isinstance(entry, dict) else None
    label = f"{source}: user {name!r} (entry {number})" if isinstance(name, str) else f"{source}: entry {number}"
    if not isinstance(entry, dict):
        raise ConfigurationError(f"{label}: expected a table with name, role and password_hash")
    unknown = sorted(set(entry) - {"name", "role", "password_hash"})
    if unknown:
        raise ConfigurationError(f"{label}: unknown key {unknown[0]!r}; the keys are name, role and password_hash")
    problem = _check_name(name)
    if problem or not isinstance(name, str):
        raise ConfigurationError(f"{label}: {problem}")
    if entry.get("role") not in ROLES:
        raise ConfigurationError(f"{label}: role must be one of {', '.join(ROLES)}, got {entry.get('role')!r}")
    if "password_hash" not in entry:
        raise ConfigurationError(f"{label}: password_hash is missing")
    try:
        parse_hash(entry["password_hash"])
    except ConfigurationError as error:
        raise ConfigurationError(f"{label}: {error}") from None
    if name in seen:
        raise ConfigurationError(f"{label}: the name already appears in an earlier entry")
    seen.add(name)
    return UserRecord(name, entry["role"], entry["password_hash"])


def read_users(path: Path) -> list[UserRecord]:
    """Read a users file, TOML or, with a ``.json`` suffix, JSON; every error is a ConfigurationError that names the file and the entry."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigurationError(f"{path}: cannot read the users file: {error.strerror or error}") from None
    try:
        document = json.loads(text) if path.suffix.lower() == ".json" else tomllib.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(f"{path}: {error}") from None
    if not isinstance(document, dict) or "version" not in document:
        raise ConfigurationError(f"{path}: version is missing; start the file with version = {FORMAT_VERSION}")
    if document["version"] != FORMAT_VERSION:
        raise ConfigurationError(
            f"{path}: unsupported version {document['version']}; this library reads version {FORMAT_VERSION}"
        )
    key = "users" if path.suffix.lower() == ".json" else "user"
    unknown = sorted(set(document) - {"version", key})
    if unknown:
        raise ConfigurationError(f"{path}: unknown key {unknown[0]!r}; the keys are version and {key}")
    entries = document.get(key, [])
    if not isinstance(entries, list):
        raise ConfigurationError(f"{path}: {key} must be a list of users")
    seen: set[str] = set()
    return [_record(entry, number, seen, path) for number, entry in enumerate(entries, 1)]


def _toml_string(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def write_users(path: Path, users: list[UserRecord]) -> None:
    """Write a users file atomically, readable by its owner only; the format follows the suffix as in ``read_users``."""
    path = Path(path)
    if path.suffix.lower() == ".json":
        document = {
            "version": FORMAT_VERSION,
            "users": [{"name": u.name, "role": u.role, "password_hash": u.password_hash} for u in users],
        }
        text = json.dumps(document, indent=2) + "\n"
    else:
        text = HEADER + f"version = {FORMAT_VERSION}\n"
        for user in users:
            text += (
                f"\n[[user]]\nname = {_toml_string(user.name)}\nrole = {_toml_string(user.role)}\n"
                f"password_hash = {_toml_string(user.password_hash)}\n"
            )
    write_atomic(path, text.encode("utf-8"), 0o600)

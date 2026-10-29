"""
Configuration objects for the quick setup: ServerConfig, ClientConfig, the two profiles and the TOML format.
Every error names the setting, as it is written in the TOML file ("server.pki", "server.limits.max_sessions").
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import ParseResult, urlparse

from .crypto.cert_gen import write_atomic
from .ua import SecurityPolicyType
from .ua.uaerrors import ConfigurationError

if TYPE_CHECKING:
    from .server.user_managers import UserManager

MAX_PORT = 65_535
PROFILES = ("secure", "development")
SECURE_POLICIES = ("Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss")
DEPRECATED_POLICIES = ("Basic128Rsa15", "Basic256")
MODES = ("Sign", "SignAndEncrypt")
SERVER_SECURE_DEFAULT = [f"{policy},SignAndEncrypt" for policy in SECURE_POLICIES]
SERVER_DEVELOPMENT_DEFAULT = ["None", "Basic256Sha256,SignAndEncrypt"]
CLIENT_SECURE_DEFAULT = "Basic256Sha256,SignAndEncrypt"
CLIENT_DEVELOPMENT_DEFAULT = "None"
USERS_FILE_VARIABLE = "ENGINIR_OPCUA_USERS_FILE"
PASSWORD_VARIABLE = "ENGINIR_OPCUA_PASSWORD"
ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
URI_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:\S+\Z")
SECRET_KEYS = frozenset({"password", "private_key_password"})


class ConfigurationProblems(ConfigurationError):
    """Every problem of a configuration, one per line; `problems` holds them as a list."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


def parse_opc_tcp_url(url: str, setting: str = "endpoint") -> ParseResult:
    """Parse an opc.tcp URL and check scheme, host and port; errors name the setting."""
    if not isinstance(url, str):
        raise ConfigurationError(f"{setting}: expected a URL string, got {url!r}")
    parsed = urlparse(url)
    if parsed.scheme != "opc.tcp":
        raise ConfigurationError(f"{setting}: expected a URL that starts with opc.tcp://, got {url!r}")
    if not parsed.hostname:
        raise ConfigurationError(f"{setting}: the URL {url!r} has no host; write opc.tcp://host:port/path")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError(f"{setting}: the URL {url!r} must not carry a user name or password")
    try:
        port = parsed.port
    except ValueError:
        port = 0
    if port is not None and not 1 <= port <= MAX_PORT:
        raise ConfigurationError(f"{setting}: the port of {url!r} must be from 1 to {MAX_PORT}")
    return parsed


def is_loopback(host: str) -> bool:
    name = host.lower().strip("[]")
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def default_application_uri(role: str) -> str:
    host = re.sub(r"[^A-Za-z0-9.\-]", "-", socket.gethostname()) or "localhost"
    return f"urn:{host}:enginir-opcua:{role}"


def _is_int(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())


class _Problems:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.items: list[str] = []

    def add(self, name: str, text: str) -> None:
        self.items.append(f"{self.prefix}.{name}: {text}")

    def text(self, name: str, value: Any, low: int = 1, high: int = 255) -> bool:
        if (
            not isinstance(value, str)
            or not low <= len(value) <= high
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            self.add(name, f"must be a text of {low} to {high} characters without control characters, got {value!r}")
            return False
        return True

    def boolean(self, name: str, value: Any) -> bool:
        if not isinstance(value, bool):
            self.add(name, f"must be true or false, got {value!r}")
            return False
        return True

    def uri(self, name: str, value: Any) -> None:
        if not isinstance(value, str) or not URI_PATTERN.match(value) or len(value.encode("utf-8")) > 255:
            self.add(
                name, f"must be a URI with a scheme, such as urn:plant:server, of at most 255 bytes, got {value!r}"
            )

    def variable(self, name: str, value: Any) -> None:
        if not isinstance(value, str) or not ENVIRONMENT_NAME.match(value):
            self.add(name, f"must be the name of an environment variable, got {value!r}")

    def integer(self, name: str, value: Any, low: int, high: int, shown_high: str | None = None) -> bool:
        if not _is_int(value) or not low <= value <= high:
            self.add(name, f"must be an integer from {low} to {shown_high or high}, got {value!r}")
            return False
        return True

    def url(self, name: str, value: Any, loopback_only: bool, what: str) -> ParseResult | None:
        try:
            parsed = parse_opc_tcp_url(value, f"{self.prefix}.{name}")
        except ConfigurationError as error:
            self.items.append(str(error))
            return None
        if loopback_only and not is_loopback(parsed.hostname or ""):
            self.add(
                name,
                f"the development profile only {what} a loopback address, got {value!r}; "
                'use 127.0.0.1 or localhost, or profile "secure"',
            )
        return parsed

    def number(self, name: str, value: Any, low: float = 0.0, high: float = 3_600.0) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low < value <= high:
            self.add(name, f"must be a number above {low:g} and at most {high:g}, got {value!r}")

    def path(self, name: str, value: Any) -> bool:
        if not isinstance(value, (str, os.PathLike)) or not str(value):
            self.add(name, f"must be a file system path, got {value!r}")
            return False
        return True


def parse_security(text: Any, profile: str) -> tuple[SecurityPolicyType | None, str | None]:
    """The policy type of a `Policy,Mode` or `None` string, or a problem text."""
    if not isinstance(text, str):
        return None, f"must be a text such as Basic256Sha256,SignAndEncrypt, got {text!r}"
    if text == "None":
        if profile == "development":
            return SecurityPolicyType.NoSecurity, None
        return None, (
            'the policy None is not allowed in the secure profile; use profile "development" '
            "for a local server without security"
        )
    policy, _, mode = text.partition(",")
    policy = policy.replace("_", "")
    if policy in DEPRECATED_POLICIES:
        return None, (
            f"the policy {policy} is deprecated and is not available in a profile; "
            "use Server.set_security_policy with allow_deprecated_policies=True"
        )
    if policy not in SECURE_POLICIES:
        return None, f"unknown policy {policy!r}; use one of {', '.join(SECURE_POLICIES)} (or None in development)"
    if mode not in MODES:
        return None, f"unknown mode {mode!r}; write Policy,Mode with Mode Sign or SignAndEncrypt"
    if mode != "SignAndEncrypt":
        return None, f"{text!r} is not allowed in a profile: only SignAndEncrypt is"
    return SecurityPolicyType[f"{policy}_{mode}"], None


def policy_name(policy: SecurityPolicyType) -> str:
    return "None" if policy is SecurityPolicyType.NoSecurity else policy.name.replace("_", ",")


def _check_pki(problems: _Problems, config: Any) -> None:
    if not problems.path("pki", config.pki):
        return
    root = Path(config.pki)
    if root.exists() and not root.is_dir():
        problems.add("pki", f"{root} exists and is not a directory")
    elif not config.create_pki:
        if not (root / "own" / "certs").is_dir() or not (root / "own" / "private").is_dir():
            problems.add(
                "pki",
                f"{root} is not a PKI directory (no own/certs and own/private); create it with enginir-opcua init",
            )
    elif not root.exists():
        parent = root.resolve().parent
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
            problems.add("pki", f"cannot create {root}: {parent} is not a writable directory")


@dataclass
class ServerLimits:
    max_sessions: int = field(default=100, metadata={"doc": "Sessions at the same time"})
    max_connections: int = field(
        default=1_000, metadata={"doc": "Secure channels at the same time, above max_sessions"}
    )
    min_session_timeout_ms: int = field(default=5_000, metadata={"doc": "Shortest Session timeout granted"})
    max_session_timeout_ms: int = field(default=600_000, metadata={"doc": "Longest Session timeout granted"})
    max_subscriptions: int = field(default=1_000, metadata={"doc": "Subscriptions of the whole server"})
    max_subscriptions_per_session: int = field(default=100, metadata={"doc": "Subscriptions of one Session"})
    min_publishing_interval_ms: int = field(default=50, metadata={"doc": "Fastest publishing interval granted"})
    max_publishing_interval_ms: int = field(default=3_600_000, metadata={"doc": "Slowest publishing interval granted"})
    max_monitored_items: int = field(default=100_000, metadata={"doc": "Monitored items of the whole server"})
    max_monitored_items_per_subscription: int = field(
        default=10_000, metadata={"doc": "Monitored items of one Subscription"}
    )
    hello_timeout_seconds: int = field(default=30, metadata={"doc": "Time a new connection has to send Hello"})
    max_message_size: int = field(default=104_857_600, metadata={"doc": "Largest message in bytes"})
    max_buffer_size: int = field(default=65_535, metadata={"doc": "Receive and send buffer in bytes"})
    max_string_length: int = field(
        default=16_777_216, metadata={"doc": "Longest String in a request in bytes, published as MaxStringLength"}
    )
    max_byte_string_length: int = field(
        default=16_777_216,
        metadata={"doc": "Longest ByteString in a request in bytes, published as MaxByteStringLength"},
    )
    max_array_length: int = field(
        default=1_000_000, metadata={"doc": "Most elements in an array value of a request, published as MaxArrayLength"}
    )

    def collect(self, problems: _Problems) -> None:
        values = {f.name: getattr(self, f.name) for f in fields(self)}

        def check(name: str, low: int, high: int | str, shown: str | None = None) -> None:
            limit = values[high] if isinstance(high, str) else high
            if not isinstance(limit, int) or isinstance(limit, bool):
                limit = 4_294_967_295
            problems.integer(name, values[name], low, limit, shown or (f"{high}" if isinstance(high, str) else None))

        check("max_sessions", 1, 65_535)
        sessions = values["max_sessions"] if _is_int(values["max_sessions"]) else 0
        if _is_int(values["max_connections"]) and not sessions + 1 <= values["max_connections"] <= 100_000:
            problems.add(
                "max_connections",
                f"must be at least max_sessions + 1 ({sessions + 1}) and at most 100000, got {values['max_connections']!r}",
            )
        elif not _is_int(values["max_connections"]):
            problems.add("max_connections", f"must be an integer, got {values['max_connections']!r}")
        check("min_session_timeout_ms", 1_000, "max_session_timeout_ms")
        check("max_session_timeout_ms", 1_000, 4_294_967_295)
        check("max_subscriptions", 1, 1_000_000)
        check("max_subscriptions_per_session", 1, "max_subscriptions")
        check("min_publishing_interval_ms", 1, "max_publishing_interval_ms")
        check("max_publishing_interval_ms", 1, 86_400_000)
        check("max_monitored_items", 1, 10_000_000)
        check("max_monitored_items_per_subscription", 1, "max_monitored_items")
        check("hello_timeout_seconds", 1, 120)
        check("max_message_size", 8_192, 4_294_967_295)
        check("max_buffer_size", 8_192, 4_294_967_295)
        check("max_string_length", 4_096, 2_147_483_647)
        check("max_byte_string_length", 4_096, 2_147_483_647)
        check("max_array_length", 100, 2_147_483_647)


def _field_names(cls: type) -> list[str]:
    return [f.name for f in fields(cls) if f.metadata.get("toml", True)]


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    return json.dumps(str(value), ensure_ascii=False)


def _dump_table(name: str, config: Any, exclude: tuple[str, ...] = ()) -> str:
    lines = [f"[{name}]"]
    for f in fields(config):
        if not f.metadata.get("toml", True) or f.name in exclude:
            continue
        value = getattr(config, f.name)
        lines.append(f"# {f.metadata.get('doc', f.name)}")
        lines.append(f"# {f.name} = {_toml_value('')}" if value is None else f"{f.name} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)


def _read_table(cls: type, table: Any, name: str, source: Path) -> dict[str, Any]:
    if not isinstance(table, dict):
        raise ConfigurationError(f"{source}: {name} must be a table")
    known = _field_names(cls)
    values: dict[str, Any] = {}
    for key, value in table.items():
        if key in SECRET_KEYS:
            raise ConfigurationError(
                f"{source}: {name}.{key}: unknown setting; passwords are not stored in the file; use "
                f"{'password_env' if key == 'password' else 'private_key_password_env'}"
            )
        if key not in known:
            raise ConfigurationError(f"{source}: {name}.{key}: unknown setting; the settings are: {', '.join(known)}")
        values[key] = value
    return values


def _load_document(path: str | Path) -> tuple[Path, dict[str, Any]]:
    source = Path(path)
    try:
        document = tomllib.loads(source.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConfigurationError(f"{source}: cannot read the file: {error.strerror or error}") from None
    except tomllib.TOMLDecodeError as error:
        raise ConfigurationError(f"{source}: {error}") from None
    return source, document


def _resolve(values: dict[str, Any], keys: tuple[str, ...], source: Path) -> None:
    for key in keys:
        value = values.get(key)
        if isinstance(value, str) and value:
            values[key] = str((source.parent / value).absolute()) if not os.path.isabs(value) else value


def _with_source(source: Path, error: ConfigurationError) -> ConfigurationError:
    problems = getattr(error, "problems", [str(error)])
    return ConfigurationProblems([f"{source}: {problem}" for problem in problems])


def _unknown_overrides(cls: type, prefix: str, overrides: dict[str, Any]) -> None:
    known = _field_names(cls) + [f.name for f in fields(cls) if not f.metadata.get("toml", True)]
    for key in overrides:
        if key not in known:
            raise ConfigurationError(f"{prefix}.{key}: unknown setting; the settings are: {', '.join(known)}")


@dataclass
class ServerConfig:
    profile: str = field(
        default="secure", metadata={"doc": 'Either "secure" (any network) or "development" (loopback only)'}
    )
    endpoint: str = field(
        default="opc.tcp://127.0.0.1:4840/enginir-opcua/server/",
        metadata={"doc": "Endpoint URL, opc.tcp://host:port/path"},
    )
    name: str = field(default="engiNIR OPC UA Server", metadata={"doc": "Application name"})
    application_uri: str = field(
        default="urn:enginir:opcua:server", metadata={"doc": "ApplicationUri, unique per application"}
    )
    product_uri: str = field(default="urn:enginir:opcua", metadata={"doc": "ProductUri"})
    manufacturer_name: str = field(default="engiNIR", metadata={"doc": "Manufacturer in the build information"})
    pki: str | Path | None = field(
        default=None, metadata={"doc": "PKI directory with the certificate, key and trust lists; relative to this file"}
    )
    create_pki: bool = field(default=True, metadata={"doc": "Create the PKI directory and a certificate when missing"})
    private_key_password_env: str | None = field(
        default=None, metadata={"doc": "Name of the environment variable that holds the private key password"}
    )
    security: list[str] | None = field(
        default=None, metadata={"doc": 'Policies as "Policy,Mode" or "None"; the profile decides the default'}
    )
    allow_no_security: bool | None = field(
        default=None, metadata={"doc": "Offer an endpoint without security (development only)"}
    )
    anonymous: bool = field(default=True, metadata={"doc": "Accept anonymous (read-only) sessions"})
    users_file: str | Path | None = field(
        default=None, metadata={"doc": "Users file, see enginir-opcua user add; relative to this file"}
    )
    user_manager: UserManager | None = field(default=None, metadata={"toml": False})
    limits: ServerLimits = field(default_factory=ServerLimits, metadata={"toml": False})

    def __post_init__(self) -> None:
        if self.profile in PROFILES:
            if self.security is None:
                self.security = list(
                    SERVER_DEVELOPMENT_DEFAULT if self.profile == "development" else SERVER_SECURE_DEFAULT
                )
            if self.allow_no_security is None:
                self.allow_no_security = self.profile == "development"

    def effective_users_file(self) -> str | Path | None:
        return self.users_file or os.environ.get(USERS_FILE_VARIABLE) or None

    def policy_types(self) -> list[SecurityPolicyType]:
        types = []
        for text in self.security or []:
            policy, problem = parse_security(text, self.profile)
            if policy is None:
                raise ConfigurationError(f"server.security: {problem}")
            types.append(policy)
        return types

    def validate(self) -> None:
        problems = _Problems("server")
        if self.profile not in PROFILES:
            problems.add("profile", f'unknown profile {self.profile!r}; use "secure" or "development"')
        development = self.profile == "development"
        problems.url("endpoint", self.endpoint, development, "listens on")
        problems.text("name", self.name)
        problems.uri("application_uri", self.application_uri)
        problems.uri("product_uri", self.product_uri)
        problems.text("manufacturer_name", self.manufacturer_name)
        problems.boolean("create_pki", self.create_pki)
        problems.boolean("anonymous", self.anonymous)
        if self.private_key_password_env is not None:
            problems.variable("private_key_password_env", self.private_key_password_env)
        secure_policy = self._check_security(problems)
        if self.allow_no_security is not None and problems.boolean("allow_no_security", self.allow_no_security):
            if self.allow_no_security and not development:
                problems.add(
                    "allow_no_security", 'only the profile "development" may offer an endpoint without security'
                )
            if "None" in (self.security or []) and not self.allow_no_security and development:
                problems.add("allow_no_security", "the policy None is listed in server.security, so this must be true")
        if secure_policy:
            if self.pki is None:
                problems.add(
                    "pki",
                    "required for the policies of server.security other than None: give a PKI directory (for example ./pki)",
                )
            else:
                _check_pki(problems, self)
        elif self.pki is not None:
            _check_pki(problems, self)
        self._check_users(problems, secure_policy)
        if not isinstance(self.limits, ServerLimits):
            problems.add("limits", "must be a ServerLimits")
        else:
            limit_problems = _Problems("server.limits")
            self.limits.collect(limit_problems)
            problems.items.extend(limit_problems.items)
        if problems.items:
            raise ConfigurationProblems(problems.items)

    def _check_security(self, problems: _Problems) -> bool:
        security = self.security
        if not isinstance(security, list) or not security:
            problems.add("security", f'must be a non-empty list of "Policy,Mode" texts, got {security!r}')
            return False
        secure = False
        seen: set[str] = set()
        for text in security:
            policy, problem = parse_security(text, self.profile if self.profile in PROFILES else "secure")
            if problem:
                problems.add("security", problem)
            elif policy is not SecurityPolicyType.NoSecurity:
                secure = True
            if text in seen:
                problems.add("security", f"{text!r} is listed twice")
            seen.add(text)
        return secure

    def _check_users(self, problems: _Problems, secure_policy: bool) -> None:
        users = self.effective_users_file()
        if users is not None and self.user_manager is not None:
            problems.add("user_manager", "cannot be combined with users_file; give one of them")
        if self.user_manager is not None:
            from .server.user_managers import PermissiveUserManager

            if not (hasattr(self.user_manager, "get_user") or hasattr(self.user_manager, "authenticate")):
                problems.add("user_manager", "must be a UserManager")
            elif self.profile == "secure" and isinstance(self.user_manager, PermissiveUserManager):
                problems.add(
                    "user_manager", "PermissiveUserManager accepts every login and is not allowed in the secure profile"
                )
        if users is not None:
            from .crypto import users_file

            if not problems.path("users_file", users):
                return
            try:
                users_file.read_users(Path(users))
            except ConfigurationError as error:
                problems.add("users_file", str(error))
            if not secure_policy and not any(p.startswith("server.security:") for p in problems.items):
                problems.add(
                    "users_file",
                    "users need a policy with encryption; add Basic256Sha256,SignAndEncrypt to server.security",
                )
        if not self.anonymous and users is None and self.user_manager is None:
            problems.add("anonymous", "no identity is accepted: set anonymous = true or give users_file")

    def dump(self, path: str | Path | None = None) -> str:
        text = (
            "# enginir-opcua server configuration. The file holds no secrets.\n"
            "# Read it with ServerConfig.from_toml(path).\n\n"
            + _dump_table("server", self, exclude=("limits",))
            + "\n"
            + _dump_table("server.limits", self.limits)
        )
        if path is not None:
            write_atomic(Path(path), text.encode("utf-8"), 0o600)
        return text

    @classmethod
    def from_toml(cls, path: str | Path) -> ServerConfig:
        source, document = _load_document(path)
        if "server" not in document:
            raise ConfigurationError(f"{source}: no [server] table")
        table = dict(document["server"]) if isinstance(document["server"], dict) else document["server"]
        limits_table = table.pop("limits", {}) if isinstance(table, dict) else {}
        values = _read_table(cls, table, "server", source)
        limit_values = _read_table(ServerLimits, limits_table, "server.limits", source)
        _resolve(values, ("pki", "users_file"), source)
        config = cls(**values, limits=ServerLimits(**limit_values))
        try:
            config.validate()
        except ConfigurationError as error:
            raise _with_source(source, error) from None
        return config


@dataclass
class ClientConfig:
    profile: str = field(
        default="secure", metadata={"doc": 'Either "secure" (any network) or "development" (loopback only)'}
    )
    url: str = field(default="opc.tcp://localhost:4840", metadata={"doc": "URL of the server"})
    name: str = field(default="engiNIR OPC UA Client", metadata={"doc": "Application name"})
    application_uri: str = field(
        default="urn:enginir:opcua:client", metadata={"doc": "ApplicationUri, unique per application"}
    )
    pki: str | Path | None = field(
        default=None, metadata={"doc": "PKI directory with the certificate, key and trust lists; relative to this file"}
    )
    create_pki: bool = field(default=True, metadata={"doc": "Create the PKI directory and a certificate when missing"})
    private_key_password_env: str | None = field(
        default=None, metadata={"doc": "Name of the environment variable that holds the private key password"}
    )
    security: str | None = field(default=None, metadata={"doc": 'Policy and mode as "Policy,Mode", or "None"'})
    server_certificate: str | Path | None = field(
        default=None, metadata={"doc": "Server certificate to trust and pin; relative to this file"}
    )
    username: str | None = field(default=None, metadata={"doc": "User name; without it the session is anonymous"})
    password: str | None = field(default=None, metadata={"toml": False})
    password_env: str | None = field(
        default=None, metadata={"doc": "Environment variable with the user password (default ENGINIR_OPCUA_PASSWORD)"}
    )
    timeout: float = field(default=4.0, metadata={"doc": "Timeout of each request in seconds"})
    session_timeout_ms: int = field(default=3_600_000, metadata={"doc": "Session timeout requested from the server"})
    auto_reconnect: bool = field(default=False, metadata={"doc": "Reconnect after a lost connection"})

    def __post_init__(self) -> None:
        if self.profile in PROFILES and self.security is None:
            self.security = CLIENT_DEVELOPMENT_DEFAULT if self.profile == "development" else CLIENT_SECURE_DEFAULT

    def password_variable(self) -> str:
        return self.password_env or PASSWORD_VARIABLE

    def effective_password(self) -> str | None:
        return self.password if self.password is not None else os.environ.get(self.password_variable())

    def policy_type(self) -> SecurityPolicyType:
        policy, problem = parse_security(self.security, self.profile)
        if policy is None:
            raise ConfigurationError(f"client.security: {problem}")
        return policy

    def validate(self) -> None:
        problems = _Problems("client")
        if self.profile not in PROFILES:
            problems.add("profile", f'unknown profile {self.profile!r}; use "secure" or "development"')
        development = self.profile == "development"
        if isinstance(self.url, str) and urlparse(self.url).username is not None:
            problems.add("url", "do not put a user name or password in the URL; use username and password")
        else:
            problems.url("url", self.url, development, "connects to")
        problems.text("name", self.name)
        problems.uri("application_uri", self.application_uri)
        problems.boolean("create_pki", self.create_pki)
        problems.boolean("auto_reconnect", self.auto_reconnect)
        if self.private_key_password_env is not None:
            problems.variable("private_key_password_env", self.private_key_password_env)
        if self.password_env is not None:
            problems.variable("password_env", self.password_env)
        policy, problem = parse_security(self.security, self.profile if self.profile in PROFILES else "secure")
        if problem:
            problems.add("security", problem)
        secure = policy is not None and policy is not SecurityPolicyType.NoSecurity
        if secure and self.pki is None:
            problems.add("pki", "required for security other than None: give a PKI directory (for example ./pki)")
        elif self.pki is not None:
            _check_pki(problems, self)
        if self.server_certificate is not None:
            if not problems.path("server_certificate", self.server_certificate):
                pass
            elif not Path(self.server_certificate).is_file():
                problems.add("server_certificate", f"{self.server_certificate} is not a file")
            elif not secure:
                problems.add("server_certificate", "needs a security other than None")
        problems.number("timeout", self.timeout)
        problems.integer("session_timeout_ms", self.session_timeout_ms, 1_000, 4_294_967_295)
        if self.username is not None:
            if not problems.text("username", self.username, 1, 255):
                pass
            elif self.effective_password() is None:
                problems.add(
                    "password",
                    f"no password for user {self.username!r}; pass password= or set the environment variable "
                    f"{self.password_variable()}",
                )
        elif self.password is not None:
            problems.add("username", "a password needs a username")
        if problems.items:
            raise ConfigurationProblems(problems.items)

    def dump(self, path: str | Path | None = None) -> str:
        text = (
            "# enginir-opcua client configuration. The file holds no secrets.\n"
            "# Read it with ClientConfig.from_toml(path).\n\n" + _dump_table("client", self)
        )
        if path is not None:
            write_atomic(Path(path), text.encode("utf-8"), 0o600)
        return text

    @classmethod
    def from_toml(cls, path: str | Path) -> ClientConfig:
        source, document = _load_document(path)
        if "client" not in document:
            raise ConfigurationError(f"{source}: no [client] table")
        values = _read_table(cls, document["client"], "client", source)
        _resolve(values, ("pki", "server_certificate"), source)
        config = cls(**values)
        try:
            config.validate()
        except ConfigurationError as error:
            raise _with_source(source, error) from None
        return config


def with_default_port(parsed: ParseResult) -> ParseResult:
    if parsed.port is not None:
        return parsed
    host = parsed.hostname or ""
    return parsed._replace(netloc=f"[{host}]:4840" if ":" in host else f"{host}:4840")


def server_user_manager(config: ServerConfig) -> UserManager | None:
    """The user manager a server configuration asks for, or none for the default."""
    if config.user_manager is not None:
        return config.user_manager
    users = config.effective_users_file()
    if users is None:
        return None
    from .server.user_managers import FileUserManager

    return FileUserManager(users, anonymous=config.anonymous)


def password_from_environment(setting: str, variable: str | None) -> str | None:
    if variable is None:
        return None
    password = os.environ.get(variable)
    if password is None:
        raise ConfigurationError(f"{setting}: the environment variable {variable} is not set")
    return password


def check_certificate_uri(certificate: Any, application_uri: str, role: str, directory: str | Path) -> None:
    """The application certificate has to carry the ApplicationUri and be valid now (OPC 10000-6, 6.2.2)."""
    from datetime import UTC, datetime

    from cryptography import x509

    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        found = names.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        found = []
    if application_uri not in found:
        shown = ", ".join(found) if found else "none"
        raise ConfigurationError(
            f"{role}.pki: the certificate in {Path(directory) / 'own' / 'certs'} has the application URI {shown}, "
            f"the application's is {application_uri}; set {role}.application_uri to the first or use a new PKI directory"
        )
    now = datetime.now(UTC)
    if certificate.not_valid_after_utc < now:
        raise ConfigurationError(
            f"{role}.pki: the certificate in {Path(directory) / 'own' / 'certs'} expired on "
            f"{certificate.not_valid_after_utc:%Y-%m-%d}; replace it or use a new PKI directory"
        )


def quickstart_server_config(
    endpoint: str, profile: str, pki: str | Path | None, users: Any, overrides: dict[str, Any]
) -> ServerConfig:
    _unknown_overrides(ServerConfig, "server", overrides)
    values: dict[str, Any] = {"endpoint": endpoint, "profile": profile, "pki": pki}
    if isinstance(users, (str, os.PathLike)):
        values["users_file"] = users
    elif users is not None:
        values["user_manager"] = users
    values.update(overrides)
    values.setdefault("application_uri", default_application_uri("server"))
    config = ServerConfig(**values)
    config.validate()
    return config


def quickstart_client_config(
    url: str,
    profile: str,
    pki: str | Path | None,
    username: str | None,
    password: str | None,
    overrides: dict[str, Any],
) -> ClientConfig:
    _unknown_overrides(ClientConfig, "client", overrides)
    values: dict[str, Any] = {"url": url, "profile": profile, "pki": pki, "username": username, "password": password}
    values.update(overrides)
    values.setdefault("application_uri", default_application_uri("client"))
    config = ClientConfig(**values)
    config.validate()
    return config

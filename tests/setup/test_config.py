import dataclasses
import tomllib
from pathlib import Path
from typing import Any

import pytest

from enginir_opcua.config import ClientConfig, ServerConfig, ServerLimits, parse_opc_tcp_url
from enginir_opcua.crypto import users_file
from enginir_opcua.ua.uaerrors import ConfigurationError

SECURE_DEFAULT = [
    "Basic256Sha256,SignAndEncrypt",
    "Aes128Sha256RsaOaep,SignAndEncrypt",
    "Aes256Sha256RsaPss,SignAndEncrypt",
]


def server(**fields: Any) -> ServerConfig:
    fields.setdefault("pki", "./pki")
    return ServerConfig(**fields)


def problems_of(config: ServerConfig | ClientConfig) -> list[str]:
    with pytest.raises(ConfigurationError) as error:
        config.validate()
    return list(getattr(error.value, "problems", [str(error.value)]))


ALL_SUPPRESSIONS = {"revocation_unknown", "issuer_revocation_unknown", "host_name_invalid"}
LEGACY_SERVER_SECURITY = [
    f"{policy},{mode}"
    for policy in ("Basic256Sha256", "Aes128Sha256RsaOaep", "Aes256Sha256RsaPss", "Basic256", "Basic128Rsa15")
    for mode in ("Sign", "SignAndEncrypt")
] + ["None"]


@pytest.mark.parametrize(
    ("profile", "security", "suppress", "plaintext", "client_security", "client_plaintext"),
    [
        pytest.param("secure", SECURE_DEFAULT, set(), False, "Basic256Sha256,SignAndEncrypt", False, id="secure"),
        pytest.param(
            "development",
            ["None", "Basic256Sha256,SignAndEncrypt"],
            ALL_SUPPRESSIONS,
            True,
            "None",
            True,
            id="development",
        ),
        pytest.param("legacy", LEGACY_SERVER_SECURITY, ALL_SUPPRESSIONS, False, "auto", False, id="legacy"),
    ],
)
def test_the_defaults_of_every_profile(
    profile: str,
    security: list[str],
    suppress: set[str],
    plaintext: bool,
    client_security: str,
    client_plaintext: bool,
) -> None:
    config = server(profile=profile)
    assert config.security == security
    assert set(config.suppress or []) == suppress
    assert config.identity_tokens is None
    assert config.allow_plaintext_password is plaintext
    assert config.accept_server_registrations is False
    assert config.anonymous is True
    config.validate()
    client = ClientConfig(profile=profile, pki="./pki")
    assert client.security == client_security
    assert set(client.suppress or []) == suppress
    assert client.allow_plaintext_password is client_plaintext
    client.validate()


def test_the_development_defaults_stay_on_the_loopback_endpoint() -> None:
    assert server(profile="development").endpoint == "opc.tcp://127.0.0.1:4840/enginir-opcua/server/"


def test_a_setting_given_explicitly_replaces_the_profile_default() -> None:
    config = server(
        suppress=["usage"],
        identity_tokens=["UserName"],
        allow_plaintext_password=True,
        accept_server_registrations=True,
    )
    assert config.suppress == ["usage"]
    assert config.identity_tokens == ["UserName"]
    assert config.allow_plaintext_password is True
    assert config.accept_server_registrations is True
    config.validate()
    client = ClientConfig(pki="./pki", suppress=[], allow_plaintext_password=True)
    assert client.suppress == []
    assert client.allow_plaintext_password is True


@pytest.mark.parametrize(
    ("fields", "setting"),
    [
        pytest.param({"profile": "x"}, "server.profile", id="profile"),
        pytest.param({"endpoint": "localhost:4840"}, "server.endpoint", id="endpoint_no_scheme"),
        pytest.param({"endpoint": "opc.tcp://host:70000/"}, "server.endpoint", id="endpoint_port"),
        pytest.param({"name": ""}, "server.name", id="name_empty"),
        pytest.param({"name": "x" * 256}, "server.name", id="name_long"),
        pytest.param({"application_uri": "no scheme"}, "server.application_uri", id="uri_space"),
        pytest.param({"application_uri": "urn:" + "x" * 300}, "server.application_uri", id="uri_long"),
        pytest.param({"product_uri": "plain"}, "server.product_uri", id="product_uri"),
        pytest.param({"manufacturer_name": ""}, "server.manufacturer_name", id="manufacturer"),
        pytest.param({"pki": None}, "server.pki", id="pki_required"),
        pytest.param({"create_pki": "yes"}, "server.create_pki", id="create_pki_type"),
        pytest.param({"private_key_password_env": "not a name"}, "server.private_key_password_env", id="env_name"),
        pytest.param({"security": []}, "server.security", id="security_empty"),
        pytest.param({"security": "Basic256Sha256,SignAndEncrypt"}, "server.security", id="security_type"),
        pytest.param({"security": ["Foo,SignAndEncrypt"]}, "server.security", id="unknown_policy"),
        pytest.param({"security": ["Basic256Sha256,Both"]}, "server.security", id="unknown_mode"),
        pytest.param({"security": ["Basic256Sha256,SignAndEncrypt"] * 2}, "server.security", id="duplicate"),
        pytest.param({"suppress": ["nothing"]}, "server.suppress", id="suppress_unknown"),
        pytest.param({"suppress": "usage"}, "server.suppress", id="suppress_type"),
        pytest.param({"identity_tokens": ["Basic"]}, "server.identity_tokens", id="token_unknown"),
        pytest.param({"identity_tokens": []}, "server.identity_tokens", id="token_empty"),
        pytest.param({"allow_plaintext_password": "yes"}, "server.allow_plaintext_password", id="plaintext_type"),
        pytest.param({"accept_server_registrations": 1}, "server.accept_server_registrations", id="registrations_type"),
        pytest.param({"anonymous": False}, "server.anonymous", id="no_identity"),
        pytest.param({"users_file": "/does/not/exist.toml"}, "server.users_file", id="users_missing"),
        pytest.param({"limits": ServerLimits(max_sessions=0)}, "server.limits.max_sessions", id="sessions_zero"),
        pytest.param(
            {"limits": ServerLimits(max_sessions=100, max_connections=50)},
            "server.limits.max_connections",
            id="connections_below_sessions",
        ),
        pytest.param(
            {"limits": ServerLimits(min_session_timeout_ms=900_000)},
            "server.limits.min_session_timeout_ms",
            id="timeouts_inverted",
        ),
        pytest.param(
            {"limits": ServerLimits(hello_timeout_seconds=500)}, "server.limits.hello_timeout_seconds", id="hello"
        ),
        pytest.param({"limits": ServerLimits(max_buffer_size=100)}, "server.limits.max_buffer_size", id="buffer"),
        pytest.param({"limits": ServerLimits(max_string_length=100)}, "server.limits.max_string_length", id="string"),
        pytest.param(
            {"limits": ServerLimits(max_byte_string_length=0)}, "server.limits.max_byte_string_length", id="bytes"
        ),
        pytest.param({"limits": ServerLimits(max_array_length=1)}, "server.limits.max_array_length", id="array"),
        pytest.param({"limits": ServerLimits(max_sessions=True)}, "server.limits.max_sessions", id="bool_is_not_int"),
    ],
)
def test_server_validation_names_the_setting(fields: dict[str, Any], setting: str) -> None:
    problems = problems_of(server(**fields))
    assert any(problem.startswith(setting + ":") for problem in problems), problems


def test_all_problems_are_reported_together() -> None:
    problems = problems_of(server(name="", endpoint="nope", security=[]))
    assert {problem.split(":")[0] for problem in problems} >= {"server.name", "server.endpoint", "server.security"}


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("localhost", True),
        ("LOCALHOST", True),
        ("127.0.0.1", True),
        ("127.0.0.5", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("[::]", False),
        ("192.0.2.1", False),
        ("plant.example.org", False),
    ],
)
def test_the_development_profile_needs_a_loopback_host(host: str, loopback: bool) -> None:
    config = server(profile="development", endpoint=f"opc.tcp://{host}:4840/x")
    client = ClientConfig(profile="development", url=f"opc.tcp://{host}:4840")
    if loopback:
        config.validate()
        client.validate()
    else:
        assert any("loopback" in p for p in problems_of(config))
        assert any(p.startswith("client.url:") and "loopback" in p for p in problems_of(client))
    server(endpoint=f"opc.tcp://{host}:4840/x").validate()


@pytest.mark.parametrize("profile", ["secure", "development", "legacy"])
@pytest.mark.parametrize(
    ("text", "risk"),
    [
        pytest.param("None", "neither signed nor encrypted", id="none"),
        pytest.param("Basic256Sha256,Sign", "signed but not encrypted", id="sign"),
        pytest.param("Basic256,SignAndEncrypt", "deprecated cipher", id="basic256"),
        pytest.param("Basic128Rsa15,SignAndEncrypt", "deprecated cipher", id="basic128rsa15"),
        pytest.param("Aes256_Sha256_RsaPss,Sign", "signed but not encrypted", id="underscored_name"),
    ],
)
def test_every_policy_and_mode_is_accepted_in_every_profile_and_logged(profile: str, text: str, risk: str) -> None:
    config = server(profile=profile, security=[text])
    config.validate()
    assert len(config.policy_types()) == 1
    lines = [line for line in config.weaknesses() if line.startswith("server.security:")]
    assert len(lines) == 1 and risk in lines[0]
    client = ClientConfig(profile=profile, pki="./pki", security=text)
    client.validate()
    assert any(line.startswith("client.security:") and risk in line for line in client.weaknesses())


def test_the_secure_profile_with_defaults_has_no_weaknesses() -> None:
    assert server().weaknesses() == []
    assert ClientConfig(pki="./pki").weaknesses() == []
    assert server(security=["Aes256Sha256RsaPss,SignAndEncrypt"]).weaknesses() == []


def test_the_weaknesses_of_the_other_profiles_name_the_profile_and_each_weak_setting() -> None:
    development = server(profile="development").weaknesses()
    assert development[0].startswith("profile development:")
    assert any(line.startswith("server.security: None:") for line in development)
    assert any(line.startswith("server.suppress: revocation_unknown") for line in development)
    assert any(line.startswith("server.allow_plaintext_password:") for line in development)
    legacy = server(profile="legacy").weaknesses()
    assert legacy[0].startswith("profile legacy:")
    assert not any(line.startswith("server.allow_plaintext_password:") for line in legacy)
    client = ClientConfig(profile="legacy", pki="./pki").weaknesses()
    assert client[0].startswith("profile legacy:")
    assert any(line.startswith("client.security: auto") for line in client)
    assert any(line.startswith("client.suppress:") for line in client)


def test_overrides_that_are_weaker_than_the_profile_are_logged() -> None:
    lines = server(
        suppress=["certificate_expired"], allow_plaintext_password=True, accept_server_registrations=True
    ).weaknesses()
    assert [line.split(":")[0] for line in lines] == [
        "server.suppress",
        "server.allow_plaintext_password",
        "server.accept_server_registrations",
    ]
    assert [line.split(":")[0] for line in ClientConfig(pki="./pki", allow_plaintext_password=True).weaknesses()] == [
        "client.allow_plaintext_password"
    ]


def test_a_unknown_policy_or_mode_is_still_an_error() -> None:
    assert any(p.startswith("server.security:") for p in problems_of(server(security=["Foo,SignAndEncrypt"])))
    assert any(p.startswith("server.security:") for p in problems_of(server(security=["Basic256Sha256,Both"])))
    assert any(p.startswith("client.security:") for p in problems_of(ClientConfig(pki="./pki", security="Foo,Sign")))


def test_auto_is_a_client_security_and_has_no_fixed_policy() -> None:
    config = ClientConfig(pki="./pki", security="auto")
    config.validate()
    assert config.automatic_security()
    with pytest.raises(ConfigurationError, match="auto"):
        config.policy_type()
    ClientConfig(profile="legacy").validate()


def test_a_toml_file_with_allow_no_security_names_an_unknown_setting(tmp_path: Path) -> None:
    path = write(tmp_path, '[server]\npki = "pki"\nallow_no_security = true\n')
    with pytest.raises(ConfigurationError, match=r"server\.allow_no_security: unknown setting"):
        ServerConfig.from_toml(path)
    assert "allow_no_security" not in server().dump()


def test_a_secure_profile_override_may_narrow_the_policy_list() -> None:
    config = server(security=["Aes256Sha256RsaPss,SignAndEncrypt"])
    config.validate()
    assert config.security == ["Aes256Sha256RsaPss,SignAndEncrypt"]


def test_users_need_a_policy_with_encryption(tmp_path: Path) -> None:
    path = tmp_path / "users.toml"
    users_file.write_users(path, [])
    config = server(profile="development", security=["None"], pki=None, users_file=str(path))
    assert any(p.startswith("server.users_file:") and "encryption" in p for p in problems_of(config))


def test_users_file_and_user_manager_exclude_each_other(tmp_path: Path) -> None:
    from enginir_opcua.server.user_managers import AnonymousReadOnlyUserManager

    path = tmp_path / "users.toml"
    users_file.write_users(path, [])
    config = server(users_file=str(path), user_manager=AnonymousReadOnlyUserManager())
    assert any(p.startswith("server.user_manager:") for p in problems_of(config))


@pytest.mark.parametrize(("profile", "logged"), [("secure", True), ("development", False), ("legacy", True)])
def test_the_permissive_manager_is_a_weakness_not_an_error(profile: str, logged: bool) -> None:
    from enginir_opcua.server.user_managers import PermissiveUserManager

    config = server(profile=profile, user_manager=PermissiveUserManager())
    config.validate()
    lines = [line for line in config.weaknesses() if line.startswith("server.user_manager:")]
    assert bool(lines) is logged


def test_the_users_file_is_read_by_validate(tmp_path: Path) -> None:
    path = tmp_path / "users.toml"
    path.write_text("version = 1\n[[user]]\nname = 'a'\nrole = 'user'\n")
    problems = problems_of(server(users_file=str(path)))
    assert any(p.startswith("server.users_file:") and "password_hash" in p for p in problems)


def test_the_environment_names_a_users_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "users.toml"
    path.write_text("version = 1\n[[user]]\nname = 'a'\n")
    monkeypatch.setenv("ENGINIR_OPCUA_USERS_FILE", str(path))
    assert problems_of(server())


def test_pki_that_cannot_be_created_or_found(tmp_path: Path) -> None:
    blocked = tmp_path / "file"
    blocked.write_text("x")
    assert any(p.startswith("server.pki:") for p in problems_of(server(pki=str(blocked / "pki"))))
    assert any(p.startswith("server.pki:") for p in problems_of(server(pki=str(tmp_path / "none"), create_pki=False)))


def test_client_validation_names_the_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENGINIR_OPCUA_PASSWORD", raising=False)
    cases: list[tuple[dict[str, Any], str]] = [
        ({"url": "opc.tcp://u:p@host:4840"}, "client.url"),
        ({"url": "http://host"}, "client.url"),
        ({"pki": None}, "client.pki"),
        ({"security": "Foo,Sign"}, "client.security"),
        ({"security": "Basic256Sha256,Both"}, "client.security"),
        ({"suppress": ["nothing"]}, "client.suppress"),
        ({"allow_plaintext_password": "yes"}, "client.allow_plaintext_password"),
        ({"timeout": 0}, "client.timeout"),
        ({"timeout": 10_000}, "client.timeout"),
        ({"session_timeout_ms": 10}, "client.session_timeout_ms"),
        ({"username": "alice"}, "client.password"),
        ({"password": "x"}, "client.username"),
        ({"server_certificate": "/no/such/file.der"}, "client.server_certificate"),
        ({"auto_reconnect": 1}, "client.auto_reconnect"),
    ]
    for fields, setting in cases:
        fields.setdefault("pki", "./pki") if "pki" not in fields else None
        problems = problems_of(ClientConfig(**fields))
        assert any(p.startswith(setting + ":") for p in problems), (fields, problems)


def test_a_client_password_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENGINIR_OPCUA_PASSWORD", "secret")
    ClientConfig(pki="./pki", username="alice").validate()
    monkeypatch.setenv("OTHER_PASSWORD", "x")
    ClientConfig(pki="./pki", username="alice", password_env="OTHER_PASSWORD").validate()
    monkeypatch.delenv("OTHER_PASSWORD")
    assert any(
        "OTHER_PASSWORD" in p
        for p in problems_of(ClientConfig(pki="./pki", username="a", password_env="OTHER_PASSWORD"))
    )


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "server.toml"
    path.write_text(text)
    return path


def test_toml_round_trip(tmp_path: Path) -> None:
    config = server(
        pki=str(tmp_path / "pki"),
        name="Plant",
        application_uri="urn:plant:server",
        limits=ServerLimits(max_sessions=7, max_connections=70),
        security=["Aes128Sha256RsaOaep,SignAndEncrypt"],
    )
    path = tmp_path / "server.toml"
    config.dump(path)
    assert ServerConfig.from_toml(path) == config
    client = ClientConfig(pki=str(tmp_path / "pki"), url="opc.tcp://plant:4840", timeout=2.5, auto_reconnect=True)
    client.dump(path)
    assert ClientConfig.from_toml(path) == client
    for profile in ("development", "legacy"):
        other = server(profile=profile, pki=str(tmp_path / "pki"))
        other.dump(path)
        assert ServerConfig.from_toml(path) == other
        client_other = ClientConfig(profile=profile, pki=str(tmp_path / "pki"))
        client_other.dump(path)
        assert ClientConfig.from_toml(path) == client_other


def test_dump_is_commented_and_holds_no_secret(tmp_path: Path) -> None:
    config = ClientConfig(pki="./pki", username="alice", password="hunter2", url="opc.tcp://h:4840")
    path = tmp_path / "client.toml"
    text = config.dump(path)
    assert "hunter2" not in text and "hunter2" not in path.read_text()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert text.startswith("#")
    body = tomllib.loads(text)["client"]
    assert body["username"] == "alice" and "password" not in body
    assert "# users_file" in server().dump()
    assert "\n# " in text


def test_toml_relative_paths_follow_the_file(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    path = tmp_path / "etc" / "server.toml"
    path.write_text('[server]\npki = "pki"\n')
    assert ServerConfig.from_toml(path).pki == str(tmp_path / "etc" / "pki")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param("[server]\ncolour = 1\n", r"server\.colour: unknown setting", id="unknown_key"),
        pytest.param("[server]\npassword = 'x'\n", "passwords are not stored", id="password_key"),
        pytest.param("[server]\nprivate_key_password = 'x'\n", "passwords are not stored", id="key_password"),
        pytest.param("[server.limits]\nmax_x = 1\n", r"server\.limits\.max_x: unknown setting", id="unknown_limit"),
        pytest.param("[other]\n", r"no \[server\] table", id="no_table"),
        pytest.param("[server\n", "line 1", id="syntax"),
        pytest.param("[server]\nname = 5\n", r"server\.name", id="type"),
        pytest.param("[server]\nname = ''\n", r"server\.name", id="invalid_value"),
        pytest.param("[server]\nuser_manager = 'x'\n", r"server\.user_manager: unknown", id="code_only_key"),
    ],
)
def test_toml_errors_name_the_file_and_the_setting(tmp_path: Path, text: str, message: str) -> None:
    path = write(tmp_path, text)
    with pytest.raises(ConfigurationError, match=message) as error:
        ServerConfig.from_toml(path)
    assert str(path) in str(error.value)


def test_a_file_with_both_tables_serves_both_classes(tmp_path: Path) -> None:
    path = write(tmp_path, '[server]\npki = "s"\n[client]\npki = "c"\n')
    assert ServerConfig.from_toml(path).pki == str(tmp_path / "s")
    assert ClientConfig.from_toml(path).pki == str(tmp_path / "c")


def test_dataclass_fields_are_all_documented_in_the_dump() -> None:
    text = server().dump()
    for field in dataclasses.fields(ServerConfig):
        if field.metadata.get("toml", True) and field.name != "limits":
            assert field.name in text


@pytest.mark.parametrize(
    "url",
    [
        "opc.tcp://alice:s3cret@host:4840",
        "http://alice:s3cret@host:4840",
        "opc.tcp://alice:s3cret@host:99999",
        "opc.tcp://alice:s3cret@:4840",
    ],
)
def test_url_errors_do_not_show_the_password(url: str) -> None:
    with pytest.raises(ConfigurationError) as refused:
        parse_opc_tcp_url(url)
    assert "s3cret" not in str(refused.value)
    assert "alice@" in str(refused.value)

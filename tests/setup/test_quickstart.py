import logging
import socket
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.config import ClientConfig, ServerConfig, ServerLimits
from enginir_opcua.crypto import pki
from enginir_opcua.crypto.security_policies import SecurityPolicyAes256Sha256RsaPss, SecurityPolicyNone
from enginir_opcua.server.user_managers import AnonymousReadOnlyUserManager, FileUserManager, PermissiveUserManager
from enginir_opcua.ua.uaerrors import ConfigurationError
from tests.conftest import find_free_port
from tests.setup.conftest import PASSWORD, make_credentials, trust

URL = "opc.tcp://127.0.0.1:4840/quick/"


def test_quickstart_applies_the_secure_profile(tmp_path: Path, users: Path) -> None:
    server = Server.quickstart(URL, pki=tmp_path / "pki", users=users, name="Plant")
    assert server.endpoint.geturl() == URL
    assert server.name == "Plant"
    assert server.get_application_uri() == f"urn:{socket.gethostname()}:enginir-opcua:server"
    assert server._security_policy == [
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
        ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
        ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
    ]
    assert isinstance(server.iserver.user_manager, FileUserManager)
    assert not server.allow_plaintext_password


@pytest.mark.parametrize(
    ("profile", "plaintext", "suppressed", "policy_count"),
    [
        pytest.param("secure", False, set(), 3, id="secure"),
        pytest.param(
            "development",
            True,
            {"revocation_unknown", "issuer_revocation_unknown", "host_name_invalid"},
            2,
            id="development",
        ),
        pytest.param(
            "legacy", False, {"revocation_unknown", "issuer_revocation_unknown", "host_name_invalid"}, 11, id="legacy"
        ),
    ],
)
def test_a_configured_server_applies_the_posture_of_its_profile(
    tmp_path: Path, profile: str, plaintext: bool, suppressed: set[str], policy_count: int
) -> None:
    server = Server.quickstart(URL, profile=profile, pki=tmp_path / "pki")
    assert server.allow_plaintext_password is plaintext
    assert set(server._suppress) == suppressed
    assert len(server._security_policy) == policy_count
    assert server.iserver.accept_server_registrations is False


def test_a_configured_server_applies_its_overrides(tmp_path: Path) -> None:
    server = Server.quickstart(
        URL,
        pki=tmp_path / "pki",
        suppress=["certificate_expired"],
        identity_tokens=["UserName", "Certificate"],
        allow_plaintext_password=True,
        accept_server_registrations=True,
    )
    assert server._suppress == ("certificate_expired",)
    assert server.iserver.supported_tokens == (ua.UserNameIdentityToken, ua.X509IdentityToken)
    assert server.allow_plaintext_password is True
    assert server.iserver.accept_server_registrations is True


async def test_a_configured_server_gives_its_suppressions_to_the_validator(tmp_path: Path, port: int) -> None:
    server = Server.quickstart(
        f"opc.tcp://127.0.0.1:{port}/s/", profile="development", pki=tmp_path / "pki", suppress=["usage"]
    )
    await server.init()
    async with server:
        validator = server.iserver.certificate_validator
        assert validator is not None
        assert {suppression.value for suppression in validator.suppressions} == {"usage"}


async def test_a_configured_server_logs_its_weaknesses_once_at_start(
    tmp_path: Path, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    server = Server.quickstart(f"opc.tcp://127.0.0.1:{port}/w/", profile="legacy", pki=tmp_path / "pki")
    await server.init()
    with caplog.at_level(logging.WARNING):
        async with server:
            pass
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert server._config is not None
    for line in server._config.weaknesses():
        assert messages.count(line) == 1
    assert not [m for m in messages if m.startswith("opc.tcp://") or "The deprecated policy" in m]


def test_quickstart_without_users_accepts_anonymous_only(tmp_path: Path) -> None:
    server = Server.quickstart(URL, pki=tmp_path / "pki")
    assert isinstance(server.iserver.user_manager, AnonymousReadOnlyUserManager)


async def test_push_management_in_the_config_is_enabled_by_init(tmp_path: Path) -> None:
    server = Server.quickstart(URL, pki=tmp_path / "pki", push_management=True)
    await server.init()
    assert server._certificate_manager is not None
    plain = Server.quickstart(URL, pki=tmp_path / "pki")
    await plain.init()
    assert plain._certificate_manager is None


def test_quickstart_applies_limits_and_overrides(tmp_path: Path) -> None:
    limits = ServerLimits(max_sessions=7, max_connections=70, max_message_size=1_000_000, max_buffer_size=16_384)
    server = Server.quickstart(URL, pki=tmp_path / "pki", limits=limits, security=["Aes256Sha256RsaPss,SignAndEncrypt"])
    assert server.iserver.session_manager.max_sessions == 7
    assert server.iserver.max_connections == 70
    assert server.limits.max_message_size == 1_000_000
    assert server.limits.max_recv_buffer == server.limits.max_send_buffer == 16_384
    assert server._security_policy == [ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt]


def test_quickstart_refuses_unknown_and_invalid_settings(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"server\.colour: unknown setting"):
        Server.quickstart(URL, pki=tmp_path, colour="red")
    with pytest.raises(ConfigurationError, match=r"server\.endpoint: the development profile only listens on"):
        Server.quickstart("opc.tcp://0.0.0.0:4840", profile="development", pki=tmp_path)
    with pytest.raises(ConfigurationError, match=r"client\.url"):
        Client.quickstart("opc.tcp://u:p@host:4840", pki=tmp_path)


def test_a_config_replaces_the_other_constructor_arguments(tmp_path: Path) -> None:
    config = ServerConfig(pki=tmp_path)
    with pytest.raises(ConfigurationError, match="config replaces"):
        Server(user_manager=AnonymousReadOnlyUserManager(), config=config)
    with pytest.raises(ConfigurationError, match="config replaces"):
        Server(allow_no_security=True, config=config)
    with pytest.raises(ConfigurationError, match="url comes from the config"):
        Client(URL, config=ClientConfig(pki=tmp_path))
    with pytest.raises(ConfigurationError, match="url"):
        Client()


def test_a_client_config_sets_names_and_timeouts(tmp_path: Path) -> None:
    client = Client(
        config=ClientConfig(
            pki=tmp_path,
            url=URL,
            name="Probe",
            application_uri="urn:probe",
            session_timeout_ms=60_000,
            timeout=2.5,
            auto_reconnect=True,
            username="a",
            password="b",
        )
    )
    assert (client.name, client.application_uri, client.session_timeout) == ("Probe", "urn:probe", 60_000)
    assert client.uaclient._timeout == 2.5 and client._auto_reconnect is True
    assert client.server_url.geturl() == URL


async def test_init_creates_the_pki_directory_and_trusts_nothing(tmp_path: Path) -> None:
    server = Server.quickstart(URL, pki=tmp_path / "pki")
    assert not (tmp_path / "pki").exists()
    await server.init()
    certificate = server.iserver.certificate
    assert certificate is not None
    assert server.get_application_uri() in pki_uris(certificate)
    assert list((tmp_path / "pki" / "trusted" / "certs").iterdir()) == []


def pki_uris(certificate: object) -> list[str]:
    from cryptography import x509

    assert isinstance(certificate, x509.Certificate)
    return certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.UniformResourceIdentifier
    )


async def test_cry31_a_certificate_with_another_application_uri_is_an_error(tmp_path: Path) -> None:
    await make_credentials(tmp_path / "pki", "urn:someone:else", pki.SERVER_USAGE)
    server = Server.quickstart(URL, pki=tmp_path / "pki")
    with pytest.raises(ConfigurationError, match=r"server\.pki: .*urn:someone:else.*application_uri"):
        await server.init()


async def test_a_missing_private_key_password_variable_names_the_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PLANT_KEY_PASSWORD", raising=False)
    server = Server.quickstart(URL, pki=tmp_path / "pki", private_key_password_env="PLANT_KEY_PASSWORD")
    with pytest.raises(ConfigurationError, match=r"server\.private_key_password_env: .*PLANT_KEY_PASSWORD"):
        await server.init()


async def test_a_missing_pki_without_create_is_reported_by_validation(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"server\.pki"):
        Server.quickstart(URL, pki=tmp_path / "none", create_pki=False)


async def test_a_secure_pair_connects_and_reads(paired: tuple[Server, Client]) -> None:
    _, client = paired
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    assert client.security_policy.URI.endswith("Basic256Sha256")


async def test_the_pair_is_applied_once_and_reconnects(paired: tuple[Server, Client]) -> None:
    _, client = paired
    await client.connect()
    first = client.security_policy
    await client.disconnect()
    await client.connect()
    assert client.security_policy is first
    await client.disconnect()


async def test_a_wrong_password_is_refused(paired: tuple[Server, Client], tmp_path: Path) -> None:
    server, _ = paired
    client = Client.quickstart(server.endpoint.geturl(), pki=tmp_path / "client-pki", username="alice", password="no")
    with pytest.raises(ua.UaError):
        await client.connect()


async def test_nothing_is_trusted_automatically(tmp_path: Path, port: int) -> None:
    url = f"opc.tcp://127.0.0.1:{port}/quick/"
    server = Server.quickstart(url, pki=tmp_path / "s")
    await server.init()
    async with server:
        client = Client.quickstart(url, pki=tmp_path / "c")
        with pytest.raises(ua.UaError):
            await client.connect()
    assert list((tmp_path / "s" / "trusted" / "certs").iterdir()) == []


async def test_the_development_profile_offers_no_security_and_warns(
    tmp_path: Path, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    url = f"opc.tcp://127.0.0.1:{port}/dev/"
    server = Server.quickstart(url, profile="development", pki=tmp_path / "pki")
    await server.init()
    with caplog.at_level(logging.WARNING):
        await server.start()
    try:
        assert "profile development" in caplog.text
        modes = {e.SecurityMode for e in await server.get_endpoints()}
        assert ua.MessageSecurityMode.None_ in modes
        async with Client.quickstart(url, profile="development") as client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    finally:
        await server.stop()


async def test_srv105_a_development_server_refuses_a_non_loopback_bind(tmp_path: Path, port: int) -> None:
    server = Server.quickstart(f"opc.tcp://127.0.0.1:{port}/", profile="development", pki=tmp_path / "pki")
    await server.init()
    server.socket_address = ("0.0.0.0", port)
    with pytest.raises(ConfigurationError, match="socket_address"):
        await server.start()


async def test_the_secure_profile_has_no_none_endpoint(paired: tuple[Server, Client]) -> None:
    server, _ = paired
    modes = {e.SecurityMode for e in await server.get_endpoints()}
    assert modes == {ua.MessageSecurityMode.SignAndEncrypt}


def test_the_client_derives_its_application_uri(tmp_path: Path) -> None:
    client = Client.quickstart(URL, pki=tmp_path)
    assert client.application_uri == f"urn:{socket.gethostname()}:enginir-opcua:client"
    assert Client(URL).application_uri == "urn:enginir:opcua:client"


async def test_a_pinned_server_certificate_is_trusted(tmp_path: Path, port: int) -> None:
    url = f"opc.tcp://127.0.0.1:{port}/quick/"
    server = Server.quickstart(url, pki=tmp_path / "s")
    await server.init()
    await make_credentials(tmp_path / "c", "urn:pinned:client", pki.CLIENT_USAGE)
    trust(tmp_path / "s", tmp_path / "c")
    pinned = tmp_path / "server.der"
    pinned.write_bytes((tmp_path / "s" / "own" / "certs" / pki.CERTIFICATE_NAME).read_bytes())
    async with server:
        client = Client.quickstart(
            url, pki=tmp_path / "c", application_uri="urn:pinned:client", server_certificate=pinned
        )
        async with client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running


def test_the_sync_twins_of_quickstart(tmp_path: Path) -> None:
    from enginir_opcua import sync

    url = f"opc.tcp://127.0.0.1:{find_free_port()}/sync/"
    server = sync.Server.quickstart(url, profile="development", pki=tmp_path / "pki")
    server.start()
    try:
        client = sync.Client.quickstart(url, profile="development")
        client.connect()
        try:
            assert client.nodes.server_state.read_value() == ua.ServerState.Running
        finally:
            client.disconnect()
    finally:
        server.stop()


async def test_cli84_init_pki_creates_the_client_certificate_before_connect(tmp_path: Path, port: int) -> None:
    client = Client.quickstart(f"opc.tcp://127.0.0.1:{port}/quick/", pki=tmp_path / "client-pki")
    certificate = await client.init_pki()
    assert (tmp_path / "client-pki" / "own" / "certs" / pki.CERTIFICATE_NAME).exists()
    assert client.application_uri in pki_uris(certificate)
    assert await client.init_pki() == certificate


async def test_cli84_init_pki_needs_a_pki_directory() -> None:
    with pytest.raises(ConfigurationError, match="init_pki"):
        await Client("opc.tcp://127.0.0.1:4840/").init_pki()
    with pytest.raises(ConfigurationError, match="init_pki"):
        await Server().init_pki()


async def test_cli84_init_pki_creates_the_server_certificate_before_init(tmp_path: Path, port: int) -> None:
    server = Server.quickstart(f"opc.tcp://127.0.0.1:{port}/quick/", pki=tmp_path / "server-pki")
    certificate = await server.init_pki()
    assert (tmp_path / "server-pki" / "own" / "certs" / pki.CERTIFICATE_NAME).exists()
    assert server.get_application_uri() in pki_uris(certificate)
    assert await server.init_pki() == certificate
    await server.init()
    assert server.iserver.certificate == certificate


async def test_cli84_a_pair_without_the_pki_helpers(tmp_path: Path, port: int) -> None:
    url = f"opc.tcp://127.0.0.1:{port}/quick/"
    server = Server.quickstart(url, pki=tmp_path / "server-pki")
    client = Client.quickstart(url, pki=tmp_path / "client-pki")
    await client.init_pki()
    await server.init()
    trust(tmp_path / "server-pki", tmp_path / "client-pki")
    trust(tmp_path / "client-pki", tmp_path / "server-pki")
    async with server, client:
        assert await client.nodes.root.read_browse_name() == ua.QualifiedName("Root", 0)


def test_cli85_the_sync_quickstarts_share_one_thread_loop(tmp_path: Path) -> None:
    from enginir_opcua import sync

    url = f"opc.tcp://127.0.0.1:{find_free_port()}/sync/"
    with sync.ThreadLoop() as tloop:
        server = sync.Server.quickstart(url, profile="development", pki=tmp_path / "pki", tloop=tloop)
        client = sync.Client.quickstart(url, profile="development", tloop=tloop)
        assert server.tloop is tloop
        assert client.tloop is tloop
        assert not server.close_tloop
        assert not client.close_tloop
        server.start()
        try:
            with client:
                assert client.nodes.server_state.read_value() == ua.ServerState.Running
        finally:
            server.stop()
        assert tloop.is_alive()


async def _legacy_pair(tmp_path: Path, port: int, client_pki: Path | None) -> tuple[Server, Client]:
    url = f"opc.tcp://127.0.0.1:{port}/auto/"
    server = Server.quickstart(url, profile="legacy", pki=tmp_path / "server-pki")
    client = Client.quickstart(url, profile="legacy", pki=client_pki)
    await server.init()
    if client_pki is not None:
        await make_credentials(client_pki, client.application_uri, pki.CLIENT_USAGE)
        trust(tmp_path / "server-pki", client_pki)
        trust(client_pki, tmp_path / "server-pki")
    return server, client


async def test_an_automatic_client_picks_the_strongest_offered_policy(
    tmp_path: Path, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    server, client = await _legacy_pair(tmp_path, port, tmp_path / "client-pki")
    with caplog.at_level(logging.INFO):
        async with server, client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    assert isinstance(client.security_policy, SecurityPolicyAes256Sha256RsaPss)
    assert client.security_policy.Mode == ua.MessageSecurityMode.SignAndEncrypt
    chosen = [r for r in caplog.records if r.levelno == logging.INFO and "Aes256Sha256RsaPss" in r.getMessage()]
    assert len(chosen) == 1 and "SignAndEncrypt" in chosen[0].getMessage()
    assert not [r for r in caplog.records if r.levelno == logging.WARNING and "without security" in r.getMessage()]


async def test_an_automatic_client_without_a_pki_falls_back_to_no_security(
    tmp_path: Path, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    server, client = await _legacy_pair(tmp_path, port, None)
    with caplog.at_level(logging.INFO):
        async with server, client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    assert isinstance(client.security_policy, SecurityPolicyNone)
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("without security" in m and "neither signed nor encrypted" in m for m in messages)
    assert any("no security" in r.getMessage() and r.levelno == logging.INFO for r in caplog.records)


async def test_an_automatic_client_falls_back_when_the_server_offers_only_no_security(
    tmp_path: Path, port: int
) -> None:
    url = f"opc.tcp://127.0.0.1:{port}/auto/"
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(url)
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await make_credentials(tmp_path / "client-pki", "urn:auto:client", pki.CLIENT_USAGE)
    client = Client.quickstart(url, profile="legacy", pki=tmp_path / "client-pki", application_uri="urn:auto:client")
    async with server, client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    assert isinstance(client.security_policy, SecurityPolicyNone)


async def test_an_automatic_client_applies_its_choice_once(tmp_path: Path, port: int) -> None:
    server, client = await _legacy_pair(tmp_path, port, tmp_path / "client-pki")
    async with server:
        await client.connect()
        first = client.security_policy
        await client.disconnect()
        await client.connect()
        assert client.security_policy is first
        await client.disconnect()


async def test_a_configured_client_logs_its_weaknesses_once_per_connect(
    tmp_path: Path, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    url = f"opc.tcp://127.0.0.1:{port}/w/"
    server = Server.quickstart(url, profile="development", pki=tmp_path / "pki")
    await server.init()
    client = Client.quickstart(url, profile="development")
    async with server:
        with caplog.at_level(logging.WARNING):
            await client.connect()
            await client.get_namespace_array()
            await client.disconnect()
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert client._config is not None
    lines = client._config.weaknesses()
    assert lines
    for line in lines:
        assert messages.count(line) == 1


async def test_a_secure_client_logs_no_weakness(paired: tuple[Server, Client]) -> None:
    _, client = paired
    assert client._config is not None and client._config.weaknesses() == []


async def test_a_configured_client_gives_its_suppressions_to_the_validator(tmp_path: Path) -> None:
    client = Client.quickstart(URL, profile="development", suppress=["usage"])
    await client._prepare_certificate_validation()
    validator = client._default_validator
    assert validator is not None
    assert {suppression.value for suppression in validator.suppressions} == {"usage"}


@pytest.mark.parametrize(
    ("profile", "plaintext"),
    [pytest.param("development", True, id="development"), pytest.param("legacy", False, id="legacy")],
)
def test_a_configured_client_takes_the_plaintext_posture_of_its_profile(
    tmp_path: Path, profile: str, plaintext: bool
) -> None:
    assert Client.quickstart(URL, profile=profile, pki=tmp_path).allow_plaintext_password is plaintext
    assert Client.quickstart(URL, profile=profile, pki=tmp_path, allow_plaintext_password=True).allow_plaintext_password


async def _clear_text_server(port: int) -> Server:
    server = Server(allow_no_security=True, user_manager=PermissiveUserManager())
    server.allow_plaintext_password = True
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}/dev/")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    return server


async def test_a_development_client_sends_its_password_in_clear_text(
    port: int, caplog: pytest.LogCaptureFixture
) -> None:
    server = await _clear_text_server(port)
    async with server:
        client = Client.quickstart(
            f"opc.tcp://127.0.0.1:{port}/dev/", profile="development", username="alice", password=PASSWORD
        )
        with caplog.at_level(logging.WARNING):
            async with client:
                assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    assert any("Sending the password in clear text" in r.getMessage() for r in caplog.records)


async def test_a_legacy_client_refuses_a_clear_text_password(port: int) -> None:
    server = await _clear_text_server(port)
    async with server:
        client = Client.quickstart(
            f"opc.tcp://127.0.0.1:{port}/dev/", profile="legacy", pki=None, username="alice", password=PASSWORD
        )
        with pytest.raises(ConfigurationError, match="allow_plaintext_password"):
            await client.connect()

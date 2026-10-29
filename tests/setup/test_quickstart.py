import logging
import socket
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.config import ClientConfig, ServerConfig, ServerLimits
from enginir_opcua.crypto import pki
from enginir_opcua.server.user_managers import AnonymousReadOnlyUserManager, FileUserManager
from enginir_opcua.ua.uaerrors import ConfigurationError
from tests.conftest import find_free_port
from tests.setup.conftest import make_credentials, trust

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


def test_quickstart_without_users_accepts_anonymous_only(tmp_path: Path) -> None:
    server = Server.quickstart(URL, pki=tmp_path / "pki")
    assert isinstance(server.iserver.user_manager, AnonymousReadOnlyUserManager)


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
        assert "development profile" in caplog.text and url in caplog.text
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

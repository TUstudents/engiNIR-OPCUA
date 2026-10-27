import asyncio
from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ha.ha_client import HaClient, HaConfig, HaMode, HaSecurityConfig
from enginir_opcua.crypto import security_policies
from enginir_opcua.crypto.uacrypto import CertProperties

from .conftest import find_free_port
from .harness import EXAMPLES, ResponseTampering, TwoUserManager, make_certificate


@pytest.fixture
async def two_endpoint_server() -> AsyncIterator[Server]:
    srv = Server(user_manager=TwoUserManager())
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_Sign])
    srv.set_identity_tokens([ua.UserNameIdentityToken])
    await srv.load_certificate(EXAMPLES / "certificate-example.der")
    await srv.load_private_key(EXAMPLES / "private-key-example.pem")
    await srv.start()
    yield srv
    await srv.stop()


async def _discovering_client(server: Server) -> Client:
    client = Client(server.endpoint.geturl())
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        EXAMPLES / "certificates" / "peer-certificate-example-1.der",
        EXAMPLES / "certificates" / "peer-private-key-example-1.pem",
        None,
        None,
        ua.MessageSecurityMode.Sign,
    )
    client.set_user("alice")
    client.set_password("alice-password")
    return client


async def test_cli7_unchanged_endpoint_list_is_accepted(two_endpoint_server: Server) -> None:
    """Part 4, 5.7.2.2: the endpoints of CreateSession equal those the client found by discovery."""
    client = await _discovering_client(two_endpoint_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


def _drop_secure_endpoints(response: ua.CreateSessionResponse) -> None:
    response.Parameters.ServerEndpoints = [
        endpoint
        for endpoint in response.Parameters.ServerEndpoints
        if endpoint.SecurityMode == ua.MessageSecurityMode.None_
    ]


def _swap_server_certificate(response: ua.CreateSessionResponse) -> None:
    other, _ = make_certificate("urn:example:other")
    for endpoint in response.Parameters.ServerEndpoints:
        endpoint.ServerCertificate = other


def _add_anonymous_policy(response: ua.CreateSessionResponse) -> None:
    for endpoint in response.Parameters.ServerEndpoints:
        endpoint.UserIdentityTokens.append(
            ua.UserTokenPolicy(PolicyId="anonymous", TokenType=ua.UserTokenType.Anonymous)
        )


@pytest.mark.parametrize("change", [_drop_secure_endpoints, _swap_server_certificate, _add_anonymous_policy])
async def test_cli7_changed_endpoint_list_closes_the_connection(
    change: object, two_endpoint_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.2: a CreateSession endpoint list that differs from the discovery result is refused."""
    tampered_responses.on(ua.CreateSessionResponse, change)  # type: ignore[arg-type]
    client = await _discovering_client(two_endpoint_server)
    with pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
        await client.connect()
    await client.disconnect()
    assert not client.uaclient.has_transport


def test_cli11_refresh_endpoints_quiet_is_gone() -> None:
    """The reconnect path never fetches endpoints over an unsecured channel to refresh its trust."""
    assert not hasattr(Client, "_refresh_endpoints_quiet")


async def test_cli11_security_error_during_reconnect_does_not_fetch_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    """The reconnect supervisor retries after a security error without a GetEndpoints call."""
    client = Client("opc.tcp://127.0.0.1:1")
    attempts: list[int] = []
    fetched: list[int] = []

    async def failing_then_working() -> bool:
        attempts.append(1)
        if len(attempts) == 1:
            raise ua.uaerrors.BadSecurityChecksFailed
        return False

    async def fetch_endpoints() -> list[ua.EndpointDescription]:
        fetched.append(1)
        return []

    async def nothing(*arguments: object) -> None:
        return None

    monkeypatch.setattr(client, "_try_reactivate_existing_session", failing_then_working)
    monkeypatch.setattr(client, "connect_and_get_server_endpoints", fetch_endpoints)
    monkeypatch.setattr(client, "_teardown_transport_only", nothing)
    monkeypatch.setattr(client, "_finalize_reconnect", nothing)
    monkeypatch.setattr(client.uaclient, "enter_reconnecting", lambda: None)
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda delay: real_sleep(0))
    assert await client._reconnect_with_backoff() is True
    assert len(attempts) == 2
    assert fetched == []


def test_cli14_ha_security_without_server_certificate_is_a_configuration_error() -> None:
    """Part 4, 5.7.2.2: an HA client with security on must be given the server certificate, not fetch it."""
    certificate = CertProperties(EXAMPLES / "certificate-example.der", "DER")
    key = CertProperties(EXAMPLES / "private-key-example.pem", "PEM")
    with pytest.raises(ValueError, match="server_certificate"):
        HaSecurityConfig(security_policies.SecurityPolicyBasic256Sha256, certificate, key)
    config = HaConfig(HaMode.WARM, urls=["opc.tcp://127.0.0.1:1"])
    with pytest.raises(ValueError, match="server_certificate"):
        HaClient(config).set_security(security_policies.SecurityPolicyBasic256Sha256, certificate, key)


def test_cli14_ha_security_with_server_certificate_and_no_security_are_accepted() -> None:
    """Part 4, 5.7.2.2: a configured server certificate is fine, and so is no security at all."""
    certificate = CertProperties(EXAMPLES / "certificate-example.der", "DER")
    key = CertProperties(EXAMPLES / "private-key-example.pem", "PEM")
    assert HaSecurityConfig().policy is None
    secured = HaSecurityConfig(security_policies.SecurityPolicyBasic256Sha256, certificate, key, certificate)
    assert secured.server_certificate == certificate

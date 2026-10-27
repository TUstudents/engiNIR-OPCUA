import asyncio
from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ha.ha_client import HaClient, HaConfig, HaMode, HaSecurityConfig
from enginir_opcua.crypto import security_policies
from enginir_opcua.crypto.uacrypto import CertProperties, x509_from_der

from .conftest import find_free_port
from .harness import EXAMPLES, PKI, ResponseTampering, TwoUserManager, make_certificate, signing_client


@pytest.fixture
async def two_endpoint_server() -> AsyncIterator[Server]:
    srv = Server(allow_no_security=True, user_manager=TwoUserManager())
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_Sign])
    srv.set_identity_tokens([ua.UserNameIdentityToken])
    await srv.load_certificate(PKI.server.certificate)
    await srv.load_private_key(PKI.server.key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    yield srv
    await srv.stop()


async def _discovering_client(server: Server) -> Client:
    client = Client(server.endpoint.geturl())
    client.set_trust_store(PKI.trust_store())
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        PKI.peer1.certificate,
        PKI.peer1.key,
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
    config = HaConfig(HaMode.WARM, urls=["opc.tcp://127.0.0.1:1", "opc.tcp://127.0.0.1:2"])
    with pytest.raises(ValueError, match="server_certificate"):
        HaClient(config).set_security(security_policies.SecurityPolicyBasic256Sha256, certificate, key)


def test_cli14_ha_security_with_a_trust_store_is_accepted() -> None:
    """Part 4, 5.7.2.2: a trust store is an alternative to a pinned server certificate."""
    certificate = CertProperties(EXAMPLES / "certificate-example.der", "DER")
    key = CertProperties(EXAMPLES / "private-key-example.pem", "PEM")
    store = PKI.trust_store()
    secured = HaSecurityConfig(security_policies.SecurityPolicyBasic256Sha256, certificate, key, trust_store=store)
    assert secured.trust_store is store
    config = HaConfig(HaMode.WARM, urls=["opc.tcp://127.0.0.1:1", "opc.tcp://127.0.0.1:2"])
    ha = HaClient(config)
    ha.set_security(security_policies.SecurityPolicyBasic256Sha256, certificate, key, trust_store=store)
    assert ha.security_config.trust_store is store


async def test_cli14_ha_reconnect_gives_the_trust_store_to_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.7.2.2: the clients of an HA client validate the server certificate with the configured store."""
    certificate = CertProperties(EXAMPLES / "certificate-example.der", "DER")
    key = CertProperties(EXAMPLES / "private-key-example.pem", "PEM")
    store = PKI.trust_store()
    config = HaConfig(HaMode.WARM, urls=["opc.tcp://127.0.0.1:1", "opc.tcp://127.0.0.1:2"])
    ha = HaClient(config)
    ha.set_security(security_policies.SecurityPolicyBasic256Sha256, certificate, key, trust_store=store)
    client = next(iter(ha.clients))
    seen: list[object] = []

    async def noop(*arguments: object, **keywords: object) -> None:
        return None

    async def record_security(**keywords: object) -> None:
        seen.append(keywords)

    monkeypatch.setattr(client, "disconnect", noop)
    monkeypatch.setattr(client, "connect", noop)
    monkeypatch.setattr(client, "set_security", record_security)
    await ha.reconnect(client)
    assert client.trust_store is store
    assert seen and "trust_store" not in seen[0]  # type: ignore[operator]


def test_cli14_ha_security_with_server_certificate_and_no_security_are_accepted() -> None:
    """Part 4, 5.7.2.2: a configured server certificate is fine, and so is no security at all."""
    certificate = CertProperties(EXAMPLES / "certificate-example.der", "DER")
    key = CertProperties(EXAMPLES / "private-key-example.pem", "PEM")
    assert HaSecurityConfig().policy is None
    secured = HaSecurityConfig(security_policies.SecurityPolicyBasic256Sha256, certificate, key, certificate)
    assert secured.server_certificate == certificate


def _other_transport_profile(response: ua.CreateSessionResponse) -> None:
    other = ua.EndpointDescription()
    other.EndpointUrl = "https://127.0.0.1:1/"
    other.TransportProfileUri = "http://opcfoundation.org/UA-Profile/Transport/https-uabinary"
    other.SecurityMode = ua.MessageSecurityMode.None_
    other.SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None"
    response.Parameters.ServerEndpoints.append(other)


async def test_cli34_other_transport_profiles_do_not_fail_the_check(
    two_endpoint_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.2: only the endpoints of the transport profile of the channel are compared."""
    tampered_responses.on(ua.CreateSessionResponse, _other_transport_profile)
    client = await _discovering_client(two_endpoint_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


def _change_security_level(response: ua.CreateSessionResponse) -> None:
    for endpoint in response.Parameters.ServerEndpoints:
        endpoint.SecurityLevel = 200


def _change_application_uri(response: ua.CreateSessionResponse) -> None:
    for endpoint in response.Parameters.ServerEndpoints:
        endpoint.Server.ApplicationUri = "urn:example:other"


@pytest.mark.parametrize("change", [_change_security_level, _change_application_uri])
async def test_cli34_security_level_and_application_uri_are_compared(
    change: object, two_endpoint_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.2: ApplicationUri and SecurityLevel are among the compared fields."""
    tampered_responses.on(ua.CreateSessionResponse, change)  # type: ignore[arg-type]
    client = await _discovering_client(two_endpoint_server)
    with pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
        await client.connect()
    await client.disconnect()


def _endpoint(url: str, level: int, profile: str = "") -> ua.EndpointDescription:
    return ua.EndpointDescription(
        EndpointUrl=url,
        SecurityMode=ua.MessageSecurityMode.Sign,
        SecurityPolicyUri=security_policies.SecurityPolicyBasic256Sha256.URI,
        SecurityLevel=level,
        TransportProfileUri=profile,
    )


def test_cli34_find_endpoint_filters_the_transport_profile_and_prefers_url_then_security_level() -> None:
    """Part 4, 5.5.4.1, 7.14: only UA-TCP binary endpoints; the URL used first, then the highest SecurityLevel."""
    binary = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
    https = "http://opcfoundation.org/UA-Profile/Transport/https-uabinary"
    endpoints = [
        _endpoint("opc.tcp://a:4840", 10, binary),
        _endpoint("opc.tcp://b:4840", 90, https),
        _endpoint("opc.tcp://c:4840", 50, ""),
        _endpoint("opc.tcp://d:4840", 70, binary),
    ]
    mode = ua.MessageSecurityMode.Sign
    uri = security_policies.SecurityPolicyBasic256Sha256.URI
    assert Client.find_endpoint(endpoints, mode, uri).EndpointUrl == "opc.tcp://d:4840"
    assert Client.find_endpoint(endpoints, mode, uri, "opc.tcp://a:4840").EndpointUrl == "opc.tcp://a:4840"
    with pytest.raises(ua.UaError, match="Sign"):
        Client.find_endpoint(endpoints[1:2], mode, uri)


async def test_cli35_unoffered_token_type_is_a_configuration_error(two_endpoint_server: Server) -> None:
    """Part 4, 5.7.3.2: the client sends only a token type the endpoint offers."""
    client = Client(two_endpoint_server.endpoint.geturl())
    with pytest.raises(ua.uaerrors.ConfigurationError):
        await client.connect()
    await client.disconnect()
    assert two_endpoint_server.iserver.session_manager.sessions == {}


async def test_cli35_session_names_are_unique_and_the_server_uri_is_null(server: Server) -> None:
    """Part 4, 5.7.2.2: SessionName is unique per client instance; ServerUri is no longer used."""
    client = Client(server.endpoint.geturl())
    client.server_uri = "urn:example:server"
    parameters: list[ua.CreateSessionParameters] = []
    real_create = client.uaclient.create_session

    async def recording(params: ua.CreateSessionParameters) -> ua.CreateSessionResult:
        parameters.append(params)
        return await real_create(params)

    client.uaclient.create_session = recording  # type: ignore[method-assign]
    await client.connect()
    await client.disconnect()
    await client.connect()
    await client.disconnect()
    assert len({p.SessionName for p in parameters}) == 2
    assert all(p.ServerUri is None for p in parameters)


async def test_cli35_client_certificate_is_null_under_policy_none(server: Server) -> None:
    """Part 4, 5.7.2.2: the user certificate is never sent as ClientCertificate."""
    client = Client(server.endpoint.geturl())
    client.user_certificate = x509_from_der(PKI.peer1.certificate.read_bytes())
    parameters: list[ua.CreateSessionParameters] = []
    real_create = client.uaclient.create_session

    async def recording(params: ua.CreateSessionParameters) -> ua.CreateSessionResult:
        parameters.append(params)
        return await real_create(params)

    client.uaclient.create_session = recording  # type: ignore[method-assign]
    await client.connect()
    await client.disconnect()
    assert not parameters[0].ClientCertificate


async def test_cli35_unknown_policy_name_is_a_configuration_error() -> None:
    """The security string names are checked, not looked up with getattr."""
    client = Client("opc.tcp://127.0.0.1:1")
    with pytest.raises(ua.uaerrors.ConfigurationError, match="Basic256Sha256"):
        await client.set_security_string("__class__,Sign,cert.pem,key.pem")
    with pytest.raises(ua.uaerrors.ConfigurationError, match="SignAndEncrypt"):
        await client.set_security_string("Basic256Sha256,Bogus,cert.pem,key.pem")


async def test_cli35_user_certificate_without_a_key_is_ignored() -> None:
    """Part 4, 5.7.3.2: a certificate without its key cannot sign the token; the user name is used."""
    client = Client("opc.tcp://127.0.0.1:1")
    client.user_certificate = x509_from_der(PKI.peer1.certificate.read_bytes())
    client._policy_ids = [ua.UserTokenPolicy(PolicyId="name", TokenType=ua.UserTokenType.UserName)]
    sent: list[ua.ActivateSessionParameters] = []

    async def activate(params: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        sent.append(params)
        return ua.ActivateSessionResult()

    client.uaclient.activate_session = activate  # type: ignore[method-assign]
    await client.activate_session(username="u", password="p", certificate=client.user_certificate)
    assert isinstance(sent[0].UserIdentityToken, ua.UserNameIdentityToken)


async def test_cli26_server_certificate_uri_must_match_the_endpoint(
    signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.2: the ApplicationUri of the endpoint is a URI of the server certificate."""
    tampered_responses.on(ua.CreateSessionResponse, _change_application_uri)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadCertificateUriInvalid):
        await client.connect()
    await client.disconnect()
    assert signing_server.iserver.session_manager.sessions == {}


async def test_cli26_matching_certificate_uri_is_accepted(signing_server: Server) -> None:
    """Part 4, 5.7.2.2: a server certificate that carries the ApplicationUri of its endpoint passes."""
    client = await signing_client(signing_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running

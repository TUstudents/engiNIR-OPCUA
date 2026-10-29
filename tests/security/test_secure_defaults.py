import logging

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic128Rsa15, SecurityPolicyBasic256Sha256
from enginir_opcua.ua.uaerrors import ConfigurationError
from tests.conftest import find_free_port
from tests.pki import generated_pki

PKI = generated_pki()


async def make_server(*, with_certificate: bool = True, **options: bool) -> Server:
    server = Server(**options)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    if with_certificate:
        await server.load_certificate(PKI.server.certificate)
        await server.load_private_key(PKI.server.key)
        server.set_trust_store(PKI.trust_store())
    return server


async def offered_policies(server: Server) -> set[str]:
    return {endpoint.SecurityPolicyUri for endpoint in await server.get_endpoints()}


async def test_srv45_no_security_endpoint_is_not_offered_by_default() -> None:
    """Part 4, 7.10 and the design's secure defaults: SecurityPolicy None has to be enabled explicitly."""
    server = await make_server()
    async with server:
        policies = await offered_policies(server)
    assert "http://opcfoundation.org/UA/SecurityPolicy#None" not in policies
    assert SecurityPolicyBasic256Sha256.URI in policies


async def test_srv45_server_without_certificate_and_without_no_security_does_not_start() -> None:
    """A server that would offer no endpoint at all fails at start and names what to do."""
    server = await make_server(with_certificate=False)
    with pytest.raises(ConfigurationError, match="allow_no_security"):
        await server.start()


async def test_srv45_allow_no_security_offers_the_endpoint() -> None:
    """The None endpoint is offered when it is enabled explicitly."""
    server = await make_server(allow_no_security=True)
    async with server:
        assert "http://opcfoundation.org/UA/SecurityPolicy#None" in await offered_policies(server)
        async with Client(server.endpoint.geturl()) as client:
            assert await client.nodes.objects.get_children()


async def test_srv45_listing_no_security_in_the_policies_offers_it() -> None:
    """Part 4, 7.10: naming the policy in set_security_policy is an explicit choice."""
    server = await make_server(with_certificate=False)
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    async with server:
        assert await offered_policies(server) == {"http://opcfoundation.org/UA/SecurityPolicy#None"}


async def test_cry8_deprecated_policy_needs_allow_deprecated_policies() -> None:
    """Part 7: Basic128Rsa15 and Basic256 are deprecated and have to be enabled explicitly."""
    server = await make_server()
    with pytest.raises(ConfigurationError, match="allow_deprecated_policies"):
        server.set_security_policy([ua.SecurityPolicyType.Basic128Rsa15_Sign])


async def test_cry8_allowed_deprecated_policy_is_offered_with_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Part 7: the deprecated policies are available when enabled, and the start says so."""
    server = await make_server(allow_deprecated_policies=True)
    server.set_security_policy([ua.SecurityPolicyType.Basic128Rsa15_Sign, ua.SecurityPolicyType.Basic256Sha256_Sign])
    with caplog.at_level(logging.WARNING):
        async with server:
            policies = await offered_policies(server)
    assert SecurityPolicyBasic128Rsa15.URI in policies
    assert "Basic128Rsa15" in caplog.text


async def test_cry8_client_refuses_a_deprecated_policy_unless_allowed() -> None:
    """Part 7: the client selects a deprecated policy only when it is enabled explicitly."""
    client = Client("opc.tcp://127.0.0.1:4840")
    with pytest.raises(ConfigurationError, match="allow_deprecated_policies"):
        await client.set_security(
            SecurityPolicyBasic128Rsa15,
            PKI.peer1.certificate,
            PKI.peer1.key,
            None,
            PKI.server.certificate,
            ua.MessageSecurityMode.Sign,
        )
    allowed = Client("opc.tcp://127.0.0.1:4840", allow_deprecated_policies=True)
    await allowed.set_security(
        SecurityPolicyBasic128Rsa15,
        PKI.peer1.certificate,
        PKI.peer1.key,
        None,
        PKI.server.certificate,
        ua.MessageSecurityMode.Sign,
    )

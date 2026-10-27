from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.server.user_managers import PermissiveUserManager

from .conftest import find_free_port
from .harness import EXAMPLES, SessionProbe

USER_CERTIFICATE = (EXAMPLES / "certificates" / "peer-certificate-example-1.der").read_bytes()


@pytest.fixture
async def unsecured_server() -> AsyncIterator[Server]:
    srv = Server(user_manager=PermissiveUserManager())
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    yield srv
    await srv.stop()


async def _activate(server: Server, token: object) -> ua.ActivateSessionResult:
    probe = await SessionProbe.open(server.endpoint.geturl())
    try:
        session = await probe.create_session()
        probe.use(session.AuthenticationToken)
        params = ua.ActivateSessionParameters()
        params.UserIdentityToken = token
        params.ClientSignature = ua.SignatureData()
        return await probe.client.uaclient.activate_session(params)
    finally:
        probe.client.disconnect_socket()


async def test_srv6_anonymous_policy_id_is_matched(unsecured_server: Server) -> None:
    """Part 4, 7.41 and 7.40.3: the PolicyId names one of the endpoint's UserTokenPolicies."""
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await _activate(unsecured_server, ua.AnonymousIdentityToken(PolicyId="no-such-policy"))


async def test_srv6_matching_anonymous_policy_id_is_accepted(unsecured_server: Server) -> None:
    """Part 4, 7.41 and 7.40.3: the PolicyId of an offered Anonymous policy is accepted."""
    await _activate(unsecured_server, ua.AnonymousIdentityToken(PolicyId="anonymous"))


async def test_srv6_empty_token_is_anonymous_without_policy_id(unsecured_server: Server) -> None:
    """Part 4, 5.7.3.2: an empty UserIdentityToken is Anonymous and carries no PolicyId."""
    await _activate(unsecured_server, ua.ExtensionObject())


async def test_srv6_token_class_not_offered_by_the_endpoint_is_identity_token_rejected(
    unsecured_server: Server,
) -> None:
    """Part 4, 5.7.3.2 and 7.40.1: the None endpoint offers no Certificate policy without a signing policy."""
    token = ua.X509IdentityToken(PolicyId="certificate", CertificateData=USER_CERTIFICATE)
    with pytest.raises(ua.uaerrors.BadIdentityTokenRejected):
        await _activate(unsecured_server, token)


async def test_srv6_user_name_token_without_user_name_policy_is_identity_token_rejected() -> None:
    """Part 4, 5.7.3.2 and 7.40.1: a UserName token needs a UserName policy on the endpoint."""
    srv = Server(user_manager=PermissiveUserManager())
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        token = ua.UserNameIdentityToken(PolicyId="username", UserName="alice", Password=b"secret")
        with pytest.raises(ua.uaerrors.BadIdentityTokenRejected):
            await _activate(srv, token)
    finally:
        await srv.stop()


async def test_srv49_no_username_policy_on_unsecured_endpoint_without_encryption(unsecured_server: Server) -> None:
    """Part 4, 7.40.4: a password must not be advertised in clear on an endpoint that cannot protect it."""
    endpoints = await unsecured_server.get_endpoints()
    assert endpoints
    for endpoint in endpoints:
        assert all(policy.TokenType != ua.UserTokenType.UserName for policy in endpoint.UserIdentityTokens)


async def test_srv49_plaintext_password_policy_can_be_enabled_explicitly() -> None:
    """Part 4, 7.40.4: the administrator may opt in to a password in clear."""
    srv = Server(user_manager=PermissiveUserManager())
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        endpoints = await srv.get_endpoints()
        assert any(policy.TokenType == ua.UserTokenType.UserName for policy in endpoints[0].UserIdentityTokens)
    finally:
        await srv.stop()

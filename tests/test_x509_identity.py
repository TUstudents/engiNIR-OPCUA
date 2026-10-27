import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.crypto import security_policies
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.uacrypto import CertProperties, certificate_thumbprint
from enginir_opcua.crypto.validator import CertificateValidator
from enginir_opcua.server.user_managers import CertificateUserManager, PermissiveUserManager, UserManager

from .conftest import find_free_port
from .harness import PKI
from .pki import Identity, live_ca, live_identity

RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"


@dataclass
class UserPki:
    directory: Path
    ca: Identity
    user: Identity
    user_certificate: Path
    user_key: Path
    ca_certificate: Path
    trusted: Path

    def trust_store(self) -> TrustStore:
        return TrustStore([self.trusted], [])


@pytest.fixture
def user_pki() -> UserPki:
    directory = Path(tempfile.mkdtemp(prefix="enginir-user-pki-"))
    ca = live_ca("User CA")
    user = live_identity("operator", issuer=ca, uri=None, dns_names=(), subject_alt_name=False, ext_key_usage=None)
    ca_certificate, _ = ca.write(directory, "ca")
    user_certificate, user_key = user.write(directory, "operator")
    trusted = directory / "trusted"
    trusted.mkdir()
    (trusted / "ca.der").write_bytes(ca.der)
    return UserPki(directory, ca, user, user_certificate, user_key, ca_certificate, trusted)


async def _start(
    manager: UserManager,
    user_trust: TrustStore | None = None,
    tokens: list[type] | None = None,
) -> Server:
    srv = Server(user_manager=manager)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_Sign])
    if tokens is not None:
        srv.set_identity_tokens(tokens)
    await srv.load_certificate(PKI.server.certificate)
    await srv.load_private_key(PKI.server.key)
    srv.set_trust_store(PKI.trust_store())
    if user_trust is not None:
        srv.set_user_trust_store(user_trust)
    await srv.start()
    return srv


async def _client(server: Server, pki: UserPki, chain: bool = False) -> Client:
    client = Client(server.endpoint.geturl())
    await client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        PKI.peer1.certificate,
        PKI.peer1.key,
        None,
        PKI.server.certificate,
        ua.MessageSecurityMode.Sign,
    )
    await client.load_client_certificate(str(pki.user_certificate))
    await client.load_private_key(pki.user_key)
    if chain:
        await client.load_client_chain([CertProperties(pki.ca_certificate, "DER")])
    return client


@pytest.fixture
async def open_user_server(user_pki: UserPki) -> AsyncIterator[Server]:
    srv = await _start(PermissiveUserManager(), user_pki.trust_store())
    yield srv
    await srv.stop()


async def test_srv6_x509_token_without_a_user_trust_store_is_refused(user_pki: UserPki) -> None:
    """Part 4, 6.1.3 and 7.40.5: with no user trust list configured an X509 user certificate is not trusted."""
    srv = await _start(PermissiveUserManager())
    try:
        client = await _client(srv, user_pki)
        with pytest.raises(ua.uaerrors.BadIdentityTokenRejected):
            await client.connect()
        await client.disconnect()
    finally:
        await srv.stop()


async def test_srv6_x509_token_certificate_goes_through_the_validator(
    user_pki: UserPki, open_user_server: Server
) -> None:
    """Part 4, 6.1.3 and 7.40.5: a user certificate issued by a trusted CA is accepted."""
    client = await _client(open_user_server, user_pki, chain=True)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


async def test_srv6_untrusted_x509_user_certificate_is_identity_token_rejected(
    user_pki: UserPki, open_user_server: Server
) -> None:
    """Part 4, 6.1.3 and 7.40.5: a user certificate that the user trust list doesn't cover is rejected."""
    other = live_identity("stranger", uri=None, dns_names=(), subject_alt_name=False, ext_key_usage=None)
    certificate, key = other.write(user_pki.directory, "stranger")
    stranger = UserPki(
        user_pki.directory, user_pki.ca, other, certificate, key, user_pki.ca_certificate, user_pki.trusted
    )
    client = await _client(open_user_server, stranger)
    with pytest.raises(ua.uaerrors.BadIdentityTokenRejected):
        await client.connect()
    await client.disconnect()


async def test_srv6_wrong_user_signature_is_user_signature_invalid(
    user_pki: UserPki, open_user_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.7.3: a user token signature that does not verify is Bad_UserSignatureInvalid."""
    activate_session = UaClient.activate_session

    async def corrupted(self: UaClient, params: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        params.UserTokenSignature.Signature = bytes(256)
        return await activate_session(self, params)

    monkeypatch.setattr(UaClient, "activate_session", corrupted)
    client = await _client(open_user_server, user_pki)
    with pytest.raises(ua.uaerrors.BadUserSignatureInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_x509_signature_algorithm_must_match_the_token_policy(
    user_pki: UserPki, open_user_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.5: the UserTokenSignature algorithm is the one of the token policy's SecurityPolicy."""
    activate_session = UaClient.activate_session

    async def sha1(self: UaClient, params: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        params.UserTokenSignature.Algorithm = RSA_SHA1
        return await activate_session(self, params)

    monkeypatch.setattr(UaClient, "activate_session", sha1)
    client = await _client(open_user_server, user_pki)
    with pytest.raises(ua.uaerrors.BadSecurityPolicyRejected):
        await client.connect()
    await client.disconnect()


async def test_srv6_unparsable_user_certificate_is_identity_token_invalid(
    user_pki: UserPki, open_user_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.5: CertificateData that is not a certificate is Bad_IdentityTokenInvalid."""
    activate_session = UaClient.activate_session

    async def garbage(self: UaClient, params: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        params.UserIdentityToken.CertificateData = b"not a certificate"
        return await activate_session(self, params)

    monkeypatch.setattr(UaClient, "activate_session", garbage)
    client = await _client(open_user_server, user_pki)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv46_chain_in_certificate_data_still_matches_the_manager(user_pki: UserPki) -> None:
    """Part 6, 6.2.6 and Part 4, 7.40.5: the manager gets the leaf, so a chain behind it doesn't hide the user."""
    manager = CertificateUserManager()
    await manager.add_user(user_pki.user_certificate, name="operator")
    srv = await _start(manager, user_pki.trust_store())
    try:
        client = await _client(srv, user_pki, chain=True)
        async with client:
            sessions = list(srv.iserver.session_manager.sessions.values())
            assert [session.user.name for session in sessions] == ["operator"]
    finally:
        await srv.stop()


async def test_srv46_unregistered_user_certificate_is_user_access_denied(user_pki: UserPki) -> None:
    """Part 4, 5.7.3.3: a trusted certificate the manager doesn't know is Bad_UserAccessDenied."""
    srv = await _start(CertificateUserManager(), user_pki.trust_store())
    try:
        client = await _client(srv, user_pki, chain=True)
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await client.connect()
        await client.disconnect()
    finally:
        await srv.stop()


async def test_srv6_user_id_is_the_certificate_thumbprint(user_pki: UserPki, open_user_server: Server) -> None:
    """Part 4, 5.7.3.1: the identity a Session is moved with is the thumbprint of the user certificate."""
    client = await _client(open_user_server, user_pki)
    async with client:
        (session,) = open_user_server.iserver.session_manager.sessions.values()
        assert session.user.id == certificate_thumbprint(user_pki.user.der).hex()


def _jump(server: Server, delta: timedelta) -> None:
    server.iserver.wall_clock = lambda: datetime.now(UTC) + delta


async def test_srv47_expired_user_certificate_drops_to_anonymous(user_pki: UserPki) -> None:
    """Part 4, 7.40.5: after the user certificate expired the Session continues as Anonymous."""
    srv = await _start(
        PermissiveUserManager(), user_pki.trust_store(), [ua.AnonymousIdentityToken, ua.X509IdentityToken]
    )
    try:
        client = await _client(srv, user_pki)
        async with client:
            (session,) = srv.iserver.session_manager.sessions.values()
            assert session.user.role is UserRole.User
            _jump(srv, timedelta(days=400))
            await srv.iserver.session_manager.sweep()
            assert session.user.role is UserRole.Anonymous
            assert session.services.user.role is UserRole.Anonymous
            assert session.token in srv.iserver.session_manager.sessions
    finally:
        await srv.stop()


async def test_srv47_expired_user_certificate_closes_session_without_anonymous(user_pki: UserPki) -> None:
    """Part 4, 7.40.5: without an Anonymous policy the Session of an expired user certificate is closed."""
    srv = await _start(PermissiveUserManager(), user_pki.trust_store(), [ua.X509IdentityToken])
    try:
        client = await _client(srv, user_pki)
        async with client:
            (session,) = srv.iserver.session_manager.sessions.values()
            _jump(srv, timedelta(days=400))
            await srv.iserver.session_manager.sweep()
            assert session.token not in srv.iserver.session_manager.sessions
    finally:
        await srv.stop()


async def test_srv47_user_certificate_within_the_grace_period_keeps_its_role(user_pki: UserPki) -> None:
    """Part 4, 7.40.5: the grace period after notAfter is configurable and keeps the user for a while."""
    srv = await _start(
        PermissiveUserManager(), user_pki.trust_store(), [ua.AnonymousIdentityToken, ua.X509IdentityToken]
    )
    try:
        client = await _client(srv, user_pki)
        async with client:
            (session,) = srv.iserver.session_manager.sessions.values()
            expires_at = session.user.expires_at
            assert expires_at is not None
            srv.iserver.wall_clock = lambda: (
                expires_at + timedelta(seconds=srv.iserver.user_certificate_grace_seconds - 1)
            )
            await srv.iserver.session_manager.sweep()
            assert session.user.role is UserRole.User
    finally:
        await srv.stop()


async def test_srv6_user_certificate_needs_no_application_uri(user_pki: UserPki) -> None:
    """Part 6, 6.2.3: a user certificate has no ApplicationUri and no host name, the validator doesn't ask for them."""
    store = user_pki.trust_store()
    await store.load()
    outcome = CertificateValidator(store).validate_user_certificate(
        user_pki.user.der + user_pki.ca.der, security_policies.SecurityPolicyBasic256Sha256.URI
    )
    assert outcome.accepted, outcome.detail


async def test_srv6_ca_certificate_is_not_a_user_certificate(user_pki: UserPki) -> None:
    """Part 6, 6.2.3: a user certificate is not a CA."""
    store = user_pki.trust_store()
    await store.load()
    outcome = CertificateValidator(store).validate_user_certificate(user_pki.ca.der, None)
    assert outcome.status == ua.StatusCodes.BadCertificateInvalid


async def test_srv6_untrusted_user_certificate_is_untrusted(user_pki: UserPki) -> None:
    """Part 4, 6.1.3: a user certificate outside the user trust list gets Bad_CertificateUntrusted."""
    stranger = live_identity("stranger", uri=None, dns_names=(), subject_alt_name=False, ext_key_usage=None)
    outcome = CertificateValidator(TrustStore()).validate_user_certificate(stranger.der, None)
    assert outcome.status == ua.StatusCodes.BadCertificateUntrusted

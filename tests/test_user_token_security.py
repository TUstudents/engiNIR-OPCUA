from collections.abc import Callable

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.crypto import uacrypto

from .harness import TWO_SESSION_USERS, signing_client

PASSWORD = TWO_SESSION_USERS["alice"]
RSA_15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"


def _rewrite_user_token(
    monkeypatch: pytest.MonkeyPatch, rewrite: Callable[[ua.UserNameIdentityToken, bytes], None]
) -> None:
    activate_session = UaClient.activate_session

    async def rewritten(self: UaClient, params: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        rewrite(params.UserIdentityToken, self.security_policy.peer_certificate)
        return await activate_session(self, params)

    monkeypatch.setattr(UaClient, "activate_session", rewritten)


def _secret(password: str, nonce: bytes) -> bytes:
    return ua.ua_binary.Primitives.Bytes.pack(password.encode("utf8") + nonce)


async def test_signing_server_accepts_correct_token(signing_server: Server) -> None:
    client = await signing_client(signing_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


async def test_srv6_password_bound_to_another_nonce_is_rejected(
    signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.2: the encrypted secret ends with the current server nonce; any other nonce is a replay."""

    def replay(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        public_key = uacrypto.x509_from_der(server_certificate).public_key()
        token.Password = uacrypto.encrypt_rsa_oaep(public_key, _secret(PASSWORD, b"\x00" * 32))

    _rewrite_user_token(monkeypatch, replay)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_cry8_rsa15_password_is_rejected_on_basic256sha256(
    signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2: the secret is encrypted with the algorithm of the UserTokenPolicy's SecurityPolicy."""

    def encrypt_with_rsa15(client: Client, password: str, policy_uri: str) -> tuple[bytes, str]:
        public_key = uacrypto.x509_from_der(client.security_policy.peer_certificate).public_key()
        return uacrypto.encrypt_rsa15(public_key, _secret(password, client._server_nonce or b"")), RSA_15

    monkeypatch.setattr(Client, "_encrypt_password", encrypt_with_rsa15)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_plaintext_password_is_rejected_when_policy_requires_encryption(
    signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.4: a UserTokenPolicy with a SecurityPolicy other than None requires an encrypted password."""

    def plaintext(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        token.Password = PASSWORD.encode("utf8")
        token.EncryptionAlgorithm = None

    _rewrite_user_token(monkeypatch, plaintext)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_unknown_policy_id_is_rejected(signing_server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 7.40.1: the PolicyId has to name one of the endpoint's UserTokenPolicies."""

    def unknown_policy(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        token.PolicyId = "no-such-policy"

    _rewrite_user_token(monkeypatch, unknown_policy)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_token_without_password_goes_to_the_user_manager(signing_server: Server) -> None:
    """A token without a password carries no secret to encrypt; the user manager decides about it."""
    client = await signing_client(signing_server)
    client.set_password("")
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await client.connect()
    await client.disconnect()

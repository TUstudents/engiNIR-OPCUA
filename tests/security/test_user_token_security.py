import hmac
import struct
from collections.abc import Callable
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.crypto import uacrypto
from enginir_opcua.server import identity
from tests.harness import TWO_SESSION_USERS, signing_client

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


def _public_key(der: bytes) -> rsa.RSAPublicKey:
    certificate = uacrypto.x509_from_der(der)
    assert certificate is not None
    public_key = certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    return public_key


def _secret(password: str, nonce: bytes) -> bytes:
    return ua.ua_binary.Primitives.Bytes.pack(password.encode("utf8") + nonce)


async def test_signing_server_accepts_correct_token(shared_signing_server: Server) -> None:
    client = await signing_client(shared_signing_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


async def test_srv6_password_bound_to_another_nonce_is_rejected(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.2: the encrypted secret ends with the current server nonce; any other nonce is a replay."""

    def replay(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        public_key = _public_key(server_certificate)
        token.Password = uacrypto.encrypt_rsa_oaep(public_key, _secret(PASSWORD, b"\x00" * 32))

    _rewrite_user_token(monkeypatch, replay)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_cry8_rsa15_password_is_rejected_on_basic256sha256(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2: the secret is encrypted with the algorithm of the UserTokenPolicy's SecurityPolicy."""

    def encrypt_with_rsa15(client: Client, password: str, policy_uri: str) -> tuple[bytes, str]:
        public_key = _public_key(client.security_policy.peer_certificate)
        return uacrypto.encrypt_rsa15(public_key, _secret(password, client._server_nonce or b"")), RSA_15

    monkeypatch.setattr(Client, "_encrypt_password", encrypt_with_rsa15)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_plaintext_password_is_rejected_when_policy_requires_encryption(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.4: a UserTokenPolicy with a SecurityPolicy other than None requires an encrypted password."""

    def plaintext(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        token.Password = PASSWORD.encode("utf8")
        token.EncryptionAlgorithm = None

    _rewrite_user_token(monkeypatch, plaintext)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_unknown_policy_id_is_rejected(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.1: the PolicyId has to name one of the endpoint's UserTokenPolicies."""

    def unknown_policy(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        token.PolicyId = "no-such-policy"

    _rewrite_user_token(monkeypatch, unknown_policy)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_token_without_password_goes_to_the_user_manager(shared_signing_server: Server) -> None:
    """A token without a password carries no secret to encrypt; the user manager decides about it."""
    client = await signing_client(shared_signing_server)
    client.set_password("")
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await client.connect()
    await client.disconnect()


RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"


def _craft_secret(monkeypatch: pytest.MonkeyPatch, build: Callable[[bytes, bytes], bytes]) -> None:
    def crafted(client: Client, password: str, policy_uri: str) -> tuple[bytes, str]:
        public_key = _public_key(client.security_policy.peer_certificate)
        plaintext = build(password.encode("utf8"), client._server_nonce or b"")
        return uacrypto.encrypt_rsa_oaep(public_key, plaintext), RSA_OAEP

    monkeypatch.setattr(Client, "_encrypt_password", crafted)


def _with_length(body: bytes, length: int, padding: bytes = b"") -> bytes:
    return struct.pack("<I", length) + body + padding


SECRET_FAILURES: dict[str, Callable[[bytes, bytes], bytes]] = {
    "nonzero_padding": lambda pw, nonce: _with_length(pw + nonce, len(pw + nonce), b"\x07\x07junk"),
    "length_beyond_plaintext": lambda pw, nonce: _with_length(pw + nonce, 9999),
    "length_shorter_than_nonce": lambda pw, nonce: _with_length(pw + nonce, len(nonce) - 1),
    "plaintext_shorter_than_length_field": lambda pw, nonce: b"\x01\x00",
    "wrong_nonce": lambda pw, nonce: _with_length(pw + bytes(len(nonce)), len(pw + nonce)),
    "invalid_utf8": lambda pw, nonce: _with_length(b"\xff\xfe" + nonce, 2 + len(nonce)),
}


@pytest.mark.parametrize("failure", sorted(SECRET_FAILURES))
async def test_srv48_all_secret_failures_give_identity_token_invalid(
    failure: str, shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.1 and 7.40.2.2: every defect of the secret is Bad_IdentityTokenInvalid."""
    _craft_secret(monkeypatch, SECRET_FAILURES[failure])
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


@pytest.mark.parametrize("failure", sorted(SECRET_FAILURES))
async def test_srv48_every_check_runs_whichever_one_fails(
    failure: str, shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.1: validation takes the same work whichever check fails; the nonce is always compared."""
    comparisons: list[int] = []
    compare_digest = hmac.compare_digest

    def counting(left: bytes, right: bytes) -> bool:
        comparisons.append(1)
        return compare_digest(left, right)

    monkeypatch.setattr(identity, "hmac", SimpleNamespace(compare_digest=counting))
    _craft_secret(monkeypatch, SECRET_FAILURES[failure])
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()
    assert comparisons == [1]


async def test_srv48_secret_with_zero_padding_is_accepted(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.2: bytes after the data are zero padding and are fine."""
    _craft_secret(monkeypatch, lambda pw, nonce: _with_length(pw + nonce, len(pw + nonce), bytes(16)))
    client = await signing_client(shared_signing_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


async def test_srv6_wrong_password_is_user_access_denied(shared_signing_server: Server) -> None:
    """Part 4, 5.7.3.3: a valid token with a wrong password is Bad_UserAccessDenied."""
    client = await signing_client(shared_signing_server)
    client.set_password("wrong")
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await client.connect()
    await client.disconnect()

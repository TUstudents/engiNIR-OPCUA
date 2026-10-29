from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.common.utils import ServiceError
from enginir_opcua.crypto import security_policies, uacrypto
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.crypto.security_policies import SecurityPolicy
from enginir_opcua.server.user_managers import UserManager
from tests.conftest import find_free_port
from tests.harness import PKI, ResponseTampering, signing_client
from tests.pki import generated_pki

POLICIES = [
    security_policies.SecurityPolicyBasic128Rsa15,
    security_policies.SecurityPolicyBasic256,
    security_policies.SecurityPolicyBasic256Sha256,
    security_policies.SecurityPolicyAes128Sha256RsaOaep,
    security_policies.SecurityPolicyAes256Sha256RsaPss,
]
DATA = b"data to protect"
SECRET = b"s" * 32
SEED = b"d" * 32


@pytest.fixture(scope="module")
async def credentials() -> tuple[object, object]:
    certificate = await uacrypto.load_certificate(PKI.server.certificate)
    private_key = await uacrypto.load_private_key(PKI.server.key)
    return certificate, private_key


def _policy(
    cls: type[SecurityPolicy], credentials: tuple[object, object], mode: ua.MessageSecurityMode
) -> SecurityPolicy:
    certificate, private_key = credentials
    return cls(certificate, certificate, private_key, mode)


@pytest.mark.parametrize("cls", POLICIES)
async def test_cry7_asymmetric_verifier_raises_signature_error(
    cls: type[SecurityPolicy], credentials: tuple[object, object]
) -> None:
    """Part 6, 6.7.7: a failed signature check is one error type for every policy."""
    policy = _policy(cls, credentials, ua.MessageSecurityMode.Sign)
    signature = policy.asymmetric_cryptography.signature(DATA)
    policy.asymmetric_cryptography.verify(DATA, signature)
    with pytest.raises(ua.uaerrors.SignatureError):
        policy.asymmetric_cryptography.verify(DATA, bytes(len(signature)))


@pytest.mark.parametrize("cls", POLICIES)
async def test_cry7_symmetric_verifier_raises_signature_error(
    cls: type[SecurityPolicy], credentials: tuple[object, object]
) -> None:
    """Part 6, 6.7.7: a failed signature check is one error type for every policy."""
    policy = _policy(cls, credentials, ua.MessageSecurityMode.Sign)
    policy.make_local_symmetric_key(SECRET, SEED)
    policy.make_remote_symmetric_key(SECRET, SEED, 60000)
    signature = policy.symmetric_cryptography.signature(DATA)
    policy.symmetric_cryptography.verify(DATA, signature)
    with pytest.raises(ua.uaerrors.SignatureError):
        policy.symmetric_cryptography.verify(DATA, bytes(len(signature)))


@pytest.mark.parametrize("verify", [uacrypto.verify_sha1, uacrypto.verify_sha256, uacrypto.verify_pss_sha256])
async def test_cry7_uacrypto_verifiers_raise_signature_error(verify, credentials: tuple[object, object]) -> None:
    certificate, _ = credentials
    with pytest.raises(ua.uaerrors.SignatureError):
        verify(certificate, DATA, bytes(256))


def test_cry7_signature_and_decryption_errors_are_ua_errors() -> None:
    assert issubclass(ua.uaerrors.SignatureError, ua.UaError)
    assert issubclass(ua.uaerrors.DecryptionError, ua.UaError)


@pytest.mark.parametrize(
    "decrypt", [uacrypto.decrypt_rsa15, uacrypto.decrypt_rsa_oaep, uacrypto.decrypt_rsa_oaep_sha256]
)
async def test_cry13_rsa_decryption_failure_raises_decryption_error(
    decrypt, credentials: tuple[object, object]
) -> None:
    _, private_key = credentials
    with pytest.raises(ua.uaerrors.DecryptionError):
        decrypt(private_key, bytes(10))


@pytest.mark.parametrize("cls", POLICIES)
async def test_cry13_asymmetric_decryption_failure_raises_decryption_error(
    cls: type[SecurityPolicy], credentials: tuple[object, object]
) -> None:
    policy = _policy(cls, credentials, ua.MessageSecurityMode.Sign)
    with pytest.raises(ua.uaerrors.DecryptionError):
        policy.asymmetric_cryptography.decrypt(bytes(300))


@pytest.mark.parametrize("cls", POLICIES)
async def test_cry13_symmetric_decryption_failure_raises_decryption_error(
    cls: type[SecurityPolicy], credentials: tuple[object, object]
) -> None:
    policy = _policy(cls, credentials, ua.MessageSecurityMode.SignAndEncrypt)
    policy.make_remote_symmetric_key(SECRET, SEED, 60000)
    with pytest.raises(ua.uaerrors.DecryptionError):
        policy.symmetric_cryptography.decrypt(bytes(17))


def _corrupt_signature(monkeypatch: pytest.MonkeyPatch, user_token: bool) -> None:
    activate_session = UaClient.activate_session

    async def corrupted(self: UaClient, params: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        signature = params.UserTokenSignature if user_token else params.ClientSignature
        signature.Signature = bytes(len(signature.Signature))
        return await activate_session(self, params)

    monkeypatch.setattr(UaClient, "activate_session", corrupted)


async def test_cry7_bad_client_signature_is_application_signature_invalid(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.7.3: Bad_ApplicationSignatureInvalid for a missing or invalid clientSignature."""
    _corrupt_signature(monkeypatch, user_token=False)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadApplicationSignatureInvalid):
        await client.connect()
    await client.disconnect()


async def test_cry7_bad_x509_token_signature_is_user_signature_invalid(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.7.3: Bad_UserSignatureInvalid for a missing or invalid userTokenSignature."""
    await shared_signing_server.stop()
    shared_signing_server.set_identity_tokens([ua.UserNameIdentityToken, ua.X509IdentityToken])
    await shared_signing_server.start()
    _corrupt_signature(monkeypatch, user_token=True)
    client: Client = await signing_client(shared_signing_server)
    await client.load_client_certificate(str(PKI.peer1.certificate))
    await client.load_private_key(PKI.peer1.key)
    with pytest.raises(ua.uaerrors.BadUserSignatureInvalid):
        await client.connect()
    await client.disconnect()


@pytest.mark.parametrize("policy_uri", [None, "", security_policies.SecurityPolicyNone.URI, "urn:unknown"])
async def test_cry7_sign_asymmetric_without_a_signing_policy_raises(
    policy_uri: str | None, credentials: tuple[object, object]
) -> None:
    """Part 6, 6.7.4 and Part 4, 5.7.3: a signature is never the data itself."""
    _, private_key = credentials
    with pytest.raises(ua.UaError):
        security_policies.sign_asymmetric(private_key, DATA, policy_uri)


def _handshake(
    cls: type[SecurityPolicy], credentials: tuple[object, object], mode: ua.MessageSecurityMode
) -> tuple[SecurityPolicy, SecurityPolicy]:
    sender = _policy(cls, credentials, mode)
    receiver = _policy(cls, credentials, mode)
    sender.make_local_symmetric_key(SECRET, SEED)
    receiver.make_remote_symmetric_key(SECRET, SEED, 60000)
    return sender, receiver


@pytest.mark.parametrize("cls", POLICIES)
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 100, 4093])
async def test_cry9_symmetric_round_trip_pads_to_the_aes_block(
    cls: type[SecurityPolicy], size: int, credentials: tuple[object, object]
) -> None:
    """Part 6, 6.7.2.5.1: padding makes the signed plaintext a multiple of the 16 byte AES block."""
    sender, receiver = _handshake(cls, credentials, ua.MessageSecurityMode.SignAndEncrypt)
    body = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    crypto = sender.symmetric_cryptography
    plain = body + crypto.padding(len(body))
    signed = plain + crypto.signature(plain)
    assert len(signed) % 16 == 0
    assert crypto.plain_block_size() == crypto.encrypted_block_size() == 16
    decrypted = receiver.symmetric_cryptography.decrypt(crypto.encrypt(signed))
    signature_size = receiver.symmetric_cryptography.vsignature_size()
    receiver.symmetric_cryptography.verify(decrypted[:-signature_size], decrypted[-signature_size:])
    assert receiver.symmetric_cryptography.remove_padding(decrypted[:-signature_size]) == body


@pytest.mark.parametrize(
    "base",
    [
        security_policies.Signer,
        security_policies.Verifier,
        security_policies.Encryptor,
        security_policies.Decryptor,
        security_policies.SecurityPolicy,
    ],
)
def test_cry9_abstract_bases_are_enforced(base: Any) -> None:
    with pytest.raises(TypeError):
        base()


def test_ws_b_security_policy_type_lives_in_the_crypto_package_and_stays_exported_from_ua() -> None:
    assert ua.SecurityPolicyType is security_policies.SecurityPolicyType
    assert ua.SecurityPolicyType.__module__.startswith("enginir_opcua.crypto")


GENERATED_PKI = generated_pki()
SERVER_CERT = GENERATED_PKI.server.certificate
SERVER_KEY = GENERATED_PKI.server.key
PEER_1 = (GENERATED_PKI.peer1.certificate, PKI.peer1.key)
PEER_2 = (GENERATED_PKI.peer2.certificate, PKI.peer2.key)


class PasswordUserManager(UserManager):
    def get_user(
        self, iserver: Any, username: str | None = None, password: str | None = None, certificate: Any = None
    ) -> User | None:
        if username == "operator" and password == "secret":
            return User(role=UserRole.Admin, name="operator")
        if username is None:
            return User(role=UserRole.User)
        return None


async def _start_server(secure: bool) -> tuple[Server, str]:
    url = f"opc.tcp://127.0.0.1:{find_free_port()}"
    srv = Server(allow_no_security=True, user_manager=PasswordUserManager())
    await srv.init()
    srv.set_endpoint(url)
    if secure:
        srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
        await srv.load_certificate(SERVER_CERT)
        await srv.load_private_key(SERVER_KEY)
        srv.set_trust_store(GENERATED_PKI.trust_store())
    else:
        srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
        srv.allow_plaintext_password = True
    await srv.start()
    return srv, url


@pytest.fixture
async def open_server() -> AsyncIterator[tuple[Server, str]]:
    srv, url = await _start_server(secure=False)
    yield srv, url
    await srv.stop()


@pytest.fixture
async def secure_server() -> AsyncIterator[tuple[Server, str]]:
    srv, url = await _start_server(secure=True)
    yield srv, url
    await srv.stop()


async def _secure_client(url: str, peer: tuple[Path, Path]) -> Client:
    client = Client(url)
    client.set_trust_store(GENERATED_PKI.trust_store())
    await client.set_security_string(f"Basic256Sha256,SignAndEncrypt,{peer[0]},{peer[1]}")
    return client


async def _open_channel(client: Client) -> None:
    await client.connect_socket()
    await client.send_hello()
    await client.open_secure_channel()


async def _activate_with_token(client: Client, token: ua.NodeId) -> None:
    client.uaclient.session.restore_authentication_token(token)
    params = ua.ActivateSessionParameters()
    params.UserIdentityToken = ua.AnonymousIdentityToken(PolicyId="anonymous")
    params.ClientSignature = ua.SignatureData()
    await client.uaclient.activate_session(params)


async def _read_server_state(client: Client) -> bool:
    params = ua.ReadParameters()
    params.NodesToRead = [
        ua.ReadValueId(NodeId=ua.NodeId(ua.ObjectIds.Server_ServerStatus_State), AttributeId=ua.AttributeIds.Value)
    ]
    status = (await client.uaclient.read(params))[0].StatusCode
    return status is not None and status.is_good()


async def test_authentication_tokens_are_random_bytestrings(open_server: tuple[Server, str]) -> None:
    _srv, url = open_server
    async with Client(url) as first, Client(url) as second:
        tokens = [first.uaclient.session.authentication_token, second.uaclient.session.authentication_token]
    assert all(token.NodeIdType == ua.NodeIdType.ByteString for token in tokens)
    assert all(len(token.Identifier) == 32 for token in tokens)
    assert tokens[0] != tokens[1]


async def test_failed_activation_on_new_channel_does_not_bind_session(open_server: tuple[Server, str]) -> None:
    srv, url = open_server
    victim = Client(url)
    victim.set_user("operator")
    victim.set_password("secret")
    async with victim:
        attacker = Client(url)
        await _open_channel(attacker)
        try:
            with pytest.raises(ua.uaerrors.BadIdentityTokenRejected):
                await _activate_with_token(attacker, victim.uaclient.session.authentication_token)
            with pytest.raises(ua.UaStatusCodeError):
                await _read_server_state(attacker)
            node = await srv.nodes.objects.add_variable(2, "Setpoint", 1.0)
            await node.set_writable()
            with pytest.raises(ua.UaStatusCodeError):
                await attacker.get_node(node.nodeid).write_value(666.0)
            assert await node.read_value() == 1.0
            assert await _read_server_state(victim)
        finally:
            attacker.disconnect_socket()


async def test_session_cannot_move_to_channel_with_other_certificate(secure_server: tuple[Server, str]) -> None:
    _srv, url = secure_server
    victim = await _secure_client(url, PEER_1)
    async with victim:
        attacker = await _secure_client(url, PEER_2)
        await _open_channel(attacker)
        try:
            with pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
                await _activate_with_token(attacker, victim.uaclient.session.authentication_token)
            with pytest.raises(ua.UaStatusCodeError):
                await _read_server_state(attacker)
            assert await _read_server_state(victim)
        finally:
            attacker.disconnect_socket()


async def test_moved_session_rejects_requests_on_old_channel(open_server: tuple[Server, str]) -> None:
    _srv, url = open_server
    async with Client(url) as original:
        token = original.uaclient.session.authentication_token
        replacement = Client(url)
        await _open_channel(replacement)
        try:
            await _activate_with_token(replacement, token)
            assert await _read_server_state(replacement)
            with pytest.raises(ua.uaerrors.BadSecureChannelIdInvalid):
                await _read_server_state(original)
        finally:
            replacement.disconnect_socket()


@pytest.mark.parametrize("client_certificate", [None, PEER_2[0].read_bytes()], ids=["missing", "other"])
async def test_create_session_certificate_must_match_channel(
    secure_server: tuple[Server, str], client_certificate: bytes | None
) -> None:
    srv, url = secure_server
    validated = []

    async def reject_unknown(certificate: Any, app_description: Any) -> None:
        validated.append(certificate)
        raise ServiceError(ua.StatusCodes.BadCertificateUntrusted)

    srv.set_application_hook(reject_unknown)
    client = await _secure_client(url, PEER_1)
    create_session = client.uaclient.create_session

    async def create_session_with_other_certificate(params: ua.CreateSessionParameters) -> ua.CreateSessionResult:
        params.ClientCertificate = client_certificate
        return await create_session(params)

    client.uaclient.create_session = create_session_with_other_certificate
    with pytest.raises(ua.uaerrors.BadSecurityChecksFailed):
        await client.connect()
    await client.disconnect()
    assert validated == []


async def _connect_expecting_bad_nonce(server: Server) -> None:
    client = await signing_client(server)
    with pytest.raises(ua.uaerrors.BadNonceInvalid):
        await client.connect()
    await client.disconnect()


async def test_cli6_short_create_session_nonce_is_rejected(
    shared_signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.2: the ServerNonce has 32 to 128 bytes, and the Client shall check the length."""

    def shorten(response: ua.CreateSessionResponse) -> None:
        response.Parameters.ServerNonce = b"\x01" * 8

    tampered_responses.on(ua.CreateSessionResponse, shorten)
    await _connect_expecting_bad_nonce(shared_signing_server)


async def test_cli6_missing_activate_session_nonce_is_rejected(
    shared_signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.3.2: the ServerNonce returned by ActivateSession has 32 to 128 bytes."""

    def drop(response: ua.ActivateSessionResponse) -> None:
        response.Parameters.ServerNonce = None

    tampered_responses.on(ua.ActivateSessionResponse, drop)
    await _connect_expecting_bad_nonce(shared_signing_server)


async def test_cli6_open_secure_channel_nonce_of_wrong_length_is_rejected(
    shared_signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.6.2.2: the ServerNonce length equals the SecureChannelNonceLength of the SecurityPolicy."""

    def shorten(response: ua.OpenSecureChannelResponse) -> None:
        response.Parameters.ServerNonce = response.Parameters.ServerNonce[:16]

    tampered_responses.on(ua.OpenSecureChannelResponse, shorten)
    await _connect_expecting_bad_nonce(shared_signing_server)

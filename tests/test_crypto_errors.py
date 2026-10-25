import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.crypto import security_policies, uacrypto
from enginir_opcua.crypto.security_policies import SecurityPolicy

from .harness import EXAMPLES, signing_client

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
    certificate = await uacrypto.load_certificate(EXAMPLES / "certificate-example.der")
    private_key = await uacrypto.load_private_key(EXAMPLES / "private-key-example.pem")
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
    signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.7.3: Bad_ApplicationSignatureInvalid for a missing or invalid clientSignature."""
    _corrupt_signature(monkeypatch, user_token=False)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadApplicationSignatureInvalid):
        await client.connect()
    await client.disconnect()


async def test_cry7_bad_x509_token_signature_is_user_signature_invalid(
    signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.7.3: Bad_UserSignatureInvalid for a missing or invalid userTokenSignature."""
    signing_server.set_identity_tokens([ua.UserNameIdentityToken, ua.X509IdentityToken])
    _corrupt_signature(monkeypatch, user_token=True)
    client: Client = await signing_client(signing_server)
    await client.load_client_certificate(str(EXAMPLES / "certificates" / "peer-certificate-example-1.der"))
    await client.load_private_key(EXAMPLES / "certificates" / "peer-private-key-example-1.pem")
    with pytest.raises(ua.uaerrors.BadUserSignatureInvalid):
        await client.connect()
    await client.disconnect()

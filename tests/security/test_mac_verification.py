import pytest

from enginir_opcua import ua
from enginir_opcua.crypto import security_policies, uacrypto
from enginir_opcua.crypto.security_policies import VerifierAesCbc, VerifierHMac256

KEY = b"k" * 32
DATA = b"chunk to verify"


@pytest.mark.parametrize(
    ("verifier", "mac"),
    [(VerifierHMac256(KEY), uacrypto.hmac_sha256(KEY, DATA)), (VerifierAesCbc(KEY), uacrypto.hmac_sha1(KEY, DATA))],
)
def test_cry6_symmetric_macs_are_compared_in_constant_time(
    monkeypatch: pytest.MonkeyPatch, verifier: security_policies.Verifier, mac: bytes
) -> None:
    compared: list[tuple[bytes, bytes]] = []

    def compare_digest(a: bytes, b: bytes) -> bool:
        compared.append((a, b))
        return a == b

    monkeypatch.setattr(security_policies.hmac, "compare_digest", compare_digest, raising=False)
    verifier.verify(DATA, mac)
    with pytest.raises(ua.uaerrors.SignatureError):
        verifier.verify(DATA, bytes(len(mac)))
    assert len(compared) == 2

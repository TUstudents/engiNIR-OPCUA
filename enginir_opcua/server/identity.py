"""Matching of a UserIdentityToken to the UserTokenPolicy of the endpoint and the legacy password secret."""

from __future__ import annotations

import hmac
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua

from ..common.utils import ServiceError
from ..crypto import security_policies, uacrypto

if TYPE_CHECKING:
    from .internal_session import ChannelSecurity

_logger = logging.getLogger(__name__)

TOKEN_TYPES: dict[type, ua.UserTokenType] = {
    ua.AnonymousIdentityToken: ua.UserTokenType.Anonymous,
    ua.UserNameIdentityToken: ua.UserTokenType.UserName,
    ua.X509IdentityToken: ua.UserTokenType.Certificate,
}

USER_TOKEN_SECURITY_POLICIES: tuple[type[security_policies.SecurityPolicy], ...] = (
    security_policies.SecurityPolicyNone,
    security_policies.SecurityPolicyBasic128Rsa15,
    security_policies.SecurityPolicyBasic256,
    security_policies.SecurityPolicyBasic256Sha256,
    security_policies.SecurityPolicyAes128Sha256RsaOaep,
    security_policies.SecurityPolicyAes256Sha256RsaPss,
)

MAX_USER_NAME_BYTES = 255
LENGTH_FIELD_BYTES = 4


@dataclass(frozen=True)
class MatchedPolicy:
    policy: ua.UserTokenPolicy
    policy_uri: str


def token_type_of(token: Any) -> ua.UserTokenType:
    for token_class, token_type in TOKEN_TYPES.items():
        if isinstance(token, token_class):
            return token_type
    raise ServiceError(ua.StatusCodes.BadIdentityTokenRejected)


def match_token_policy(
    endpoints: Iterable[ua.EndpointDescription], security: ChannelSecurity, token: Any, empty: bool
) -> MatchedPolicy:
    token_type = token_type_of(token)
    offered = [
        (policy, endpoint)
        for endpoint in endpoints
        if endpoint.SecurityPolicyUri == security.policy_uri and endpoint.SecurityMode == security.mode
        for policy in endpoint.UserIdentityTokens
        if policy.TokenType == token_type
    ]
    if not offered:
        _logger.warning(
            "Rejected %s token: the endpoint of the channel offers no such UserTokenPolicy", token_type.name
        )
        raise ServiceError(ua.StatusCodes.BadIdentityTokenRejected)
    wanted = getattr(token, "PolicyId", None) or ""
    for policy, endpoint in offered:
        if empty or (policy.PolicyId or "") == wanted:
            return MatchedPolicy(policy, policy.SecurityPolicyUri or endpoint.SecurityPolicyUri)
    _logger.warning("Rejected %s token with unknown PolicyId %r", token_type.name, wanted)
    raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)


def token_encryption_algorithm(policy_uri: str) -> str:
    for policy_class in USER_TOKEN_SECURITY_POLICIES:
        if policy_class.URI == policy_uri:
            return policy_class.AsymmetricEncryptionURI
    raise ServiceError(ua.StatusCodes.BadSecurityPolicyRejected)


def _decrypt(private_key: Any, algorithm: str, secret: bytes) -> bytes:
    if algorithm == "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
        return uacrypto.decrypt_rsa15(private_key, secret)
    if algorithm == "http://www.w3.org/2001/04/xmlenc#rsa-oaep":
        return uacrypto.decrypt_rsa_oaep(private_key, secret)
    if algorithm == "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256":
        return uacrypto.decrypt_rsa_oaep_sha256(private_key, secret)
    raise ServiceError(ua.StatusCodes.BadSecurityPolicyRejected)


def decode_password_secret(private_key: Any, algorithm: str, secret: bytes, nonce: bytes) -> str | None:
    """Return the password, or None for any defect; every check runs whichever one fails."""
    try:
        raw = _decrypt(private_key, algorithm, secret)
        intact = True
    except ServiceError:
        raise
    except Exception:
        raw = b""
        intact = False
    raw = raw.ljust(LENGTH_FIELD_BYTES, b"\x00")
    length = int.from_bytes(raw[:LENGTH_FIELD_BYTES], "little")
    end = LENGTH_FIELD_BYTES + length
    data = raw[LENGTH_FIELD_BYTES:end]
    padding = raw[end:]
    password_bytes = data[: max(length - len(nonce), 0)]
    token_nonce = data[max(len(data) - len(nonce), 0) :].rjust(len(nonce), b"\x00")
    intact &= end <= len(raw)
    intact &= length >= len(nonce)
    intact &= hmac.compare_digest(token_nonce, nonce)
    intact &= padding.count(0) == len(padding)
    try:
        password: str | None = password_bytes.decode("utf-8")
    except UnicodeDecodeError:
        password = None
    if not intact or password is None:
        _logger.warning("Rejected a password secret that does not verify")
        return None
    return password


def _check_user_name(user_name: str | None) -> str:
    name = user_name or ""
    if len(name.encode("utf-8")) > MAX_USER_NAME_BYTES or any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        _logger.warning("Rejected a user name that is too long or has control characters")
        raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)
    return name


def user_name_credentials(
    matched: MatchedPolicy,
    security: ChannelSecurity,
    token: ua.UserNameIdentityToken,
    private_key: Any,
    nonce: bytes,
) -> tuple[str, str]:
    user_name = _check_user_name(token.UserName)
    expected = token_encryption_algorithm(matched.policy_uri)
    if security.mode == ua.MessageSecurityMode.Sign and not expected:
        _logger.warning("Rejected a UserName token without encryption on a Sign channel")
        raise ServiceError(ua.StatusCodes.BadIdentityTokenRejected)
    if not token.Password and not token.EncryptionAlgorithm:
        return user_name, ""
    if (token.EncryptionAlgorithm or "") != expected:
        _logger.warning(
            "Rejected user token encrypted with %r, policy %s requires %r",
            token.EncryptionAlgorithm,
            matched.policy.PolicyId,
            expected,
        )
        raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)
    secret = bytes(token.Password or b"")
    if expected:
        password = decode_password_secret(private_key, expected, secret, nonce)
    else:
        try:
            password = secret.decode("utf-8")
        except UnicodeDecodeError:
            password = None
    if password is None:
        raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)
    return user_name, password

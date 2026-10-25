import os
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from enginir_opcua import ua
from enginir_opcua.common.connection import FrameReader, SecureChannel, TransportError, TransportLimits
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto import uacrypto
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256, SecurityPolicyNone

from .harness import EXAMPLES


def test_srv25_channel_exposes_its_security_properties() -> None:
    """Part 6, 6.7.7: sessions read the channel's identity from the channel, not from the policy object."""
    channel = SecureChannel(SecurityPolicyNone(), TransportLimits())
    channel.security_token.ChannelId = 7
    assert channel.channel_id == 7
    assert channel.policy_uri == SecurityPolicyNone.URI
    assert channel.security_mode == ua.MessageSecurityMode.None_
    assert not channel.peer_certificate
    assert not channel.local_certificate
    assert channel.last_used > 0


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class ChannelPair:
    def __init__(self, client: SecureChannel, server: SecureChannel, clock: FakeClock) -> None:
        self.client = client
        self.server = server
        self.clock = clock
        self.request_id = 0
        self._ids = SimpleNamespace(get_new_channel_id=lambda: 77)

    def renew(self, lifetime: int = 3_600_000) -> None:
        self._open(ua.SecurityTokenRequestType.Renew, lifetime)

    def _open(self, request_type: ua.SecurityTokenRequestType, lifetime: int) -> None:
        nonce_length = self.client.security_policy.secure_channel_nonce_length
        client_nonce = os.urandom(nonce_length)
        params = ua.OpenSecureChannelParameters(
            RequestType=request_type, ClientNonce=client_nonce, RequestedLifetime=lifetime
        )
        result = self.server.open(params, self._ids)
        self.client.set_channel(result, request_type, client_nonce)

    def send(self, sender: SecureChannel, receiver: SecureChannel, tamper_token: int | None = None) -> object:
        self.request_id += 1
        data = bytearray(sender.message_to_binary(b"payload", request_id=self.request_id))
        if tamper_token is not None:
            data[12:16] = tamper_token.to_bytes(4, "little")
        reader = FrameReader(lambda: 65535)
        reader.feed(bytes(data))
        ((header, body),) = list(reader.frames())
        return receiver.receive_from_header_and_body(header, Buffer(bytes(body)))


def open_pair(policy: bool = False) -> ChannelPair:
    clock = FakeClock()
    if policy:
        certificate = EXAMPLES / "certificate-example.der"
        key = EXAMPLES / "private-key-example.pem"
        peer_certificate = EXAMPLES / "certificates" / "peer-certificate-example-1.der"
        peer_key = EXAMPLES / "certificates" / "peer-private-key-example-1.pem"
        client_policy = SecurityPolicyBasic256Sha256(
            uacrypto.x509_from_der(certificate.read_bytes()),
            uacrypto.x509_from_der(peer_certificate.read_bytes()),
            serialization.load_pem_private_key(peer_key.read_bytes(), None),
            ua.MessageSecurityMode.Sign,
        )
        server_policy = SecurityPolicyBasic256Sha256(
            uacrypto.x509_from_der(peer_certificate.read_bytes()),
            uacrypto.x509_from_der(certificate.read_bytes()),
            serialization.load_pem_private_key(key.read_bytes(), None),
            ua.MessageSecurityMode.Sign,
        )
    else:
        client_policy, server_policy = SecurityPolicyNone(), SecurityPolicyNone()
    client = SecureChannel(client_policy, TransportLimits())
    server = SecureChannel(server_policy, TransportLimits())
    for channel in (client, server):
        channel._clock = clock
    pair = ChannelPair(client, server, clock)
    pair._open(ua.SecurityTokenRequestType.Issue, 3_600_000)
    return pair


@pytest.mark.parametrize(
    ("requested", "revised"),
    [(0, 3_600_000), (1, 10_000), (50_000, 50_000), (2**32 - 1, 3_600_000)],
)
@pytest.mark.parametrize("request_type", [ua.SecurityTokenRequestType.Issue, ua.SecurityTokenRequestType.Renew])
def test_com37_requested_lifetime_is_revised(
    requested: int, revised: int, request_type: ua.SecurityTokenRequestType
) -> None:
    """Part 4, 5.6.2.2: the server returns a lifetime it chose within its limits, never 0."""
    pair = open_pair()
    params = ua.OpenSecureChannelParameters(RequestType=request_type, RequestedLifetime=requested)
    result = pair.server.open(params, pair._ids)
    assert result.SecurityToken.RevisedLifetime == revised


def test_com38_token_ids_are_random_nonzero_and_not_repeated() -> None:
    """Part 4, 5.6.2.2: a new SecurityToken has its own TokenId; 13 for every channel is not random."""
    ids = set()
    for _ in range(5):
        ids.add(open_pair().server.security_token.TokenId)
    pair = open_pair()
    ids.add(pair.server.security_token.TokenId)
    for _ in range(20):
        params = ua.OpenSecureChannelParameters(RequestType=ua.SecurityTokenRequestType.Renew)
        token = pair.server.open(params, pair._ids).SecurityToken
        assert token.TokenId not in ids
        ids.add(token.TokenId)
    assert 0 not in ids
    assert 13 not in ids


def test_com59_token_id_zero_does_not_replace_the_current_token() -> None:
    """Part 6, 6.7.7: the empty token slot has id 0; a chunk with that id must not rotate anything."""
    pair = open_pair()
    token_id = pair.server.security_token.TokenId
    with pytest.raises(TransportError) as error:
        pair.send(pair.client, pair.server, tamper_token=0)
    assert error.value.status == ua.StatusCodes.BadSecureChannelTokenUnknown
    assert pair.server.security_token.TokenId == token_id


@pytest.mark.parametrize("policy", [False, True], ids=["none", "basic256sha256"])
def test_cry7_unknown_token_id_is_token_unknown(policy: bool) -> None:
    """Part 6, 6.7.7: the key is selected by the TokenId; an id nobody issued selects none."""
    pair = open_pair(policy)
    with pytest.raises(TransportError) as error:
        pair.send(pair.client, pair.server, tamper_token=12345)
    assert error.value.status == ua.StatusCodes.BadSecureChannelTokenUnknown


@pytest.mark.parametrize("policy", [False, True], ids=["none", "basic256sha256"])
def test_cry7_old_and_new_tokens_both_work_during_a_renewal(policy: bool) -> None:
    """Part 4, 5.6.2.1: the server sends under the old token until the new one is used, and both are accepted."""
    pair = open_pair(policy)
    pair.send(pair.client, pair.server)
    pair.renew()
    assert pair.send(pair.server, pair.client) is not None
    assert pair.server._next is not None
    assert pair.send(pair.client, pair.server) is not None
    assert pair.server._next is None
    assert pair.send(pair.server, pair.client) is not None


@pytest.mark.parametrize("policy", [False, True], ids=["none", "basic256sha256"])
def test_com62_a_token_is_accepted_until_125_percent_of_its_lifetime(policy: bool) -> None:
    """Part 4, 5.6.2.1: expired tokens are refused, also the current one, for every policy."""
    pair = open_pair(policy)
    lifetime = pair.server.security_token.RevisedLifetime / 1000
    pair.clock.now += lifetime * 1.2
    assert pair.send(pair.client, pair.server) is not None
    pair.clock.now += lifetime * 0.1
    with pytest.raises(TransportError) as error:
        pair.send(pair.client, pair.server)
    assert error.value.status == ua.StatusCodes.BadSecureChannelTokenUnknown
    assert pair.server.expires_in() == 0


def test_com62_expires_in_counts_down_to_the_end_of_the_last_window() -> None:
    """Part 4, 5.6.2.1: the channel is closed when no token is inside its window any more."""
    pair = open_pair()
    lifetime = pair.server.security_token.RevisedLifetime / 1000
    assert pair.server.expires_in() == pytest.approx(lifetime * 1.25)
    pair.clock.now += lifetime
    assert pair.server.expires_in() == pytest.approx(lifetime * 0.25)
    pair.renew()
    pair.server.open(ua.OpenSecureChannelParameters(RequestType=ua.SecurityTokenRequestType.Renew), pair._ids)
    assert pair.server.expires_in() == pytest.approx(lifetime * 1.25)

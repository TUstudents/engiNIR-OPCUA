import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256, SecurityPolicyNone
from enginir_opcua.server.identity import IdentityGuard, peer_key
from enginir_opcua.server.internal_session import ChannelSecurity

from .conftest import find_free_port
from .harness import EXAMPLES, TWO_SESSION_USERS, TwoUserManager, signing_client


class Delays:
    def __init__(self) -> None:
        self.slept: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def delays(signing_server: Server) -> Delays:
    recorded = Delays()
    signing_server.iserver.identity_guard.sleep = recorded.sleep
    return recorded


async def _login(server: Server, password: str | None = None) -> None:
    client = await signing_client(server)
    if password is not None:
        client.set_password(password)
    try:
        await client.connect()
    finally:
        await client.disconnect()


async def _fail(server: Server, times: int) -> None:
    for _ in range(times):
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await _login(server, "wrong")


async def test_srv39_repeated_bad_passwords_are_delayed(signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: from the sixth attempt of a peer on, every answer waits 1 s, doubling."""
    await _fail(signing_server, 5)
    assert delays.slept == []
    await _fail(signing_server, 3)
    assert delays.slept == [1.0, 2.0, 4.0]


async def test_srv39_valid_token_is_delayed_after_five_failures(signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: the delay applies to a correct password too, which is not answered at once."""
    await _fail(signing_server, 5)
    await _login(signing_server)
    assert delays.slept == [1.0]


async def test_srv39_success_resets_the_counter(signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: a successful login clears the failures of the peer."""
    await _fail(signing_server, 5)
    await _login(signing_server)
    await _login(signing_server)
    await _fail(signing_server, 5)
    assert delays.slept == [1.0]


async def test_srv39_key_of_the_signing_server_login_is_a_peer_key(signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: a failed secured login is recorded under the key of its channel."""
    await _fail(signing_server, 1)
    assert list(signing_server.iserver.identity_guard.records) == ["ip:127.0.0.1"]


async def test_srv39_key_is_the_ip_address_when_unsecured() -> None:
    """Part 4, 5.7.3.1: unsecured channels are told apart by the IP address."""
    srv = Server(user_manager=TwoUserManager())
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        client = Client(srv.endpoint.geturl())
        client.set_user("alice")
        client.set_password("wrong")
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await client.connect()
        await client.disconnect()
        assert list(srv.iserver.identity_guard.records) == ["ip:127.0.0.1"]
        assert TWO_SESSION_USERS["alice"] != "wrong"
    finally:
        await srv.stop()


@pytest.fixture
def guard() -> IdentityGuard:
    return IdentityGuard()


def test_srv39_parallel_attempts_count_in_flight(guard: IdentityGuard) -> None:
    """Part 4, 5.7.3.1: attempts still waiting count as failures, so a burst cannot beat the counter."""
    delays = [guard.begin("uri:burst") for _ in range(8)]
    assert delays == [0.0] * 5 + [1.0, 2.0, 4.0]


def test_srv39_delay_is_capped(guard: IdentityGuard) -> None:
    """Part 4, 5.7.3.1: the delay doubles up to 30 s."""
    for _ in range(40):
        guard.begin("uri:flood")
    assert guard.begin("uri:flood") == 30.0


def test_srv39_other_peers_are_not_delayed(guard: IdentityGuard) -> None:
    """Part 4, 5.7.3.1: failures of one peer do not slow down another."""
    for _ in range(10):
        guard.begin("uri:noisy")
    assert guard.begin("uri:quiet") == 0.0


def test_srv39_table_is_bounded() -> None:
    """Part 4, 5.7.3.1: the memory for failure counters has a limit; the oldest entry goes first."""
    guard = IdentityGuard(max_keys=3)
    for number in range(5):
        guard.begin(f"uri:{number}")
        guard.record_failure(f"uri:{number}")
        guard.end(f"uri:{number}")
    assert list(guard.records) == ["uri:2", "uri:3", "uri:4"]


def test_srv39_failures_expire_after_ten_minutes() -> None:
    """Part 4, 5.7.3.1: a peer without failures for ten minutes starts afresh."""
    clock = Clock()
    guard = IdentityGuard(clock=clock)
    for _ in range(5):
        guard.begin("uri:old")
        guard.record_failure("uri:old")
        guard.end("uri:old")
    clock.now += 601
    assert guard.begin("uri:old") == 0.0


async def test_srv39_wait_is_an_await_that_leaves_other_requests_alone(signing_server: Server) -> None:
    """Part 4, 5.7.3.1: the delay is a wait on the request's own task, other Sessions keep working."""
    release = asyncio.Event()
    waiting = asyncio.Event()

    async def hold(seconds: float) -> None:
        waiting.set()
        await release.wait()

    working = await signing_client(signing_server, "bob")
    async with working:
        await _fail(signing_server, 5)
        signing_server.iserver.identity_guard.sleep = hold
        delayed = asyncio.create_task(_login(signing_server))
        await asyncio.wait_for(waiting.wait(), 10)
        assert await working.nodes.server_state.read_value() == ua.ServerState.Running
        assert not delayed.done()
        release.set()
        await asyncio.wait_for(delayed, 10)


def test_srv39_key_is_the_application_uri_of_the_certificate() -> None:
    """Part 4, 5.7.3.1: a secured channel is identified by the ApplicationUri in the client certificate."""
    uri = "urn:example:backoff-client"
    security = ChannelSecurity(
        _certificate_with_uri(uri), SecurityPolicyBasic256Sha256.URI, ua.MessageSecurityMode.Sign
    )
    assert peer_key(security, "10.1.2.3") == f"uri:{uri}"


def test_srv39_key_falls_back_to_the_address_without_a_uri() -> None:
    """Part 4, 5.7.3.1: a certificate without an ApplicationUri leaves the address as the key."""
    certificate = (EXAMPLES / "certificates" / "peer-certificate-example-1.der").read_bytes()
    security = ChannelSecurity(certificate, SecurityPolicyBasic256Sha256.URI, ua.MessageSecurityMode.Sign)
    assert peer_key(security, "10.1.2.3") == "ip:10.1.2.3"


def test_srv39_key_of_an_unsecured_channel_is_the_address_only() -> None:
    """Part 4, 5.7.3.1: with mode None the key is the IP address, whatever the client claims."""
    security = ChannelSecurity(
        _certificate_with_uri("urn:example:claimed"), SecurityPolicyNone.URI, ua.MessageSecurityMode.None_
    )
    assert peer_key(security, "10.1.2.3") == "ip:10.1.2.3"


def _certificate_with_uri(uri: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "backoff")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


async def test_srv39_clean_logins_leave_no_record(signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: the table only holds peers that failed, its memory is bounded by them."""
    guard = signing_server.iserver.identity_guard
    await _login(signing_server)
    assert guard.records == {}

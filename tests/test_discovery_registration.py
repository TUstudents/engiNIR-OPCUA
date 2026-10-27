from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.utils import ServiceError
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256

from .conftest import find_free_port
from .harness import PKI, start_discovery_server
from .pki import CLIENT_APPLICATION_URI

REGISTRANT_URI = CLIENT_APPLICATION_URI


def _registered_server(uri: str) -> ua.RegisteredServer:
    server = ua.RegisteredServer()
    server.ServerUri = uri
    server.ProductUri = uri
    server.ServerNames = [ua.LocalizedText("evil")]
    server.ServerType = ua.ApplicationType.Server
    server.DiscoveryUrls = ["opc.tcp://evil.invalid:4840"]
    server.IsOnline = True
    return server


@pytest.fixture
async def secure_discovery_server() -> AsyncIterator[Server]:
    srv = await start_discovery_server(find_free_port())
    yield srv
    await srv.stop()


async def _registrant(server: Server, secure: bool = True) -> Client:
    client = Client(server.endpoint.geturl())
    if secure:
        await client.set_security(
            SecurityPolicyBasic256Sha256,
            PKI.peer1.certificate,
            PKI.peer1.key,
            None,
            PKI.server.certificate,
            ua.MessageSecurityMode.SignAndEncrypt,
        )
    await client.connect_sessionless()
    return client


async def _registered_uris(server: Server) -> list[str]:
    async with Client(server.endpoint.geturl()) as client:
        return [description.ApplicationUri for description in await client.find_servers()]


async def test_srv5_register_server_is_refused_by_default(server: Server) -> None:
    """Part 4, 5.5.5: only discovery servers accept RegisterServer; others answer Bad_ServiceUnsupported."""
    async with Client(server.endpoint.geturl()) as client:
        with pytest.raises(ua.uaerrors.BadServiceUnsupported):
            await client.uaclient.register_server(_registered_server("urn:evil"))
        uris = [description.ApplicationUri for description in await client.find_servers()]
    assert "urn:evil" not in uris


async def test_srv5_discovery_server_accepts_registrations(secure_discovery_server: Server) -> None:
    """Part 4, 5.5.5.1: a secure channel whose certificate carries the ServerUri may register."""
    client = await _registrant(secure_discovery_server)
    try:
        await client.uaclient.register_server(_registered_server(REGISTRANT_URI))
    finally:
        await client.disconnect_sessionless()
    assert REGISTRANT_URI in await _registered_uris(secure_discovery_server)


async def test_srv5_register_server_on_none_channel_is_refused(secure_discovery_server: Server) -> None:
    """Part 4, 5.5.5.1: RegisterServer needs a SecureChannel that authenticates the client."""
    client = await _registrant(secure_discovery_server, secure=False)
    try:
        with pytest.raises(ua.uaerrors.BadSecurityModeInsufficient):
            await client.uaclient.register_server(_registered_server(REGISTRANT_URI))
    finally:
        await client.disconnect_sessionless()
    assert REGISTRANT_URI not in await _registered_uris(secure_discovery_server)


async def test_srv5_server_uri_must_match_channel_certificate(secure_discovery_server: Server) -> None:
    """Part 4, 5.5.5.1: the registration is rejected if the serverUri differs from the certificate's applicationUri."""
    client = await _registrant(secure_discovery_server)
    try:
        with pytest.raises(ua.uaerrors.BadServerUriInvalid):
            await client.uaclient.register_server(_registered_server("urn:evil"))
    finally:
        await client.disconnect_sessionless()
    assert "urn:evil" not in await _registered_uris(secure_discovery_server)


async def test_srv5_register_server2_is_checked_like_register_server(secure_discovery_server: Server) -> None:
    """Part 4, 5.5.5.1 and 5.5.6: RegisterServer2 follows the same rules."""
    params = ua.RegisterServer2Parameters()
    params.Server = _registered_server("urn:evil")
    client = await _registrant(secure_discovery_server)
    try:
        with pytest.raises(ua.uaerrors.BadServerUriInvalid):
            await client.uaclient.register_server2(params)
    finally:
        await client.disconnect_sessionless()


async def test_srv44_register_without_names_is_server_name_missing(secure_discovery_server: Server) -> None:
    """Part 4, 5.5.5.3: a RegisteredServer without ServerNames is Bad_ServerNameMissing."""
    registered = _registered_server(REGISTRANT_URI)
    registered.ServerNames = []
    client = await _registrant(secure_discovery_server)
    try:
        with pytest.raises(ua.uaerrors.BadServerNameMissing):
            await client.uaclient.register_server(registered)
    finally:
        await client.disconnect_sessionless()


async def test_srv44_register_online_without_discovery_urls_is_discovery_url_missing(
    secure_discovery_server: Server,
) -> None:
    """Part 4, 5.5.5.3: an online registration without DiscoveryUrls is Bad_DiscoveryUrlMissing."""
    registered = _registered_server(REGISTRANT_URI)
    registered.DiscoveryUrls = []
    client = await _registrant(secure_discovery_server)
    try:
        with pytest.raises(ua.uaerrors.BadDiscoveryUrlMissing):
            await client.uaclient.register_server(registered)
    finally:
        await client.disconnect_sessionless()


async def test_srv44_register_offline_removes_the_entry(secure_discovery_server: Server) -> None:
    """Part 4, 5.5.5.1: a server going offline registers once more with IsOnline false and disappears."""
    client = await _registrant(secure_discovery_server)
    try:
        await client.uaclient.register_server(_registered_server(REGISTRANT_URI))
        assert REGISTRANT_URI in await _registered_uris(secure_discovery_server)
        offline = _registered_server(REGISTRANT_URI)
        offline.IsOnline = False
        await client.uaclient.register_server(offline)
    finally:
        await client.disconnect_sessionless()
    assert REGISTRANT_URI not in await _registered_uris(secure_discovery_server)


async def test_srv44_registry_is_bounded() -> None:
    """Part 4, 5.5.5: a full registry refuses a new ServerUri with Bad_ResourceUnavailable; known ones renew."""
    iserver = Server().iserver
    iserver.max_registered_servers = 2
    iserver.register_server(_registered_server("urn:one"))
    iserver.register_server(_registered_server("urn:two"))
    iserver.register_server(_registered_server("urn:one"))
    with pytest.raises(ServiceError) as refused:
        iserver.register_server(_registered_server("urn:three"))
    assert refused.value.code == ua.StatusCodes.BadResourceUnavailable
    offline = _registered_server("urn:one")
    offline.IsOnline = False
    iserver.register_server(offline)
    iserver.register_server(_registered_server("urn:three"))


async def test_srv44_registrations_expire_unless_renewed() -> None:
    """Part 4, 5.5.5.1: a registration that is not renewed within the registration period leaves FindServers."""
    iserver = Server().iserver
    now = [1000.0]
    iserver.clock = lambda: now[0]
    iserver.register_server(_registered_server("urn:one"))
    iserver.register_server(_registered_server("urn:two"))
    now[0] += iserver.registration_timeout - 1
    iserver.register_server(_registered_server("urn:two"))
    now[0] += 2
    uris = [description.ApplicationUri for description in iserver.find_servers(ua.FindServersParameters())]
    assert "urn:one" not in uris
    assert "urn:two" in uris

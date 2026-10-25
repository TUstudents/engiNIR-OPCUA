import pytest

from enginir_opcua import Client, Server, ua


def _registered_server(uri: str) -> ua.RegisteredServer:
    server = ua.RegisteredServer()
    server.ServerUri = uri
    server.ProductUri = uri
    server.ServerNames = [ua.LocalizedText("evil")]
    server.ServerType = ua.ApplicationType.Server
    server.DiscoveryUrls = ["opc.tcp://evil.invalid:4840"]
    server.IsOnline = True
    return server


async def test_srv5_register_server_is_refused_by_default(server: Server) -> None:
    """Part 4, 5.5.5: only discovery servers accept RegisterServer; others answer Bad_ServiceUnsupported."""
    async with Client(server.endpoint.geturl()) as client:
        with pytest.raises(ua.uaerrors.BadServiceUnsupported):
            await client.uaclient.register_server(_registered_server("urn:evil"))
        uris = [description.ApplicationUri for description in await client.find_servers()]
    assert "urn:evil" not in uris


async def test_srv5_discovery_server_accepts_registrations(discovery_server: Server) -> None:
    """A server that opts in with accept_server_registrations() acts as a discovery server."""
    async with Client(discovery_server.endpoint.geturl()) as client:
        await client.uaclient.register_server(_registered_server("urn:test:registered"))
        uris = [description.ApplicationUri for description in await client.find_servers()]
    assert "urn:test:registered" in uris

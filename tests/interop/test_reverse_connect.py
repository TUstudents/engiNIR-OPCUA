import os
from pathlib import Path

import pytest

from enginir_opcua import Client, ua

from .reference_nodes import SERVER_APPLICATION_URI, serve
from .support import SECURITY_CASES, ReferenceStack, free_port

pytestmark = pytest.mark.interop

REVERSE_PORT_ENV = "ENGINIR_INTEROP_REVERSE_PORT"
NONE_CASE = next(case for case in SECURITY_CASES if case.name == "none")


@pytest.fixture(scope="module")
def reverse_port() -> int:
    port = os.environ.get(REVERSE_PORT_ENV)
    if not port:
        pytest.skip(f"{REVERSE_PORT_ENV} is not set; the reference server has to be started with --reverseconnect")
    return int(port)


async def test_our_client_accepts_the_reverse_connection_of_the_reference_server(
    reference_server_url: str, reverse_port: int
) -> None:
    """Part 6, 7.1.3: the reference server connects out with a ReverseHello and our client runs the session on it."""
    [endpoint, *_] = [
        e
        for e in await Client(reference_server_url).connect_and_get_server_endpoints()
        if e.EndpointUrl.startswith("opc.tcp://")
    ]
    server_uri = endpoint.Server.ApplicationUri
    client = Client(endpoint.EndpointUrl, timeout=10)
    client.listen_reverse(
        f"opc.tcp://127.0.0.1:{reverse_port}",
        server_uri=server_uri,
        endpoint_url=endpoint.EndpointUrl,
        accept_timeout=90,
    )
    async with client:
        state = await client.get_node(ua.ObjectIds.Server_ServerStatus_State).read_value()
        assert state == ua.ServerState.Running
        uris = await client.get_namespace_array()
        assert any("ReferenceServer" in uri for uri in uris)


async def test_reference_client_connects_to_our_server_by_reverse_connect(
    reference_stack: ReferenceStack, tmp_path: Path
) -> None:
    """Part 6, 7.1.3: our server connects out; the reference client accepts, sends the Hello and browses."""
    home = tmp_path / "home"
    home.mkdir()
    port = free_port()
    async with serve(tmp_path, NONE_CASE, tmp_path, free_port()) as running:
        running.server.add_reverse_connect(f"opc.tcp://localhost:{port}", endpoint_url=running.url, retry_interval=0.5)
        code, output = await reference_stack.run_client(
            home,
            running.url,
            "--autoaccept",
            "--console",
            "--nosecurity",
            "--reverseconnect",
            f"opc.tcp://localhost:{port}",
            "--browseall",
            "--timeout",
            "40",
        )
    assert SERVER_APPLICATION_URI
    assert "Connected!" in output, output
    assert "Browse the full address space." in output, output
    assert code == 0, output


async def test_reference_client_reads_our_diagnostics(reference_stack: ReferenceStack, tmp_path: Path) -> None:
    """Part 5, 6.3.3: the reference client browses the diagnostics of our server without error."""
    home = tmp_path / "home"
    home.mkdir()
    async with serve(tmp_path, NONE_CASE, tmp_path, free_port()) as running:
        running.server.diagnostics.enabled = True
        code, output = await reference_stack.run_client(
            home, running.url, "--autoaccept", "--console", "--nosecurity", "--browseall", "--timeout", "30"
        )
        summary = running.server.diagnostics.summary()
    assert "Connected!" in output, output
    assert "Browse the full address space." in output, output
    assert code == 0, output
    assert summary.CumulatedSessionCount >= 1

import logging
import re
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from tests.conftest import find_free_port
from tests.waiting import wait_until

PEER = r"127\.0\.0\.1:\d+"
SERVER_LOGGERS = ("enginir_opcua.server", "enginir_opcua.common", "enginir_opcua.crypto")
NOISE = ("None", "TransportLimits(", "processor returned", "User(role", "  ")


def lines(caplog: pytest.LogCaptureFixture, level: int) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == level and r.name.startswith(SERVER_LOGGERS)]


def assert_clean(messages: list[str]) -> None:
    for message in messages:
        assert not any(noise in message for noise in NOISE), message


@pytest.fixture
async def open_server() -> AsyncIterator[Server]:
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    async with server:
        yield server


async def test_a_discovery_connection_logs_one_line_when_it_opens_and_one_when_it_closes(
    open_server: Server, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="enginir_opcua")
    client = Client(f"opc.tcp://127.0.0.1:{open_server.endpoint.port}", allow_no_security=True)
    await client.connect_and_get_server_endpoints()
    await wait_until(lambda: any(" closed" in m for m in lines(caplog, logging.INFO)))
    info = [m for m in lines(caplog, logging.INFO) if re.match(PEER, m)]
    assert len(info) == 2, info
    assert re.fullmatch(f"{PEER} connected", info[0])
    assert re.fullmatch(f"{PEER} closed \\(client closed the secure channel\\)", info[1])
    assert_clean(lines(caplog, logging.INFO))


async def test_a_session_logs_who_activated_it_what_failed_and_when_it_closed(
    open_server: Server, caplog: pytest.LogCaptureFixture
) -> None:
    ns = await open_server.register_namespace("http://test.example/log")
    node = await open_server.nodes.objects.add_variable(ns, "Locked", 1.0)
    caplog.set_level(logging.INFO, logger="enginir_opcua")
    async with Client(f"opc.tcp://127.0.0.1:{open_server.endpoint.port}", allow_no_security=True) as client:
        with pytest.raises(ua.UaStatusCodeError):
            await client.get_node(node.nodeid).write_value(2.0)
    info = lines(caplog, logging.INFO)
    session = r'Session ns=1;i=\d+ "engiNIR OPC UA Client Session\d+ [0-9a-f]+"'
    assert any(re.fullmatch(f"{session} activated for anonymous from {PEER}", m) for m in info), info
    assert any(re.fullmatch(f"Write from {session} \\(anonymous\\) failed: BadUserAccessDenied", m) for m in info), info
    assert any(re.fullmatch(f"{session} closed", m) for m in info), info
    assert_clean(info)


async def test_an_untrusted_client_certificate_gives_one_warning_with_the_trust_command(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    url = f"opc.tcp://127.0.0.1:{find_free_port()}/log/"
    server = Server.quickstart(url, pki=tmp_path / "server")
    client = Client.quickstart(url, pki=tmp_path / "client")
    await server.init()
    await client.init_pki()
    (tmp_path / "client" / "trusted" / "certs" / "server.der").write_bytes(
        (tmp_path / "server" / "own" / "certs" / "application.der").read_bytes()
    )
    caplog.set_level(logging.INFO, logger="enginir_opcua")
    async with server:
        with pytest.raises(Exception):
            await client.connect()
    warnings = [m for m in lines(caplog, logging.WARNING) if "certificate" in m and "client" in m.lower()]
    refused = [m for m in warnings if "rejected" in m]
    assert len(refused) == 1, warnings
    assert re.match(f"{PEER} refused: client certificate [0-9a-f]{{40}} \\(CN=", refused[0])
    assert "enginir-opcua trust" in refused[0] and "set_trust_store" not in refused[0]


async def test_the_startup_warning_names_the_trusted_folder_of_the_pki_directory(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    server = Server.quickstart(f"opc.tcp://127.0.0.1:{find_free_port()}/log/", pki=tmp_path / "pki")
    await server.init()
    caplog.set_level(logging.WARNING, logger="enginir_opcua")
    async with server:
        pass
    warning = next(m for m in lines(caplog, logging.WARNING) if "No client certificate is trusted" in m)
    assert str(tmp_path / "pki" / "trusted" / "certs") in warning
    assert "enginir-opcua trust" in warning and "set_trust_store" not in warning

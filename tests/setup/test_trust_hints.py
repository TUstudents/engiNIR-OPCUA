import logging
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto import pki
from enginir_opcua.crypto.uacrypto import certificate_thumbprint
from enginir_opcua.crypto.validator import Outcome, Step, untrusted_hint
from tests.setup.conftest import make_credentials, trust


def thumbprint_of(directory: Path) -> str:
    return certificate_thumbprint((directory / "own" / "certs" / pki.CERTIFICATE_NAME).read_bytes()).hex()


async def refused_pair(tmp_path: Path, port: int, trust_client: bool, trust_server: bool) -> tuple[Server, Client]:
    url = f"opc.tcp://127.0.0.1:{port}/hint/"
    server = Server.quickstart(url, pki=tmp_path / "spki")
    client = Client.quickstart(url, pki=tmp_path / "cpki")
    await server.init()
    await make_credentials(tmp_path / "cpki", client.application_uri, pki.CLIENT_USAGE)
    if trust_client:
        trust(tmp_path / "spki", tmp_path / "cpki")
    if trust_server:
        trust(tmp_path / "cpki", tmp_path / "spki")
    return server, client


async def test_r48_the_server_log_names_the_trust_command(
    tmp_path: Path, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    server, client = await refused_pair(tmp_path, port, trust_client=False, trust_server=True)
    thumbprint = thumbprint_of(tmp_path / "cpki")
    async with server:
        with caplog.at_level(logging.WARNING):
            with pytest.raises(ua.UaError):
                await client.connect()
            with pytest.raises(ua.UaError):
                await client.connect()
    hints = [r.getMessage() for r in caplog.records if "it is not trusted" in r.getMessage()]
    assert len(hints) == 1
    assert hints[0].startswith(f"client certificate {thumbprint} (")
    assert f"enginir-opcua trust {thumbprint} --pki {tmp_path / 'spki'}" in hints[0]


async def test_r49_the_client_exception_names_the_trust_command(tmp_path: Path, port: int) -> None:
    server, client = await refused_pair(tmp_path, port, trust_client=True, trust_server=False)
    thumbprint = thumbprint_of(tmp_path / "spki")
    async with server:
        with pytest.raises(ua.uaerrors.BadCertificateUntrusted) as error:
            await client.connect()
    message = str(error.value)
    assert f"server certificate {thumbprint}" in message
    assert f"enginir-opcua trust {thumbprint} --pki {tmp_path / 'cpki'}" in message
    assert (tmp_path / "cpki" / "rejected" / "certs" / f"{thumbprint}.der").exists()


async def test_cli73_a_refused_channel_says_which_certificate_to_trust(tmp_path: Path, port: int) -> None:
    server, client = await refused_pair(tmp_path, port, trust_client=False, trust_server=True)
    thumbprint = thumbprint_of(tmp_path / "cpki")
    async with server:
        with pytest.raises(ua.uaerrors.BadSecurityChecksFailed) as error:
            await client.connect()
    assert f"this client's certificate {thumbprint}" in str(error.value)
    assert f"enginir-opcua trust {thumbprint} --pki" in str(error.value)


async def test_cli72_the_server_certificate_of_the_endpoint_list_is_kept_for_trusting(
    tmp_path: Path, port: int
) -> None:
    server, client = await refused_pair(tmp_path, port, trust_client=False, trust_server=False)
    thumbprint = thumbprint_of(tmp_path / "spki")
    async with server:
        with pytest.raises(ua.UaError):
            await client.connect()
    assert (tmp_path / "cpki" / "rejected" / "certs" / f"{thumbprint}.der").exists()


def test_the_hint_without_a_pki_directory_names_the_trust_store() -> None:
    outcome = Outcome(
        False, status=ua.StatusCodes.BadCertificateUntrusted, step=Step.TRUST, subject="CN=x", untrusted_chain=(b"abc",)
    )
    assert "trusted certificates of the server's trust store" in (untrusted_hint("client", outcome, None) or "")
    assert untrusted_hint("client", Outcome(True), None) is None

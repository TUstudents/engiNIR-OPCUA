import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from enginir_opcua import Client, Server
from enginir_opcua.crypto import pki, users_file
from tests.conftest import find_free_port

PASSWORD = "correct horse"


async def make_credentials(directory: Path, uri: str, usage: list) -> None:  # type: ignore[type-arg]
    pki.create_directories(directory)
    await pki.load_own_credentials(directory, application_uri=uri, host_names=["localhost"], usage=usage)


def trust(directory: Path, other: Path) -> None:
    source = other / "own" / "certs" / pki.CERTIFICATE_NAME
    shutil.copy(source, directory / "trusted" / "certs" / f"from-{other.name}.der")


@pytest.fixture
def port() -> int:
    return find_free_port()


@pytest.fixture
def users(tmp_path: Path) -> Path:
    path = tmp_path / "users.toml"
    users_file.write_users(path, [users_file.UserRecord("alice", "user", users_file.hash_password(PASSWORD))])
    return path


@pytest.fixture
async def paired(tmp_path: Path, port: int, users: Path) -> AsyncIterator[tuple[Server, Client]]:
    url = f"opc.tcp://127.0.0.1:{port}/quick/"
    server = Server.quickstart(url, pki=tmp_path / "server-pki", users=users)
    client = Client.quickstart(url, pki=tmp_path / "client-pki", username="alice", password=PASSWORD)
    await server.init()
    await make_credentials(tmp_path / "client-pki", client.application_uri, pki.CLIENT_USAGE)
    trust(tmp_path / "server-pki", tmp_path / "client-pki")
    trust(tmp_path / "client-pki", tmp_path / "server-pki")
    async with server:
        yield server, client

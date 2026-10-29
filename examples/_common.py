"""
Helpers shared by the examples: a temporary working directory, a free port, and the pairing of two PKI directories.
The pairing is what `enginir-opcua pair` does on the command line; see 01_secure_pair.py for the steps spelled out.
"""

import argparse
import shutil
import socket
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from enginir_opcua.crypto import pki


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def workdir() -> Iterator[Path]:
    directory = Path(tempfile.mkdtemp(prefix="enginir-example-"))
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def duration_argument(default: float = 2.0, text: str = "seconds to keep running") -> float:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=default, help=text)
    return float(parser.parse_args().duration)


async def create_client_credentials(client_pki: Path, application_uri: str) -> None:
    pki.create_directories(client_pki)
    await pki.load_own_credentials(
        client_pki, application_uri=application_uri, host_names=["localhost"], usage=pki.CLIENT_USAGE
    )


def trust(directory: Path, other: Path) -> None:
    source = other / "own" / "certs" / pki.CERTIFICATE_NAME
    shutil.copy(source, directory / "trusted" / "certs" / f"from-{other.name}.der")


async def pair(server_pki: Path, client_pki: Path, client_uri: str) -> None:
    """Both sides trust the other's certificate. The server's PKI directory exists after `await server.init()`."""
    await create_client_credentials(client_pki, client_uri)
    trust(server_pki, client_pki)
    trust(client_pki, server_pki)

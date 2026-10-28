import argparse
import getpass
import subprocess
import sys
from pathlib import Path

import pytest

from enginir_opcua import Client
from enginir_opcua.tools import PASSWORD_VARIABLE, build_parser, configure_client

ROOT = Path(__file__).parent.parent


def _arguments(*command_line: str) -> argparse.Namespace:
    return build_parser().parse_args(["read", "-n", "i=1", "--user", "operator", *command_line])


def test_tool3_password_option_is_gone() -> None:
    """A password on the command line shows up in the process list and the shell history."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["read", "-n", "i=1", "--password", "secret"])


async def test_tool3_password_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The password is taken from ENGINIR_OPCUA_PASSWORD when it is set."""
    monkeypatch.setenv(PASSWORD_VARIABLE, "from-environment")
    client = Client("opc.tcp://127.0.0.1:4840")
    await configure_client(client, _arguments())
    assert client._password == "from-environment"


async def test_tool3_password_is_asked_on_the_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """--ask-password prompts for the password, and the prompt wins over the environment."""
    monkeypatch.setenv(PASSWORD_VARIABLE, "from-environment")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "typed")
    client = Client("opc.tcp://127.0.0.1:4840")
    await configure_client(client, _arguments("--ask-password"))
    assert client._password == "typed"


async def test_tool3_no_password_is_needed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a prompt and without the variable the tool does not set a password."""
    monkeypatch.delenv(PASSWORD_VARIABLE, raising=False)
    client = Client("opc.tcp://127.0.0.1:4840")
    await configure_client(client, _arguments())
    assert not client._password


def test_tool3_the_server_command_help_says_it_is_a_demo() -> None:
    """The demo server offers no security, and its help says so."""
    result = subprocess.run(
        [sys.executable, "-m", "enginir_opcua", "server", "--help"], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0
    assert "DEMO" in result.stdout
    assert "no security" in result.stdout
    assert "127.0.0.1" in result.stdout

import argparse
import getpass
import subprocess
import sys
from pathlib import Path

import pytest

from enginir_opcua import Client
from enginir_opcua.tools import PASSWORD_VARIABLE, _configure_client_with_args, add_common_args

ROOT = Path(__file__).parent.parent


def _arguments(*command_line: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_common_args(parser)
    return parser.parse_args(["--user", "operator", *command_line])


def test_tool3_password_option_is_gone() -> None:
    """A password on the command line shows up in the process list and the shell history."""
    parser = argparse.ArgumentParser()
    add_common_args(parser)
    with pytest.raises(SystemExit):
        parser.parse_args(["--password", "secret"])


async def test_tool3_password_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The password is taken from ENGINIR_OPCUA_PASSWORD when it is set."""
    monkeypatch.setenv(PASSWORD_VARIABLE, "from-environment")
    client = Client("opc.tcp://127.0.0.1:4840")
    await _configure_client_with_args(client, _arguments())
    assert client._password == "from-environment"


async def test_tool3_password_is_asked_on_the_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """--ask-password prompts for the password, and the prompt wins over the environment."""
    monkeypatch.setenv(PASSWORD_VARIABLE, "from-environment")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "typed")
    client = Client("opc.tcp://127.0.0.1:4840")
    await _configure_client_with_args(client, _arguments("--ask-password"))
    assert client._password == "typed"


async def test_tool3_no_password_is_needed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a prompt and without the variable the tool does not set a password."""
    monkeypatch.delenv(PASSWORD_VARIABLE, raising=False)
    client = Client("opc.tcp://127.0.0.1:4840")
    await _configure_client_with_args(client, _arguments())
    assert not client._password


def test_tool3_uaserver_help_says_it_is_a_demo() -> None:
    """uaserver listens on all interfaces without security, and its help says so."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "uaserver"), "--help"], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0
    assert "DEMO" in result.stdout
    assert "no security" in result.stdout

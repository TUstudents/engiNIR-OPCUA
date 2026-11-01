import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from enginir_opcua import tools
from enginir_opcua.crypto import users_file
from tests.conftest import find_free_port

README = Path(__file__).resolve().parents[2] / "README.md"
PASSWORD = "correct horse battery"


def readme_block(marker: str) -> str:
    blocks = [block for block in re.findall(r"```python\n(.*?)```", README.read_text(encoding="utf-8"), re.S)]
    found = [block for block in blocks if marker in block]
    assert len(found) == 1, f"expected one Python block of README.md with {marker!r}"
    return found[0]


def substituted(code: str, replacements: dict[str, str]) -> str:
    for old, new in replacements.items():
        assert old in code, f"README.md no longer contains {old!r}; update the test"
        code = code.replace(old, new)
    return code


def run_python(code: str, directory: Path) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "ENGINIR_OPCUA_PASSWORD": PASSWORD}
    return subprocess.run(
        [sys.executable, "-c", code], cwd=directory, env=environment, capture_output=True, text=True, timeout=60
    )


def wait_for_port(port: int, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        assert process.poll() is None, process.communicate()
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    pytest.fail("the README server did not start")


def test_the_readme_examples_run(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    port = find_free_port()
    url = f"opc.tcp://127.0.0.1:{port}/oven/"
    assert tools.main(["init", "server", str(tmp_path / "oven"), "--endpoint", f"opc.tcp://0.0.0.0:{port}/oven/"]) == 0
    record = users_file.UserRecord("alice", "user", users_file.hash_password(PASSWORD))
    users_file.write_users(tmp_path / "oven" / "users.toml", [record])
    assert tools.main(["init", "client", str(tmp_path / "cli")]) == 0
    assert tools.main(["pair", str(tmp_path / "oven" / "pki"), str(tmp_path / "cli" / "pki")]) == 0
    capsys.readouterr()
    server_code = substituted(readme_block("ServerConfig.from_toml"), {"while True:": "for _ in range(60):"})
    client = {
        "opc.tcp://192.168.0.10:4840": url,
        '"ns=3;s=Line1.Temperature"': '"ns=2;i=2"',
        'pki="pki"': 'pki="cli/pki"',
    }
    async_code = substituted(
        readme_block("create_subscription"),
        {
            **client,
            '"ns=3;s=Line1.Setpoint"': '"ns=2;i=3"',
            'username="operator"': 'username="alice"',
            "asyncio.sleep(60)": "asyncio.sleep(2)",
        },
    )
    sync_code = substituted(readme_block("enginir_opcua.sync"), client)
    server = subprocess.Popen(
        [sys.executable, "-c", server_code], cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        wait_for_port(port, server)
        subscribed = run_python(async_code, tmp_path)
        assert subscribed.returncode == 0, subscribed.stderr
        lines = subscribed.stdout.splitlines()
        float(lines[0])
        assert any(line.startswith("ns=2;i=2 ") for line in lines[1:]), subscribed.stdout
        read = run_python(sync_code, tmp_path)
        assert read.returncode == 0, read.stderr
        float(read.stdout.strip())
    finally:
        server.kill()
        server.communicate()

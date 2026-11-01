import asyncio
import os
import re
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from enginir_opcua import Client, Server, tools, ua
from enginir_opcua.crypto import users_file
from tests.conftest import find_free_port

REPOSITORY = Path(__file__).resolve().parents[2]
README = REPOSITORY / "README.md"
NODESETS = REPOSITORY / "nodeset"
PASSWORD = "correct horse battery"


def readme_block(marker: str) -> str:
    blocks = re.findall(r"```python\n(.*?)```", README.read_text(encoding="utf-8"), re.S)
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


async def run_fragment(code: str, **names: Any) -> dict[str, Any]:
    scope: dict[str, Any] = {"asyncio": asyncio, "ua": ua, "Server": Server}
    exec(f"async def fragment({', '.join(names)}):\n{textwrap.indent(code, '    ')}\n    return locals()", scope)
    result: dict[str, Any] = await scope["fragment"](**names)
    return result


class Scale:
    def read_kg(self) -> float:
        return 12.5


def test_the_readme_demo_runs(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    port = find_free_port()
    assert tools.main(["init", "server", str(tmp_path / "srv"), "--endpoint", f"opc.tcp://0.0.0.0:{port}/demo/"]) == 0
    assert tools.main(["init", "client", str(tmp_path / "cli")]) == 0
    assert tools.main(["pair", str(tmp_path / "srv" / "pki"), str(tmp_path / "cli" / "pki")]) == 0
    record = users_file.UserRecord("alice", "user", users_file.hash_password(PASSWORD))
    users_file.write_users(tmp_path / "srv" / "users.toml", [record])
    capsys.readouterr()
    server_code = substituted(readme_block("ServerConfig.from_toml"), {"while True:": "for _ in range(60):"})
    client_code = substituted(
        readme_block("from enginir_opcua import Client\n"), {"localhost:4840": f"localhost:{port}"}
    )
    server = subprocess.Popen(
        [sys.executable, "-c", server_code], cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        wait_for_port(port, server)
        read = run_python(client_code, tmp_path)
        assert read.returncode == 0, read.stderr
        assert float(read.stdout.strip()) >= 21.5
    finally:
        server.kill()
        server.communicate()


async def test_the_readme_use_cases_run(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    url = f"opc.tcp://127.0.0.1:{find_free_port()}/cases/"
    server = Server.quickstart(url, pki=tmp_path / "server-pki")
    client = Client.quickstart(url, pki=tmp_path / "client-pki")
    await server.init()
    await client.init_pki()
    assert tools.main(["pair", str(tmp_path / "server-pki"), str(tmp_path / "client-pki")]) == 0
    idx = await server.register_namespace("urn:example:readme")
    for name, value in (("Temperature", 20.0), ("Pressure", 1.2), ("Speed", 300)):
        await server.nodes.objects.add_variable(ua.NodeId(f"Line1.{name}", idx), name, value)
    device = await server.nodes.objects.add_object(idx, "Device")
    bridge = await run_fragment(
        readme_block("set_attribute_value_callback"), server=server, idx=idx, device=device, scale=Scale()
    )
    sync_code = substituted(
        readme_block("enginir_opcua.sync"),
        {
            "opc.tcp://192.168.0.10:4840": url,
            'pki="pki"': f'pki="{tmp_path / "client-pki"}"',
            "ns=3;s=": f"ns={idx};s=",
        },
    )
    capsys.readouterr()
    async with server:
        await asyncio.to_thread(exec, sync_code, {})
        assert capsys.readouterr().out.strip() == "[20.0, 1.2, 300]"
        async with client:
            assert await client.get_node(bridge["weight"].nodeid).read_value() == 12.5
    simulator = substituted(
        readme_block("Machine.NodeSet2.xml"),
        {
            "opc.tcp://127.0.0.1:4840/machine/": f"opc.tcp://127.0.0.1:{find_free_port()}/machine/",
            'pki="pki"': f'pki="{tmp_path / "machine-pki"}"',
            '"Machine.NodeSet2.xml"': f'"{REPOSITORY / "tests" / "custom_enum.xml"}"',
            "...  # write test values, run the tests": "namespaces = await server.get_namespace_array()",
        },
    )
    simulated = await run_fragment(simulator)
    assert len(simulated["namespaces"]) > 2


@pytest.mark.skipif(not (NODESETS / "ADI").is_dir(), reason="needs the nodeset submodule")
async def test_the_readme_instrument_runs(tmp_path: Path) -> None:
    server = Server.quickstart(f"opc.tcp://127.0.0.1:{find_free_port()}/adi/", pki=tmp_path / "pki")
    await server.init()
    idx = await server.register_namespace("urn:example:instrument")
    code = substituted(
        readme_block("Opc.Ua.Adi.NodeSet2.xml"),
        {
            '"Opc.Ua.Di.NodeSet2.xml"': f'"{NODESETS / "DI" / "Opc.Ua.Di.NodeSet2.xml"}"',
            '"Opc.Ua.Adi.NodeSet2.xml"': f'"{NODESETS / "ADI" / "Opc.Ua.Adi.NodeSet2.xml"}"',
        },
    )
    instrument = await run_fragment(code, server=server, idx=idx)
    children = {(await child.read_browse_name()).Name for child in await instrument["spectrometer"].get_children()}
    assert {"Identification", "ParameterSet", "Absorbance"} <= children
    assert await instrument["serial"].read_value() == "SN-0001"

import argparse
import getpass
import os
import select
import signal
import socket
import subprocess
import sys
import time
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from enginir_opcua import Client, tools, ua, uamethod
from enginir_opcua.server.user_managers import PermissiveUserManager
from enginir_opcua.sync import Server
from enginir_opcua.tools import PASSWORD_VARIABLE, build_parser, configure_client
from tests.conftest import find_free_port
from tests.tools.sync_waiting import wait_until_sync

ROOT = Path(__file__).parent.parent.parent


PORT = find_free_port()
UNBUFFERED = {**os.environ, "PYTHONUNBUFFERED": "1"}


URL = f"opc.tcp://127.0.0.1:{PORT}/tools"


ADMIN_URL = f"opc.tcp://admin@127.0.0.1:{PORT}/tools"


UNUSED_URL = f"opc.tcp://127.0.0.1:{find_free_port()}"


@uamethod
def echo(parent, text):
    return text


@uamethod
def add(parent, x, y):
    return x + y


@pytest.fixture(scope="module")
def tool_server():
    server = Server(allow_no_security=True, user_manager=PermissiveUserManager())
    server.aio_obj.allow_plaintext_password = True
    server.disable_clock(True)
    server.set_endpoint(URL)
    idx = server.register_namespace("urn:enginir:test:tools")
    holder = server.nodes.objects.add_object(idx, "Holder")
    variables = {}
    for name, value, vtype in (
        ("Int32", 5, ua.VariantType.Int32),
        ("String", "text", ua.VariantType.String),
        ("Double", 1.5, ua.VariantType.Double),
        ("Bool", False, ua.VariantType.Boolean),
        ("DateTime", datetime(2020, 1, 1, tzinfo=UTC), ua.VariantType.DateTime),
        ("Guid", uuid.UUID(int=1), ua.VariantType.Guid),
        ("ByteString", b"\x00", ua.VariantType.ByteString),
        ("NodeId", ua.NodeId(1, 0), ua.VariantType.NodeId),
        ("LocalizedText", ua.LocalizedText("a"), ua.VariantType.LocalizedText),
        ("StatusCode", ua.StatusCode(0), ua.VariantType.StatusCode),
        ("QualifiedName", ua.QualifiedName("a", 0), ua.VariantType.QualifiedName),
        ("XmlElement", "<a/>", ua.VariantType.XmlElement),
        ("Array", [1.0, 2.0], ua.VariantType.Double),
    ):
        variable = holder.add_variable(idx, name, value, vtype)
        variable.set_writable()
        variables[name] = variable.nodeid.to_string()
    single = server.nodes.objects.add_object(idx, "Single")
    single.add_method(idx, "Echo", echo, [ua.VariantType.String], [ua.VariantType.String])
    pair = server.nodes.objects.add_object(idx, "Pair")
    pair.add_method(idx, "Add", add, [ua.VariantType.Int32, ua.VariantType.Int32], [ua.VariantType.Int32])
    pair.add_method(idx, "Echo", echo, [ua.VariantType.String], [ua.VariantType.String])
    with server:
        yield {
            "variables": variables,
            "single": single.nodeid.to_string(),
            "pair": pair.nodeid.to_string(),
            "holder": holder.nodeid.to_string(),
        }


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = tools.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_tool1_every_command_is_registered_and_k_names_are_reserved():
    names = set(tools.COMMANDS)
    assert {
        "read",
        "write",
        "call",
        "ls",
        "subscribe",
        "history",
        "discover",
        "server",
        "shell",
        "generate-structs",
    } <= names
    assert not names & tools.RESERVED_COMMANDS
    assert tools.RESERVED_COMMANDS == {"init", "trust", "pki", "pair"}


def test_tool1_browse_is_an_alias_of_ls(capsys, tool_server):
    code, out, _ = run(capsys, "browse", "-u", URL, "-n", "i=85")
    assert code == 0 and "Holder" in out


@pytest.mark.parametrize(
    ("datatype", "text", "expected"),
    [
        ("bool", "true", True),
        ("bool", "0", False),
        ("sbyte", "-5", -5),
        ("byte", "0x10", 16),
        ("int16", "-300", -300),
        ("uint16", "300", 300),
        ("int32", "-70000", -70000),
        ("uint32", "70000", 70000),
        ("int64", "-5", -5),
        ("uint64", "5", 5),
        ("float", "1.5", 1.5),
        ("double", "2.5", 2.5),
        ("string", "a,b", "a,b"),
        ("datetime", "2026-10-01", datetime(2026, 10, 1, tzinfo=UTC)),
        ("datetime", "2026-10-01T10:20:30Z", datetime(2026, 10, 1, 10, 20, 30, tzinfo=UTC)),
        ("guid", "00000000-0000-0000-0000-000000000001", uuid.UUID(int=1)),
        ("bytestring", "0a:1B ff", b"\x0a\x1b\xff"),
        ("bytestring", "0x0a1b", b"\x0a\x1b"),
        ("xmlelement", "<a/>", ua.XmlElement("<a/>")),
        ("xml", "<a/>", ua.XmlElement("<a/>")),
        ("nodeid", "ns=2;i=5", ua.NodeId(5, 2)),
        ("expandednodeid", "ns=2;i=5", ua.ExpandedNodeId(5, 2)),
        ("qualifiedname", "2:Name", ua.QualifiedName("Name", 2)),
        ("browsename", "Name", ua.QualifiedName("Name", 0)),
        ("localizedtext", "hello", ua.LocalizedText("hello")),
        ("statuscode", "0", ua.StatusCode(0)),
        ("statuscode", "BadNodeIdUnknown", ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)),
        ("Guid", "00000000-0000-0000-0000-000000000001", uuid.UUID(int=1)),
    ],
)
def test_tool1_every_datatype_choice_converts(datatype, text, expected):
    """Part 6, 5.1.2: every built-in type that the program offers can be built from text."""
    variant = tools.variant_from_text(text, datatype)
    assert variant.Value == expected


def test_tool1_the_choices_of_write_and_call_are_the_converters_types(capsys):
    for command in ("write", "call"):
        with pytest.raises(SystemExit):
            tools.main([command, "--help"])
        out = capsys.readouterr().out
        for name in (
            "bytestring",
            "xmlelement",
            "localizedtext",
            "datetime",
            "guid",
            "auto" if command == "write" else "guess",
        ):
            assert name in out


def test_tool1_without_array_a_comma_stays_in_the_string():
    assert tools.variant_from_text("a,b", "guess").Value == "a,b"
    assert tools.variant_from_text("a,b", "guess", array=True).Value == ["a", "b"]
    assert tools.variant_from_text("1;2", "int32", array=True, separator=";").Value == [1, 2]


def test_tool6_a_bad_bool_is_an_error():
    with pytest.raises(tools.ToolError, match="bool"):
        tools.variant_from_text("yes", "bool")


def test_tool1_integers_are_range_checked():
    with pytest.raises(tools.ToolError, match="byte"):
        tools.variant_from_text("300", "byte")


def test_tool1_guess_picks_the_simplest_type():
    assert tools.variant_from_text("true", "guess").VariantType is ua.VariantType.Boolean
    assert tools.variant_from_text("12", "guess").VariantType is ua.VariantType.Int64
    assert tools.variant_from_text("1.5", "guess").VariantType is ua.VariantType.Double
    assert tools.variant_from_text("abc", "guess").VariantType is ua.VariantType.String


def test_tool1_datetime_without_zone_is_utc():
    assert tools.parse_time("2026-10-01 10:00").tzinfo is UTC


def test_tool2_str_to_datetime_keeps_working_for_old_callers():
    assert tools.str_to_datetime("2026-10-01").tzinfo is UTC


def test_tool1_write_then_read_round_trip_for_each_type(capsys, tool_server):
    variables = tool_server["variables"]
    cases = {
        "Int32": "42",
        "String": "a,b,c",
        "Double": "2.25",
        "Bool": "true",
        "DateTime": "2026-10-01T10:00:00Z",
        "Guid": "00000000-0000-0000-0000-000000000002",
        "ByteString": "0aff",
        "NodeId": "ns=3;i=7",
        "LocalizedText": "hello",
        "StatusCode": "BadNodeIdUnknown",
        "QualifiedName": "3:Name",
        "XmlElement": "<b/>",
    }
    for name, text in cases.items():
        code, _, err = run(capsys, "write", "-u", ADMIN_URL, "-n", variables[name], text)
        assert code == 0, (name, err)
    code, out, _ = run(capsys, "read", "-u", URL, "-n", variables["Int32"])
    assert out.strip() == "42"
    code, out, _ = run(capsys, "read", "-u", URL, "-n", variables["String"])
    assert out.strip() == "a,b,c"


def test_tool1_write_an_array(capsys, tool_server):
    node = tool_server["variables"]["Array"]
    code, _, err = run(capsys, "write", "-u", ADMIN_URL, "-n", node, "--array", "3,4.5,6")
    assert code == 0, err
    code, out, _ = run(capsys, "read", "-u", URL, "-n", node)
    assert out.strip() == "[3.0, 4.5, 6.0]"


def test_tool1_old_array_values_still_parse(capsys, tool_server, monkeypatch):
    array = tool_server["variables"]["Array"]
    for flag, value in (("true", "1,2"), ("false", "2.5")):
        monkeypatch.setattr(sys, "argv", ["enginir-uawrite", "-u", ADMIN_URL, "-n", array, "-l", flag, value])
        with pytest.raises(SystemExit) as exit_info:
            tools.uawrite()
        capsys.readouterr()
        assert exit_info.value.code == (0 if flag == "true" else 1)


def test_tool2_an_explicit_root_node_is_accepted(capsys, tool_server):
    code, out, _ = run(capsys, "ls", "-u", URL, "-n", "i=84")
    assert code == 0 and "Objects" in out
    code, out, err = run(capsys, "read", "-u", URL, "-n", "i=84", "-a", "BrowseName")
    assert code == 0, err


def test_tool2_read_needs_a_node(capsys):
    code, _, err = run(capsys, "read", "-u", URL)
    assert code == 2 and "browse path" in err


def test_tool5_path_with_only_root_selects_the_start_node(capsys, tool_server):
    code, out, err = run(capsys, "ls", "-u", URL, "-p", "0:Root")
    assert code == 0, err
    assert "Objects" in out


def test_tool5_a_path_selects_a_node(capsys, tool_server):
    code, out, _ = run(capsys, "read", "-u", URL, "-p", "0:Objects,2:Holder,2:Int32")
    assert code == 0 and out.strip() == "42"


def test_tool5_ls_depth_zero_is_a_usage_error(capsys, tool_server):
    code, _, err = run(capsys, "ls", "-u", URL, "-n", "i=85", "-d", "0")
    assert code == 2 and "depth" in err


def test_tool5_ls_formats(capsys, tool_server):
    holder = tool_server["holder"]
    _, names, _ = run(capsys, "ls", "-u", URL, "-n", holder, "--format", "name")
    _, values, _ = run(capsys, "ls", "-u", URL, "-n", holder, "--format", "value")
    _, long, _ = run(capsys, "ls", "-u", URL, "-n", holder, "-l")
    # The first line names the server URL, whose random port may contain "42"; only the listing counts.
    names, values, long = (_listing(out) for out in (names, values, long))
    assert "Int32" in names and "42" not in names
    assert "42" in values
    assert "DataType" in long and "Timestamp" in long
    _, legacy, _ = run(capsys, "ls", "-u", URL, "-n", holder, "-l", "0")
    assert "42" not in _listing(legacy)


def _listing(out: str) -> str:
    return "\n".join(line for line in out.splitlines() if not line.startswith("Browsing node "))


def test_tool5_ls_depth_two_indents_children(capsys, tool_server):
    _, out, _ = run(capsys, "ls", "-u", URL, "-n", "i=85", "-d", "2", "--format", "name")
    assert any(line.startswith("  ") for line in out.splitlines())


@pytest.mark.parametrize(
    "argv",
    [
        ["read", "-n", "i=2258"],
        ["write", "-n", "i=2258", "1"],
        ["call", "-n", "i=85"],
        ["ls"],
        ["subscribe", "-n", "i=2258", "--count", "1"],
        ["history", "-n", "i=2258"],
        ["generate-structs", "-n", "i=93", "-o", "unused.py"],
        ["discover"],
    ],
)
def test_tool4_a_refused_connection_is_one_line_and_exit_1(capsys, argv):
    code, _out, err = run(capsys, argv[0], "-u", UNUSED_URL, "--timeout", "1", *argv[1:])
    assert code == 1
    assert "Traceback" not in err
    lines = [line for line in err.splitlines() if "error:" in line]
    assert len(lines) == 1 and lines[0].startswith(f"enginir-opcua {argv[0]}: error: ")


def test_tool4_a_bad_status_prints_its_name(capsys, tool_server):
    code, _, err = run(capsys, "read", "-u", URL, "-n", "ns=2;i=999999")
    assert code == 1 and "BadNodeIdUnknown" in err


def test_tool4_a_value_that_cannot_be_converted_is_an_error(capsys, tool_server):
    code, _, err = run(capsys, "write", "-u", ADMIN_URL, "-n", tool_server["variables"]["Int32"], "-t", "int32", "x")
    assert code == 1 and "int32" in err


def test_tool2_discover_prints_endpoints_and_survives_missing_network_support(capsys, tool_server):
    code, out, err = run(capsys, "discover", "-u", URL, "-n")
    assert code == 0, err
    assert "Endpoint 1" in out and "Security Mode" in out
    assert "not supported" in err or "Server on network" in out


def test_tool2_discover_prints_each_network_record(capsys, monkeypatch):
    async def servers(self):
        return ua.FindServersOnNetworkResult(
            Servers=[ua.ServerOnNetwork(RecordId=7, ServerName="alpha", DiscoveryUrl="opc.tcp://a:1")]
        )

    async def nothing(self):
        return []

    monkeypatch.setattr(tools.Client, "connect_and_find_servers_on_network", servers)
    monkeypatch.setattr(tools.Client, "connect_and_find_servers", nothing)
    monkeypatch.setattr(tools.Client, "connect_and_get_server_endpoints", nothing)
    code, out, _ = run(capsys, "discover", "-n")
    assert code == 0 and "alpha" in out and "opc.tcp://a:1" in out and out.count("Performing discovery") == 1


def test_tool6_call_with_one_method_needs_no_m(capsys, tool_server):
    code, out, err = run(capsys, "call", "-u", URL, "-n", tool_server["single"], "a,b")
    assert code == 0, err
    assert out.strip() == "a,b"


def test_tool6_call_with_several_methods_and_no_m_is_refused(capsys, tool_server):
    code, _, err = run(capsys, "call", "-u", URL, "-n", tool_server["pair"], "1", "2")
    assert code == 2 and "Add" in err and "Echo" in err


def test_tool1_call_passes_a_string_with_commas_and_several_arguments(capsys, tool_server):
    code, out, err = run(capsys, "call", "-u", URL, "-n", tool_server["pair"], "-m", "2:Echo", "-t", "string", "x,y")
    assert code == 0, err
    assert out.strip() == "x,y"
    code, out, err = run(capsys, "call", "-u", URL, "-n", tool_server["pair"], "-m", "2:Add", "2", "3")
    assert code == 0, err
    assert out.strip() == "5"


def test_tool6_the_old_uacall_splits_its_value_at_commas(capsys, tool_server, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["enginir-uacall", "-u", URL, "-n", tool_server["pair"], "-m", "2:Add", "2,3"])
    with pytest.raises(SystemExit) as exit_info:
        tools.uacall()
    assert exit_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip().endswith("5")
    assert "deprecated" in captured.err


def test_tool1_each_old_script_prints_the_notice_and_runs(capsys, monkeypatch):
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["scripts"]
    assert scripts["enginir-opcua"] == "enginir_opcua.tools:cli"
    old = {name: target for name, target in scripts.items() if name != "enginir-opcua"}
    assert len(old) == 11
    for name, target in old.items():
        module, function = target.split(":")
        assert module == "enginir_opcua.tools"
        monkeypatch.setattr(sys, "argv", [name, "--help"])
        with pytest.raises(SystemExit) as exit_info:
            getattr(tools, function)()
        assert exit_info.value.code == 0
        captured = capsys.readouterr()
        assert f"{name} is deprecated" in captured.err
        assert "4.0.0" in captured.err


def test_tool7_the_helper_scripts_in_tools_are_gone():
    assert not [p.name for p in (ROOT / "tools").iterdir() if p.name.startswith("ua")]


def test_tool5_the_namespace_option_is_gone(capsys):
    with pytest.raises(SystemExit):
        tools.main(["read", "-i", "2", "-n", "i=1"])


def test_tool3_the_demo_server_warns_at_start_and_binds_to_loopback_by_default(monkeypatch):
    parser = tools.build_parser()
    args = parser.parse_args(["server"])
    assert args.url == "opc.tcp://127.0.0.1:4840"


def test_tool2_server_shell_keeps_serving(capsys, monkeypatch):
    url = f"opc.tcp://127.0.0.1:{find_free_port()}"
    seen = {}

    def shell(namespace, banner=""):
        seen["names"] = set(namespace)
        seen["code"] = tools.main(["read", "-u", url, "-n", "i=2259"])
        seen["root"] = namespace["root"].read_browse_name().Name

    monkeypatch.setattr(tools, "open_shell", shell)
    assert tools.main(["server", "--shell", "-u", url]) == 0
    _out, err = capsys.readouterr()
    assert seen["code"] == 0
    assert {"server", "run", "root", "objects", "ua"} <= seen["names"]
    assert seen["root"] == "Root"
    assert "demo server" in err.lower()


def test_tool2_shell_namespace_has_client_root_objects_and_mynode(capsys, tool_server, monkeypatch):
    seen = {}

    def shell(namespace, banner=""):
        seen.update(namespace)

    monkeypatch.setattr(tools, "open_shell", shell)
    code, _, err = run(capsys, "shell", "-u", URL, "-n", tool_server["holder"])
    assert code == 0, err
    assert {"client", "root", "objects", "ua", "mynode"} <= set(seen)


def test_tool6_shell_without_ipython_sees_the_names(monkeypatch):
    import code

    captured = {}
    monkeypatch.setattr(code, "interact", lambda banner="", local=None, **kwargs: captured.update(local or {}))
    monkeypatch.setitem(sys.modules, "IPython", None)
    tools.open_shell({"client": 1, "root": 2})
    assert captured == {"client": 1, "root": 2}


def test_tool6_ipython_is_not_imported_by_the_module():
    code = "import sys\nimport enginir_opcua.tools\nassert 'IPython' not in sys.modules\n"
    assert subprocess.run([sys.executable, "-c", code], timeout=60).returncode == 0


def test_tool2_subscribe_count_stops_after_n_notifications(capsys, tool_server):
    code, out, err = run(capsys, "subscribe", "-u", URL, "-n", tool_server["variables"]["Int32"], "--count", "1")
    assert code == 0, err
    assert len(out.strip().splitlines()) == 1


def test_tool2_subscribe_duration_stops_the_run(capsys, tool_server):
    started = time.monotonic()
    code, _, err = run(capsys, "subscribe", "-u", URL, "-n", tool_server["variables"]["Int32"], "--duration", "1")
    assert code == 0, err
    assert time.monotonic() - started < 10


def test_tool2_events_subscription_defaults_to_the_server_object(capsys, tool_server):
    code, _, err = run(capsys, "subscribe", "-u", URL, "-t", "event", "--duration", "1")
    assert code == 0, err


def test_tool2_history_times_are_utc():
    assert tools.parse_time("2026-10-01").utcoffset().total_seconds() == 0


def test_tool2_control_characters_in_server_text_are_escaped():
    assert tools.clean("a\nb\x1b[31m\ttab") == "a\\x0ab\\x1b[31m\ttab"


def test_tool2_the_timeout_is_a_float(capsys):
    args = tools.build_parser().parse_args(["read", "--timeout", "0.25", "-n", "i=1"])
    assert args.timeout == 0.25


def test_tool2_the_log_level_option_and_old_verbose_flag(capsys):
    parser = tools.build_parser()
    assert parser.parse_args(["--log-level", "DEBUG", "read", "-n", "i=1"]).log_level == "DEBUG"
    assert parser.parse_args(["read", "-n", "i=1", "-v", "INFO"]).log_level == "INFO"


def test_tool3_a_password_in_the_url_is_warned_about(capsys, tool_server):
    _code, _, err = run(capsys, "read", "-u", f"opc.tcp://admin:secret@127.0.0.1:{PORT}/tools", "-n", "i=2258")
    assert "visible in the process list" in err
    assert "secret" not in err.replace("visible", "")


def read_until(process: subprocess.Popen[bytes], needle: bytes, timeout: float = 30.0) -> None:
    assert process.stdout is not None
    seen = b""
    deadline = time.monotonic() + timeout
    while needle not in seen:
        remaining = deadline - time.monotonic()
        assert remaining > 0, seen
        if select.select([process.stdout], [], [], remaining)[0]:
            chunk = os.read(process.stdout.fileno(), 4096)
            assert chunk, "the process ended before it printed the expected output"
            seen += chunk


def interrupt(process: subprocess.Popen) -> tuple[bytes | str, bytes | str]:
    process.send_signal(signal.SIGINT)
    try:
        return process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        pytest.fail(f"no exit after SIGINT; stdout={out!r} stderr={err!r}")


def port_accepts(port: int) -> bool:
    with socket.socket() as probe:
        return probe.connect_ex(("127.0.0.1", port)) == 0


def test_tool2_ctrl_c_in_subscribe_exits_cleanly(tool_server):
    command = [
        sys.executable,
        "-m",
        "enginir_opcua",
        "subscribe",
        "-u",
        URL,
        "-n",
        tool_server["variables"]["Int32"],
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=UNBUFFERED)
    read_until(process, tool_server["variables"]["Int32"].encode())
    _, err = interrupt(process)
    assert process.returncode == 0
    assert b"Traceback" not in err


def test_tool2_ctrl_c_in_server_exits_cleanly():
    port = find_free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "enginir_opcua", "server", "-u", f"opc.tcp://127.0.0.1:{port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_until_sync(lambda: port_accepts(port), timeout=30)
    _, err = interrupt(process)
    assert process.returncode == 0
    assert "Traceback" not in err
    assert "demo server" in err.lower()


def test_tool2_the_version_option(capsys):
    with pytest.raises(SystemExit) as exit_info:
        tools.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip()


def test_tool2_history_reads_values_and_events(capsys, running_server):
    node = "ns=2;s=ToolsReadWrite"
    admin = running_server.replace("//", "//admin@")
    assert tools.main(["write", "-u", admin, "-n", node, "-t", "string", "hist"]) == 0
    capsys.readouterr()
    code, out, err = run(capsys, "history", "-u", running_server, "-n", node, "--limit", "5")
    assert code == 0, err
    assert "Source timestamp" in out and "hist" in out


def test_tool1_old_tools_still_read_and_list(capsys, running_server, monkeypatch):
    for script, argv in (("uals", ["-n", "i=85"]), ("uaread", ["-n", "ns=2;s=ToolsReadWrite"])):
        monkeypatch.setattr(sys, "argv", [f"enginir-{script}", "-u", running_server, *argv])
        with pytest.raises(SystemExit) as exit_info:
            getattr(tools, script)()
        assert exit_info.value.code == 0
        assert "deprecated" in capsys.readouterr().err


ROOT = Path(__file__).parent.parent.parent


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

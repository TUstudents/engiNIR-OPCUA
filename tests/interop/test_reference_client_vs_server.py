import asyncio
import shutil
from pathlib import Path

import pytest

from enginir_opcua import ua

from .reference_nodes import serve
from .support import SECURITY_CASES, USER_NAME, USER_PASSWORD, ReferenceStack, SecurityCase, free_port, make_identity

pytestmark = pytest.mark.interop

CASES = [(case, user) for case in SECURITY_CASES for user in ("anonymous", "username")]
CASE_IDS = [f"{case.name}-{user}" for case, user in CASES]
UNREACHABLE = "opc.tcp://127.0.0.1:1/unreachable"


@pytest.fixture(scope="module")
def reference_client_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("reference-client-home")


@pytest.fixture(scope="module")
async def trusted_clients(
    reference_stack: ReferenceStack, reference_client_home: Path, tmp_path_factory: pytest.TempPathFactory
) -> Path:
    await reference_stack.run_client(reference_client_home, UNREACHABLE, "--autoaccept", "--timeout", "1")
    own = reference_client_home / "OPC Foundation" / "pki" / "own" / "certs"
    certificates = [
        path for path in own.glob("*.der") if not any(curve in path.name for curve in ("Nist", "Brainpool"))
    ]
    assert len(certificates) == 1, f"expected one RSA client certificate in {own}, found {certificates}"
    trusted = tmp_path_factory.mktemp("trusted-clients")
    shutil.copyfile(certificates[0], trusted / "reference-client.der")
    return trusted


def client_options(case: SecurityCase, user: str) -> list[str]:
    options = ["--autoaccept", "--console"]
    if case.policy is None:
        options.append("--nosecurity")
    if user == "username":
        options += ["--username", USER_NAME, "--userpassword", USER_PASSWORD]
    return options


@pytest.mark.parametrize(("case", "user"), CASES, ids=CASE_IDS)
async def test_reference_client_connects_and_browses(
    case: SecurityCase,
    user: str,
    reference_stack: ReferenceStack,
    reference_client_home: Path,
    trusted_clients: Path,
    tmp_path: Path,
) -> None:
    async with serve(tmp_path, case, trusted_clients, free_port()) as running:
        code, output = await reference_stack.run_client(
            reference_client_home, running.url, *client_options(case, user), "--browseall", "--timeout", "30"
        )
    assert "Connected!" in output, output
    assert "Browse the full address space." in output, output
    assert "Client disconnected." in output, output
    assert code == 0, output


@pytest.mark.parametrize(("case", "user"), CASES, ids=CASE_IDS)
async def test_reference_client_reads_writes_calls_and_subscribes(
    case: SecurityCase,
    user: str,
    reference_stack: ReferenceStack,
    reference_client_home: Path,
    trusted_clients: Path,
    tmp_path: Path,
) -> None:
    async with serve(tmp_path, case, trusted_clients, free_port()) as running:
        next_sequence_numbers: list[int] = []

        async def let_notifications_flow() -> None:
            await asyncio.sleep(5)
            subscriptions = running.server.iserver.subscription_service.subscriptions
            next_sequence_numbers.extend(subscription._sequence for subscription in subscriptions.values())

        _, output = await reference_stack.run_client(
            reference_client_home,
            running.url,
            *client_options(case, user),
            until="Waiting...",
            during=let_notifications_flow,
        )
        namespace = running.namespace
        assert "Connected!" in output, output
        assert "Read Value =" in output, output
        assert await running.server.get_node(ua.NodeId("Scalar_Static_Int32", namespace)).read_value() == 100
        assert await running.server.get_node(ua.NodeId("Scalar_Static_Float", namespace)).read_value() == 100.5
        assert await running.server.get_node(ua.NodeId("Scalar_Static_String", namespace)).read_value() == "String Test"
        assert running.observations.method_calls == [(10.5, 10)]
        assert "OutputValue = 20.5" in output, output
        assert running.observations.monitored_items >= 3
        assert next_sequence_numbers
        assert max(next_sequence_numbers) > 3


async def test_reference_client_with_an_untrusted_certificate_is_rejected(
    reference_stack: ReferenceStack, reference_client_home: Path, trusted_clients: Path, tmp_path: Path
) -> None:
    case = next(case for case in SECURITY_CASES if case.name == "basic256sha256-encrypt")
    someone_else = await make_identity(tmp_path / "someone-else")
    only_someone_else = tmp_path / "only-someone-else"
    only_someone_else.mkdir()
    shutil.copyfile(someone_else.certificate, only_someone_else / "someone-else.der")
    async with serve(tmp_path, case, only_someone_else, free_port()) as running:
        _, output = await reference_stack.run_client(
            reference_client_home,
            running.url,
            *client_options(case, "anonymous"),
            "--timeout",
            "5",
        )
    assert "Connected!" not in output, output
    assert "Could not connect to server!" in output, output


async def test_reference_client_browses_a_server_with_file_and_directory_objects(
    reference_stack: ReferenceStack, reference_client_home: Path, trusted_clients: Path, tmp_path: Path
) -> None:
    from enginir_opcua.server.file_transfer import MemoryFile

    case = SECURITY_CASES[0]
    root = tmp_path / "shared"
    root.mkdir()
    (root / "from_disk.txt").write_text("content")
    async with serve(tmp_path, case, trusted_clients, free_port()) as running:
        objects = running.server.nodes.objects
        await running.server.add_file(objects, "InteropFile", MemoryFile(b"abc"), mime_type="text/plain")
        await running.server.add_directory(objects, "InteropFileSystem", root, writable=True)
        code, output = await reference_stack.run_client(
            reference_client_home, running.url, *client_options(case, "anonymous"), "--browseall", "--timeout", "30"
        )
    assert "Browse the full address space." in output, output
    assert "Client disconnected." in output, output
    assert code == 0, output

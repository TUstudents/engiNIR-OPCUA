import os
import re
import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from enginir_opcua import Client, ua

from .support import (
    MATRIX,
    NONE_POLICY_URI,
    USER_TOKEN_TYPES,
    ClientIdentity,
    ReferenceStack,
    SecurityCase,
    connect,
    make_identity,
)

SERVER_URL_ENV = "ENGINIR_INTEROP_SERVER_URL"
CLIENT_DLL_ENV = "ENGINIR_INTEROP_CLIENT_DLL"
PKI_ENV = "ENGINIR_INTEROP_REFERENCE_PKI"
DOTNET_ENV = "ENGINIR_INTEROP_DOTNET"

SELECTED = re.compile(r"(?<!not )\binterop\b")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if SELECTED.search(config.option.markexpr or ""):
        return
    interop_dir = Path(__file__).parent
    deselected = [item for item in items if interop_dir in item.path.parents]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if item not in deselected]


@pytest.fixture(scope="module")
def reference_server_url() -> str:
    url = os.environ.get(SERVER_URL_ENV)
    if not url:
        pytest.skip(f"{SERVER_URL_ENV} is not set; start the reference server with tools/interop/run.sh")
    return url


@pytest.fixture(scope="module")
def reference_client_dll() -> Path:
    dll = os.environ.get(CLIENT_DLL_ENV)
    if not dll:
        pytest.skip(f"{CLIENT_DLL_ENV} is not set; point it at ConsoleReferenceClient.dll or use tools/interop/run.sh")
    path = Path(dll)
    if not path.is_file():
        pytest.skip(f"{CLIENT_DLL_ENV} points at {path}, which is not a file")
    return path


@pytest.fixture(scope="module")
def reference_stack(reference_client_dll: Path) -> ReferenceStack:
    dotnet = os.environ.get(DOTNET_ENV) or shutil.which("dotnet")
    if dotnet is None:
        pytest.skip(f"dotnet is not on PATH and {DOTNET_ENV} is not set")
    return ReferenceStack(Path(dotnet), reference_client_dll)


@pytest.fixture(scope="module")
async def identity(tmp_path_factory: pytest.TempPathFactory) -> ClientIdentity:
    return await make_identity(tmp_path_factory.mktemp("interop-identity"))


@pytest.fixture(scope="module")
def trusted_user_identity(identity: ClientIdentity) -> ClientIdentity:
    pki = os.environ.get(PKI_ENV)
    if not pki:
        pytest.skip(f"{PKI_ENV} is not set; the reference server's user certificate store is unknown")
    trusted = Path(pki) / "trustedUser" / "certs"
    trusted.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(identity.certificate, trusted / "enginir-interop-client.der")
    return identity


@pytest.fixture(scope="module")
async def offered_user_tokens(
    reference_server_url: str,
) -> dict[tuple[str, ua.MessageSecurityMode], set[ua.UserTokenType]]:
    endpoints = await Client(reference_server_url).connect_and_get_server_endpoints()
    return {
        (endpoint.SecurityPolicyUri, endpoint.SecurityMode): {token.TokenType for token in endpoint.UserIdentityTokens}
        for endpoint in endpoints
        if endpoint.EndpointUrl.startswith("opc.tcp://")
    }


@pytest.fixture(params=MATRIX, ids=[f"{case.name}-{user}" for case, user in MATRIX])
def matrix_case(
    request: pytest.FixtureRequest,
    offered_user_tokens: dict[tuple[str, ua.MessageSecurityMode], set[ua.UserTokenType]],
) -> tuple[SecurityCase, str]:
    case, user = request.param
    policy_uri = case.policy.URI if case.policy is not None else NONE_POLICY_URI
    token_type = USER_TOKEN_TYPES[user]
    if token_type not in offered_user_tokens.get((policy_uri, case.mode), set()):
        pytest.skip(f"the reference server does not offer {user} tokens on {case.name} (its UserTokenPolicy override)")
    if user == "certificate":
        request.getfixturevalue("trusted_user_identity")
    return case, user


@pytest.fixture
async def client(
    matrix_case: tuple[SecurityCase, str], reference_server_url: str, identity: ClientIdentity
) -> AsyncIterator[Client]:
    case, user = matrix_case
    connected = await connect(reference_server_url, identity, case, user)
    yield connected
    await connected.disconnect()

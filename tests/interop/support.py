import asyncio
import os
import shutil
import signal
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from enginir_opcua import Client, ua
from enginir_opcua.client.ua_client import UASocketProtocol
from enginir_opcua.crypto import security_policies

NAMESPACE_URI = "http://opcfoundation.org/Quickstarts/ReferenceServer"
USER_NAME = "user1"
USER_PASSWORD = "password"


@dataclass(frozen=True)
class SecurityCase:
    name: str
    policy: type[security_policies.SecurityPolicy] | None
    mode: ua.MessageSecurityMode
    server_policy: ua.SecurityPolicyType


SECURITY_CASES = (
    SecurityCase("none", None, ua.MessageSecurityMode.None_, ua.SecurityPolicyType.NoSecurity),
    SecurityCase(
        "basic256sha256-sign",
        security_policies.SecurityPolicyBasic256Sha256,
        ua.MessageSecurityMode.Sign,
        ua.SecurityPolicyType.Basic256Sha256_Sign,
    ),
    SecurityCase(
        "basic256sha256-encrypt",
        security_policies.SecurityPolicyBasic256Sha256,
        ua.MessageSecurityMode.SignAndEncrypt,
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
    ),
    SecurityCase(
        "aes128-encrypt",
        security_policies.SecurityPolicyAes128Sha256RsaOaep,
        ua.MessageSecurityMode.SignAndEncrypt,
        ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
    ),
    SecurityCase(
        "aes256-encrypt",
        security_policies.SecurityPolicyAes256Sha256RsaPss,
        ua.MessageSecurityMode.SignAndEncrypt,
        ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
    ),
)

NONE_POLICY_URI = "http://opcfoundation.org/UA/SecurityPolicy#None"

USER_TOKEN_TYPES = {
    "anonymous": ua.UserTokenType.Anonymous,
    "username": ua.UserTokenType.UserName,
    "certificate": ua.UserTokenType.Certificate,
}

USERS = ("anonymous", "username", "certificate")

MATRIX = tuple(
    (case, user) for case in SECURITY_CASES for user in USERS if case.policy is not None or user == "anonymous"
)


@dataclass(frozen=True)
class ClientIdentity:
    certificate: Path
    private_key: Path
    pki: Path


async def make_identity(directory: Path, reference_server_certificates: list[Path] | None = None) -> ClientIdentity:
    pki = directory / "pki"
    client = Client("opc.tcp://localhost:4840")
    await client.set_pki_directory(pki)
    for index, reference in enumerate(reference_server_certificates or []):
        shutil.copyfile(reference, pki / "trusted" / "certs" / f"reference-server-{index}.der")
    return ClientIdentity(pki / "own" / "certs" / "application.der", pki / "own" / "private" / "application.pem", pki)


async def connect(
    url: str,
    identity: ClientIdentity,
    case: SecurityCase,
    user: str,
    channel_lifetime_ms: int | None = None,
    **client_options: Any,
) -> Client:
    client = Client(url, **client_options)
    await client.set_pki_directory(identity.pki, create=False)
    if channel_lifetime_ms is not None:
        client.secure_channel_timeout = channel_lifetime_ms
    if case.policy is not None:
        await client.set_security(case.policy, mode=case.mode)
    if user == "username":
        client.set_user(USER_NAME)
        client.set_password(USER_PASSWORD)
    elif user == "certificate":
        await client.load_client_certificate(str(identity.certificate))
        await client.load_private_key(identity.private_key)
    await client.connect()
    return client


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def protocol_of(client: Client) -> UASocketProtocol:
    protocol = client.uaclient.protocol
    assert protocol is not None
    return protocol


def reference_nodeid(client_namespaces: list[str], identifier: str) -> ua.NodeId:
    return ua.NodeId(identifier, client_namespaces.index(NAMESPACE_URI))


@dataclass(frozen=True)
class ReferenceStack:
    dotnet: Path
    client_dll: Path

    def environment(self, data_home: Path) -> dict[str, str]:
        env = dict(os.environ)
        env.update({"HOME": str(data_home), "XDG_DATA_HOME": str(data_home), "DOTNET_CLI_TELEMETRY_OPTOUT": "1"})
        return env

    async def run_client(
        self,
        data_home: Path,
        url: str,
        *options: str,
        until: str | None = None,
        during: Callable[[], Awaitable[None]] | None = None,
        timeout: float = 120,
    ) -> tuple[int, str]:
        process = await asyncio.create_subprocess_exec(
            str(self.dotnet),
            str(self.client_dll),
            *options,
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=self.environment(data_home),
            cwd=self.client_dll.parent,
        )
        stream = process.stdout
        assert stream is not None
        lines: list[str] = []
        reached = asyncio.Event()

        async def read_output() -> None:
            async for raw in stream:
                line = raw.decode(errors="replace")
                lines.append(line)
                if until is not None and until in line:
                    reached.set()

        reader = asyncio.create_task(read_output())
        try:
            async with asyncio.timeout(timeout):
                if until is not None:
                    await reached.wait()
                    if during is not None:
                        await during()
                    process.send_signal(signal.SIGINT)
                await process.wait()
        except TimeoutError:
            process.kill()
            await process.wait()
        await reader
        return process.returncode or 0, "".join(lines)

import asyncio
import os
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


SECURITY_CASES = (
    SecurityCase("none", None, ua.MessageSecurityMode.None_),
    SecurityCase("basic256sha256-sign", security_policies.SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.Sign),
    SecurityCase(
        "basic256sha256-encrypt",
        security_policies.SecurityPolicyBasic256Sha256,
        ua.MessageSecurityMode.SignAndEncrypt,
    ),
    SecurityCase(
        "aes128-encrypt", security_policies.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityMode.SignAndEncrypt
    ),
    SecurityCase(
        "aes256-encrypt", security_policies.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityMode.SignAndEncrypt
    ),
)

USERS = ("anonymous", "username", "certificate")

MATRIX = tuple(
    (case, user) for case in SECURITY_CASES for user in USERS if case.policy is not None or user == "anonymous"
)


@dataclass(frozen=True)
class ClientIdentity:
    certificate: Path
    private_key: Path


async def make_identity(directory: Path) -> ClientIdentity:
    client = Client("opc.tcp://localhost:4840")
    certificate, private_key = await client.setup_self_signed_certificate(
        directory / "key.pem", directory / "certificate.der"
    )
    return ClientIdentity(certificate, private_key)


async def connect(
    url: str,
    identity: ClientIdentity,
    case: SecurityCase,
    user: str,
    channel_lifetime_ms: int | None = None,
    **client_options: Any,
) -> Client:
    client = Client(url, **client_options)
    if channel_lifetime_ms is not None:
        client.secure_channel_timeout = channel_lifetime_ms
    if case.policy is not None:
        await client.set_security(case.policy, identity.certificate, identity.private_key, mode=case.mode)
    if user == "username":
        client.set_user(USER_NAME)
        client.set_password(USER_PASSWORD)
    elif user == "certificate":
        await client.load_client_certificate(str(identity.certificate))
        await client.load_private_key(identity.private_key)
    await client.connect()
    return client


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

    async def run_client(self, data_home: Path, url: str, *options: str, timeout: float = 120) -> tuple[int, str]:
        process = await asyncio.create_subprocess_exec(
            str(self.dotnet),
            str(self.client_dll),
            *options,
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=self.environment(data_home),
        )
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout)
        except TimeoutError:
            process.kill()
            output, _ = await process.communicate()
        return process.returncode or 0, output.decode(errors="replace")

"""Push certificate management over OPC UA (OPC 10000-12, 7.10): ServerConfiguration, TrustLists, ApplyChanges."""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto import cert_gen, pki
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.server.user_managers import UserManager
from enginir_opcua.ua.ua_binary import struct_from_binary, struct_to_binary
from tests.conftest import find_free_port
from tests.pki import live_ca, make_ca, make_identity
from tests.waiting import wait_until

ROLES = {"secadmin": UserRole.SecurityAdmin, "secadmin2": UserRole.SecurityAdmin, "admin": UserRole.Admin}
SERVER_CONFIGURATION = ua.NodeId(ua.ObjectIds.ServerConfiguration)
APPLICATION_GROUP = ua.NodeId(ua.ObjectIds.ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList)
TRUST_LIST = ua.NodeId(ua.ObjectIds.ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList)
RSA_TYPE = ua.NodeId(ua.ObjectIds.RsaSha256ApplicationCertificateType)
MASK_ALL = 15


class RoleUserManager(UserManager):
    accepted_token_types = frozenset({ua.UserTokenType.UserName})

    def get_user(
        self, iserver: Any, username: str | None = None, password: str | None = None, certificate: Any = None
    ) -> User | None:
        role = ROLES.get(username or "")
        return User(role=role, name=username) if role is not None else None


@dataclass
class Rig:
    server: Server
    port: int
    root: Path
    client_root: Path
    clients: list[Client]

    @property
    def url(self) -> str:
        return f"opc.tcp://127.0.0.1:{self.port}"

    async def connect(self, user: str, mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt) -> Client:
        index = len(self.clients)
        root = self.client_root / f"client{index}"
        client = Client(f"opc.tcp://{user}:pw@127.0.0.1:{self.port}", timeout=5)
        await client.set_pki_directory(root)
        shutil.copy(root / "own" / "certs" / "application.der", self.root / "trusted" / "certs" / f"client{index}.der")
        shutil.copy(self.root / "own" / "certs" / "application.der", root / "trusted" / "certs" / f"server{index}.der")
        await self.server.reload_trust_store()
        await client.set_security(SecurityPolicyBasic256Sha256, mode=mode)
        await client.connect()
        self.clients.append(client)
        return client


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    port = find_free_port()
    server = Server(user_manager=RoleUserManager())
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    server.set_security_policy(
        [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt, ua.SecurityPolicyType.Basic256Sha256_Sign]
    )
    await server.set_pki_directory(tmp_path / "server")
    await server.enable_push_management(activity_timeout=5)
    await server.start()
    rig = Rig(server, port, tmp_path / "server", tmp_path / "clients", [])
    yield rig
    for client in rig.clients:
        try:
            await client.disconnect()
        except Exception:
            pass
    await server.stop()


def byte(value: int) -> ua.Variant:
    return ua.Variant(value, ua.VariantType.Byte)


def uint32(value: int) -> ua.Variant:
    return ua.Variant(value, ua.VariantType.UInt32)


def boolean(value: bool) -> ua.Variant:
    return ua.Variant(value, ua.VariantType.Boolean)


def node_id(value: ua.NodeId | None) -> ua.Variant:
    return ua.Variant(value if value is not None else ua.NodeId(), ua.VariantType.NodeId)


async def call(client: Client, parent: ua.NodeId, method: str, *args: ua.Variant) -> Any:
    return await client.get_node(parent).call_method(ua.QualifiedName(method, 0), *args)


async def status_of(awaitable: Any) -> int:
    with pytest.raises(ua.UaStatusCodeError) as caught:
        await awaitable
    return caught.value.code


async def read_trust_list(client: Client, mask: int | None = None) -> Any:
    if mask is None:
        handle = await call(client, TRUST_LIST, "Open", byte(1))
    else:
        handle = await call(client, TRUST_LIST, "OpenWithMasks", uint32(mask))
    content = b""
    while chunk := await call(client, TRUST_LIST, "Read", uint32(handle), ua.Variant(4096, ua.VariantType.Int32)):
        content += chunk
    await call(client, TRUST_LIST, "Close", uint32(handle))
    return struct_from_binary(ua.TrustListDataType, Buffer(content))


async def write_trust_list(client: Client, data: Any) -> bool:
    handle = await call(client, TRUST_LIST, "Open", byte(6))
    content = struct_to_binary(data)
    for offset in range(0, len(content), 2048):
        await call(
            client,
            TRUST_LIST,
            "Write",
            uint32(handle),
            ua.Variant(content[offset : offset + 2048], ua.VariantType.ByteString),
        )
    return bool(await call(client, TRUST_LIST, "CloseAndUpdate", uint32(handle)))


def trust_list_data(trusted: list[bytes], masks: int = 1, **lists: list[bytes]) -> Any:
    data = ua.TrustListDataType()
    data.SpecifiedLists = masks
    data.TrustedCertificates = trusted
    data.TrustedCrls = lists.get("trusted_crls", [])
    data.IssuerCertificates = lists.get("issuers", [])
    data.IssuerCrls = lists.get("issuer_crls", [])
    return data


def own_der(rig: Rig, index: int) -> bytes:
    return (rig.root / "trusted" / "certs" / f"client{index}.der").read_bytes()


async def test_srv86_server_configuration_has_values_and_the_unsupported_nodes_are_gone(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    configuration = client.get_node(SERVER_CONFIGURATION)
    assert await (await configuration.get_child("MaxTrustListSize")).read_value() == 65535
    assert list(await (await configuration.get_child("SupportedPrivateKeyFormats")).read_value()) == ["PEM", "PFX"]
    assert await (await configuration.get_child("SupportsTransactions")).read_value() is True
    assert await (await configuration.get_child("ApplicationUri")).read_value() == rig.server.get_application_uri()
    names = {(await child.read_browse_name()).Name for child in await configuration.get_children()}
    assert {"UpdateCertificate", "ApplyChanges", "CancelChanges", "CreateSigningRequest", "GetRejectedList"} <= names
    assert {"GetCertificates", "CertificateGroups"} <= names
    assert not names & {"ConfigurationFile", "KeyCredentialConfiguration", "ResetToServerDefaults", "DeleteCertificate"}
    groups = client.get_node(ua.NodeId(ua.ObjectIds.ServerConfiguration_CertificateGroups))
    assert {(await child.read_browse_name()).Name for child in await groups.get_children()} == {
        "DefaultApplicationGroup"
    }


async def test_push_management_needs_a_pki_directory() -> None:
    server = Server()
    await server.init()
    with pytest.raises(ua.uaerrors.ConfigurationError):
        await server.enable_push_management()


@pytest.mark.parametrize(
    ("user", "mode", "expected"),
    [
        pytest.param("secadmin", ua.MessageSecurityMode.SignAndEncrypt, None, id="security_admin_encrypted"),
        pytest.param(
            "secadmin", ua.MessageSecurityMode.Sign, ua.StatusCodes.BadSecurityModeInsufficient, id="sign_only"
        ),
        pytest.param("admin", ua.MessageSecurityMode.SignAndEncrypt, ua.StatusCodes.BadUserAccessDenied, id="admin"),
    ],
)
@pytest.mark.parametrize(
    ("parent", "method", "args"),
    [
        pytest.param(SERVER_CONFIGURATION, "GetRejectedList", (), id="get_rejected_list"),
        pytest.param(SERVER_CONFIGURATION, "GetCertificates", (node_id(None),), id="get_certificates"),
        pytest.param(TRUST_LIST, "OpenWithMasks", (uint32(MASK_ALL),), id="open_with_masks"),
        pytest.param(TRUST_LIST, "Open", (byte(1),), id="open_read"),
    ],
)
async def test_methods_need_security_admin_over_an_encrypted_channel(
    rig: Rig, user: str, mode: ua.MessageSecurityMode, expected: int | None, parent: ua.NodeId, method: str, args: tuple
) -> None:
    client = await rig.connect(user, mode)
    if expected is None:
        await call(client, parent, method, *args)
    else:
        assert await status_of(call(client, parent, method, *args)) == expected


async def test_trust_list_read_returns_the_binary_trust_list_data_type(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    data = await read_trust_list(client)
    assert data.SpecifiedLists == MASK_ALL
    assert own_der(rig, 0) in [bytes(item) for item in data.TrustedCertificates]
    masked = await read_trust_list(client, 1)
    assert masked.SpecifiedLists == 1
    assert masked.IssuerCertificates in ([], None)
    assert masked.TrustedCrls in ([], None)


async def test_trust_list_open_refuses_other_modes_and_size_is_not_supported(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    assert await status_of(call(client, TRUST_LIST, "Open", byte(3))) == ua.StatusCodes.BadNotSupported
    size = await client.get_node(TRUST_LIST).get_child("Size")
    dv = await size.read_data_value(raise_on_bad_status=False)
    assert dv.StatusCode is not None and dv.StatusCode.value == ua.StatusCodes.BadNotSupported


async def test_a_transaction_is_invisible_until_apply_changes(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    original = await read_trust_list(client)
    extra = make_identity(
        "extra",
    ).der
    kept = [bytes(item) for item in original.TrustedCertificates]
    assert await write_trust_list(client, trust_list_data([*kept, extra]))
    assert extra not in [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    assert not any(path.read_bytes() == extra for path in (rig.root / "trusted" / "certs").iterdir())
    await call(client, SERVER_CONFIGURATION, "ApplyChanges")
    assert extra in [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    assert any(path.read_bytes() == extra for path in (rig.root / "trusted" / "certs").iterdir())
    last_update = await (await client.get_node(TRUST_LIST).get_child("LastUpdateTime")).read_value()
    assert last_update.year > 2000


async def test_only_the_masked_lists_are_replaced(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    ca = make_ca()
    await write_trust_list(client, trust_list_data([], masks=4, issuers=[ca.der]))
    await call(client, SERVER_CONFIGURATION, "ApplyChanges")
    data = await read_trust_list(client)
    assert [bytes(item) for item in data.IssuerCertificates] == [ca.der]
    assert own_der(rig, 0) in [bytes(item) for item in data.TrustedCertificates]


async def test_another_session_gets_transaction_pending_and_session_id_invalid(rig: Rig) -> None:
    first = await rig.connect("secadmin")
    second = await rig.connect("secadmin2")
    kept = [bytes(item) for item in (await read_trust_list(first)).TrustedCertificates]
    await write_trust_list(first, trust_list_data(kept))
    assert await status_of(call(second, TRUST_LIST, "Open", byte(6))) == ua.StatusCodes.BadTransactionPending
    assert await status_of(call(second, SERVER_CONFIGURATION, "ApplyChanges")) == ua.StatusCodes.BadSessionIdInvalid
    assert await status_of(call(second, SERVER_CONFIGURATION, "CancelChanges")) == ua.StatusCodes.BadSessionIdInvalid
    await call(first, SERVER_CONFIGURATION, "CancelChanges")
    handle = await call(second, TRUST_LIST, "Open", byte(6))
    await call(second, TRUST_LIST, "Close", uint32(handle))


async def test_cancel_changes_discards_and_apply_without_a_transaction_is_nothing_to_do(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    assert await status_of(call(client, SERVER_CONFIGURATION, "ApplyChanges")) == ua.StatusCodes.BadNothingToDo
    assert await status_of(call(client, SERVER_CONFIGURATION, "CancelChanges")) == ua.StatusCodes.BadNothingToDo
    extra = make_identity("extra").der
    kept = [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    await write_trust_list(client, trust_list_data([*kept, extra]))
    await call(client, SERVER_CONFIGURATION, "CancelChanges")
    assert await status_of(call(client, SERVER_CONFIGURATION, "ApplyChanges")) == ua.StatusCodes.BadNothingToDo
    assert extra not in [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]


async def test_closing_the_session_ends_the_transaction(rig: Rig) -> None:
    first = await rig.connect("secadmin")
    second = await rig.connect("secadmin2")
    kept = [bytes(item) for item in (await read_trust_list(first)).TrustedCertificates]
    await write_trust_list(first, trust_list_data(kept))
    await first.disconnect()
    rig.clients.remove(first)
    await wait_until(
        lambda: rig.server._certificate_manager is not None and rig.server._certificate_manager.transaction is None
    )
    handle = await call(second, TRUST_LIST, "Open", byte(6))
    await call(second, TRUST_LIST, "Close", uint32(handle))


async def test_apply_changes_with_a_trust_list_open_for_writing_is_invalid_state(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    kept = [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    await write_trust_list(client, trust_list_data(kept))
    handle = await call(client, TRUST_LIST, "Open", byte(6))
    assert await status_of(call(client, SERVER_CONFIGURATION, "ApplyChanges")) == ua.StatusCodes.BadInvalidState
    await call(client, TRUST_LIST, "Close", uint32(handle))
    await call(client, SERVER_CONFIGURATION, "ApplyChanges")


async def test_a_trust_list_that_does_not_decode_or_parse_is_refused_and_discarded(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    handle = await call(client, TRUST_LIST, "Open", byte(6))
    await call(client, TRUST_LIST, "Write", uint32(handle), ua.Variant(b"\x01\x02", ua.VariantType.ByteString))
    assert (
        await status_of(call(client, TRUST_LIST, "CloseAndUpdate", uint32(handle))) == ua.StatusCodes.BadInvalidArgument
    )
    with pytest.raises(ua.UaStatusCodeError) as refused:
        await write_trust_list(client, trust_list_data([b"not a certificate"]))
    assert refused.value.code == ua.StatusCodes.BadCertificateInvalid
    assert await status_of(call(client, SERVER_CONFIGURATION, "ApplyChanges")) == ua.StatusCodes.BadNothingToDo


async def test_a_trust_list_over_the_size_limit_is_request_too_large(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    rig.server._certificate_manager.max_trust_list_size = 1000  # type: ignore[union-attr]
    handle = await call(client, TRUST_LIST, "Open", byte(6))
    big = ua.Variant(b"x" * 2000, ua.VariantType.ByteString)
    assert await status_of(call(client, TRUST_LIST, "Write", uint32(handle), big)) == ua.StatusCodes.BadRequestTooLarge


async def test_read_after_an_out_of_band_change_is_invalid_state(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    handle = await call(client, TRUST_LIST, "Open", byte(1))
    await rig.server.reload_trust_store()
    code = await status_of(call(client, TRUST_LIST, "Read", uint32(handle), ua.Variant(100, ua.VariantType.Int32)))
    assert code == ua.StatusCodes.BadInvalidState


async def test_the_activity_timeout_discards_an_idle_trust_list_handle(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    manager = rig.server._certificate_manager
    assert manager is not None
    manager.activity_timeout = 0.2
    handle = await call(client, TRUST_LIST, "Open", byte(6))
    await wait_until(lambda: not manager.groups[next(iter(manager.groups))].entry.handles)  # type: ignore[union-attr]
    assert await status_of(call(client, TRUST_LIST, "Close", uint32(handle))) == ua.StatusCodes.BadInvalidArgument


async def test_add_and_remove_certificate_apply_at_once(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    peer = make_identity("peer")
    await call(client, TRUST_LIST, "AddCertificate", ua.Variant(peer.der, ua.VariantType.ByteString), boolean(True))
    assert peer.der in [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    thumbprint = peer.certificate.fingerprint(
        __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA1"]).SHA1()
    ).hex()
    await call(
        client, TRUST_LIST, "RemoveCertificate", ua.Variant(thumbprint.upper(), ua.VariantType.String), boolean(True)
    )
    assert peer.der not in [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    assert (
        await status_of(
            call(client, TRUST_LIST, "RemoveCertificate", ua.Variant(thumbprint, ua.VariantType.String), boolean(True))
        )
        == ua.StatusCodes.BadInvalidArgument
    )
    assert (
        await status_of(
            call(client, TRUST_LIST, "AddCertificate", ua.Variant(peer.der, ua.VariantType.ByteString), boolean(False))
        )
        == ua.StatusCodes.BadCertificateInvalid
    )


async def test_add_certificate_while_a_transaction_exists_is_transaction_pending(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    kept = [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    await write_trust_list(client, trust_list_data(kept))
    peer = make_identity("peer")
    code = await status_of(
        call(client, TRUST_LIST, "AddCertificate", ua.Variant(peer.der, ua.VariantType.ByteString), boolean(True))
    )
    assert code == ua.StatusCodes.BadTransactionPending


async def test_remove_a_ca_that_another_certificate_needs_is_chain_incomplete(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    ca = make_ca()
    leaf = make_identity("leaf", issuer=ca)
    kept = [bytes(item) for item in (await read_trust_list(client)).TrustedCertificates]
    await write_trust_list(client, trust_list_data([*kept, ca.der, leaf.der]))
    await call(client, SERVER_CONFIGURATION, "ApplyChanges")
    thumbprint = ca.certificate.fingerprint(
        __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA1"]).SHA1()
    ).hex()
    code = await status_of(
        call(client, TRUST_LIST, "RemoveCertificate", ua.Variant(thumbprint, ua.VariantType.String), boolean(True))
    )
    assert code == ua.StatusCodes.BadCertificateChainIncomplete


def public_der(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # type: ignore[no-any-return]


def sha1_hex(der: bytes) -> str:
    return hashlib.sha1(der, usedforsecurity=False).hexdigest()


def server_der(rig: Rig) -> bytes:
    certificate = rig.server.iserver.certificate
    assert certificate is not None
    return certificate.public_bytes(serialization.Encoding.DER)


async def signing_request(
    client: Client, subject: str = "", regenerate: bool = True, nonce: bytes = b"n" * 32
) -> bytes:
    return bytes(
        await call(
            client,
            SERVER_CONFIGURATION,
            "CreateSigningRequest",
            node_id(None),
            node_id(RSA_TYPE),
            ua.Variant(subject, ua.VariantType.String),
            boolean(regenerate),
            ua.Variant(nonce, ua.VariantType.ByteString),
        )
    )


async def update_certificate(
    client: Client, certificate: bytes, key_format: str = "", key: bytes = b"", group: ua.NodeId | None = None
) -> bool:
    return bool(
        await call(
            client,
            SERVER_CONFIGURATION,
            "UpdateCertificate",
            node_id(group),
            node_id(RSA_TYPE),
            ua.Variant(certificate, ua.VariantType.ByteString),
            ua.Variant([], ua.VariantType.ByteString),
            ua.Variant(key_format, ua.VariantType.String),
            ua.Variant(key, ua.VariantType.ByteString),
        )
    )


def self_signed(rig: Rig, uri: str, key: Any = None) -> tuple[Any, bytes]:
    key = key or cert_gen.generate_private_key()
    certificate = cert_gen.generate_self_signed_app_certificate(
        key, "replacement", {}, [x509.UniformResourceIdentifier(uri), x509.DNSName("localhost")], pki.SERVER_USAGE
    )
    return key, certificate.public_bytes(serialization.Encoding.DER)


async def test_signing_request_then_update_certificate_replaces_the_server_certificate(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    watcher = await rig.connect("admin")
    ca = live_ca("Management CA")
    await call(client, TRUST_LIST, "AddCertificate", ua.Variant(ca.der, ua.VariantType.ByteString), boolean(True))
    request = x509.load_der_x509_csr(await signing_request(client))
    uris = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.UniformResourceIdentifier
    )
    assert uris == [rig.server.get_application_uri()]
    assert [path.name for path in (rig.root / "own" / "pending").iterdir()] == ["DefaultApplicationGroup_RsaSha256.pem"]
    signed = cert_gen.sign_certificate_request(request, ca.certificate, ca.key)
    signed_der = signed.public_bytes(serialization.Encoding.DER)
    before = server_der(rig)
    assert await update_certificate(client, signed_der)
    assert server_der(rig) == before
    await call(client, SERVER_CONFIGURATION, "ApplyChanges")
    assert server_der(rig) == signed_der
    assert (rig.root / "own" / "certs" / "application.der").read_bytes() == signed_der
    assert list((rig.root / "own" / "pending").iterdir()) == []
    assert bytes(rig.server.iserver.endpoints[0].ServerCertificate).startswith(signed_der)
    await wait_until(lambda: not rig.server.bserver.clients)  # type: ignore[union-attr]
    assert watcher is not None


async def test_update_certificate_with_pem_and_pfx_keys(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    key, der = self_signed(rig, rig.server.get_application_uri())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    assert await update_certificate(client, der, "PEM", pem)
    await call(client, SERVER_CONFIGURATION, "CancelChanges")
    key2, der2 = self_signed(rig, rig.server.get_application_uri())
    pfx = pkcs12.serialize_key_and_certificates(b"x", key2, None, None, serialization.NoEncryption())
    assert await update_certificate(client, der2, "PFX", pfx)
    await call(client, SERVER_CONFIGURATION, "ApplyChanges")
    assert server_der(rig) == der2


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        pytest.param("uri", ua.StatusCodes.BadCertificateUriInvalid, id="uri_mismatch"),
        pytest.param("key", ua.StatusCodes.BadSecurityChecksFailed, id="key_mismatch"),
        pytest.param("no_key", ua.StatusCodes.BadSecurityChecksFailed, id="no_matching_key"),
        pytest.param("format", ua.StatusCodes.BadNotSupported, id="unknown_format"),
        pytest.param("garbage", ua.StatusCodes.BadCertificateInvalid, id="garbage"),
        pytest.param("group", ua.StatusCodes.BadInvalidArgument, id="unknown_group"),
    ],
)
async def test_update_certificate_refusals(rig: Rig, case: str, expected: int) -> None:
    client = await rig.connect("secadmin")
    uri = "urn:other" if case == "uri" else rig.server.get_application_uri()
    key, der = self_signed(rig, uri)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    if case == "key":
        pem = cert_gen.generate_private_key().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    arguments: dict[str, Any] = {"certificate": der, "key_format": "PEM", "key": pem}
    if case == "no_key":
        arguments.update(key_format="", key=b"")
    if case == "format":
        arguments.update(key_format="DER")
    if case == "garbage":
        arguments.update(certificate=b"garbage")
    if case == "group":
        arguments.update(group=ua.NodeId(1234, 3))
    assert await status_of(update_certificate(client, **arguments)) == expected
    assert await status_of(call(client, SERVER_CONFIGURATION, "ApplyChanges")) == ua.StatusCodes.BadNothingToDo


async def test_signing_request_nonce_subject_and_pending_key(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    assert await status_of(signing_request(client, nonce=b"short")) == ua.StatusCodes.BadInvalidArgument
    assert await status_of(signing_request(client, subject="XX=bad")) == ua.StatusCodes.BadInvalidArgument
    first = x509.load_der_x509_csr(await signing_request(client, subject="CN=Pending/O=engiNIR"))
    assert first.subject.rfc4514_string() in ("O=engiNIR,CN=Pending", "CN=Pending,O=engiNIR")
    pending = rig.root / "own" / "pending" / "DefaultApplicationGroup_RsaSha256.pem"
    first_key = pending.read_bytes()
    second = x509.load_der_x509_csr(await signing_request(client))
    assert pending.read_bytes() != first_key
    assert public_der(second.public_key()) != public_der(first.public_key())
    kept = x509.load_der_x509_csr(await signing_request(client, regenerate=False))
    assert public_der(kept.public_key()) == public_der(rig.server.iserver.certificate.public_key())  # type: ignore[union-attr]


async def test_the_pending_key_is_usable_from_another_session(rig: Rig) -> None:
    first = await rig.connect("secadmin")
    second = await rig.connect("secadmin2")
    ca = live_ca("Management CA")
    await call(first, TRUST_LIST, "AddCertificate", ua.Variant(ca.der, ua.VariantType.ByteString), boolean(True))
    request = x509.load_der_x509_csr(await signing_request(first))
    signed = cert_gen.sign_certificate_request(request, ca.certificate, ca.key)
    assert await update_certificate(second, signed.public_bytes(serialization.Encoding.DER))


async def test_get_rejected_list_returns_valid_but_untrusted_certificates(rig: Rig, tmp_path: Path) -> None:
    client = await rig.connect("secadmin")
    stranger = Client(rig.url, timeout=3)
    await stranger.set_pki_directory(tmp_path / "stranger")
    shutil.copy(rig.root / "own" / "certs" / "application.der", tmp_path / "stranger" / "trusted" / "certs")
    await stranger.set_security(SecurityPolicyBasic256Sha256)
    with pytest.raises(ua.UaError):
        await stranger.connect()
    der = (tmp_path / "stranger" / "own" / "certs" / "application.der").read_bytes()
    await wait_until(lambda: any((rig.root / "rejected" / "certs").glob("*.der")))
    result = await call(client, SERVER_CONFIGURATION, "GetRejectedList")
    listed = [bytes(item) for item in result or []]
    assert der in listed


async def test_trust_list_updated_event_after_add_certificate(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    received: list[Any] = []

    class Handler:
        def event_notification(self, event: Any) -> None:
            received.append(event)

    subscription = await client.create_subscription(50, Handler())
    await subscription.subscribe_events(
        client.get_node(ua.NodeId(ua.ObjectIds.Server)), ua.NodeId(ua.ObjectIds.TrustListUpdatedAuditEventType)
    )
    peer = make_identity("peer")
    await call(client, TRUST_LIST, "AddCertificate", ua.Variant(peer.der, ua.VariantType.ByteString), boolean(True))
    await wait_until(lambda: bool(received))
    assert received[0].TrustListId == TRUST_LIST


async def test_certificate_updated_event_carries_no_private_key(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    received: list[Any] = []

    class Handler:
        def event_notification(self, event: Any) -> None:
            received.append(event)

    subscription = await client.create_subscription(50, Handler())
    await subscription.subscribe_events(
        client.get_node(ua.NodeId(ua.ObjectIds.Server)), ua.NodeId(ua.ObjectIds.CertificateUpdatedAuditEventType)
    )
    key, der = self_signed(rig, rig.server.get_application_uri())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    await update_certificate(client, der, "PEM", pem)
    await call(client, SERVER_CONFIGURATION, "ApplyChanges")
    await wait_until(lambda: bool(received))
    assert received[0].CertificateType == RSA_TYPE
    assert pem not in repr(received[0]).encode()


async def test_a_client_removed_from_the_trust_list_is_disconnected(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    await rig.connect("admin")
    assert len(rig.server.bserver.clients) == 2  # type: ignore[union-attr]
    thumbprint = sha1_hex(own_der(rig, 1))
    await call(client, TRUST_LIST, "RemoveCertificate", ua.Variant(thumbprint, ua.VariantType.String), boolean(True))
    await wait_until(lambda: len(rig.server.bserver.clients) == 1)  # type: ignore[union-attr]


async def test_get_certificates_lists_the_server_certificate(rig: Rig) -> None:
    client = await rig.connect("secadmin")
    types, certificates = await call(client, SERVER_CONFIGURATION, "GetCertificates", node_id(None))
    assert list(types) == [RSA_TYPE]
    assert bytes(certificates[0]).startswith(server_der(rig))


async def test_the_minimum_security_mode_can_be_relaxed_to_sign(rig: Rig) -> None:
    assert rig.server._certificate_manager is not None
    rig.server._certificate_manager.min_security_mode = ua.MessageSecurityMode.Sign
    client = await rig.connect("secadmin", ua.MessageSecurityMode.Sign)
    await call(client, SERVER_CONFIGURATION, "GetRejectedList")

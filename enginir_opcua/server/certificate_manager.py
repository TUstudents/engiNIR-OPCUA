"""
Certificate management over OPC UA, the push model of OPC 10000-12, 7.10: the ServerConfiguration Object, the
CertificateGroups with their TrustLists, UpdateCertificate, CreateSigningRequest, GetRejectedList, GetCertificates,
ApplyChanges and CancelChanges. Only a SecurityAdmin over an encrypted channel may call any of them.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12

from enginir_opcua import ua
from enginir_opcua.common import event_objects
from enginir_opcua.common.node import Node
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto import cert_gen, pki, security_policies
from enginir_opcua.crypto.file_journal import FileJournal
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.crypto.truststore import (
    MASK_ALL,
    MASK_ISSUER_CERTIFICATES,
    MASK_ISSUER_CRLS,
    MASK_TRUSTED_CERTIFICATES,
    MASK_TRUSTED_CRLS,
    StoreSnapshot,
    TrustLists,
    TrustStore,
)
from enginir_opcua.crypto.uacrypto import certificate_thumbprint, split_certificate_chain
from enginir_opcua.crypto.validator import CertificateValidator, PeerRole, Step, Suppression, ValidationContext
from enginir_opcua.ua.ua_binary import struct_from_binary, struct_to_binary

from .file_transfer import READ, WRITE, FileEntry, MemoryFile
from .internal_session import InternalSession, current_call_session

if TYPE_CHECKING:
    from .server import Server

_logger = logging.getLogger(__name__)

DEFAULT_MAX_TRUST_LIST_SIZE = 65_535
HARD_TRUST_LIST_LIMIT = 64 * 1024 * 1024
DEFAULT_ACTIVITY_TIMEOUT = 60.0
MIN_NONCE_LENGTH = 32
ENCODING_OVERHEAD = 16 * 1024
MIN_DATE = datetime(1601, 1, 1, tzinfo=UTC)
CERTIFICATE_TYPE = ua.NodeId(ua.ObjectIds.RsaSha256ApplicationCertificateType)
APPLICATION_GROUP = ua.NodeId(ua.ObjectIds.ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList)
_STATUS = ua.StatusCodes


def _status(code: int) -> ua.UaStatusCodeError:
    return ua.UaStatusCodeError(code)


def _der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def _variant(value: Any, variant_type: ua.VariantType) -> ua.Variant:
    return ua.Variant(value, variant_type)


class SizeUnknownFile(MemoryFile):
    """The provider behind a TrustList Object: its Size is not supported (OPC 10000-12, 7.8.2.1)."""

    def size(self) -> int | None:
        return None


class TrustListBuffer(MemoryFile):
    """The bytes a client writes into a TrustList; nothing is applied before CloseAndUpdate."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit

    async def write(self, offset: int, data: bytes) -> None:
        if offset + len(data) > self.limit:
            raise _status(_STATUS.BadRequestTooLarge)
        await super().write(offset, data)

    async def truncate(self) -> None:
        return None


class TrustListSnapshot(MemoryFile):
    """The encoded trust list a read handle sees; it fails once the store changed under it."""

    def __init__(self, content: bytes, store: TrustStore) -> None:
        super().__init__(content)
        self.store = store
        self.generation = store.generation

    async def read(self, offset: int, length: int) -> bytes:
        if self.store.generation != self.generation:
            raise _status(_STATUS.BadInvalidState)
        return await super().read(offset, length)

    def size(self) -> int | None:
        return None


@dataclass
class Group:
    name: str
    node: Node
    trust_list: Node
    store: TrustStore
    kind: str
    entry: FileEntry | None = None
    last_update: datetime = MIN_DATE


@dataclass
class PendingCertificate:
    certificate: x509.Certificate
    chain: list[x509.Certificate]
    key: RSAPrivateKey
    uses_pending_key: bool


@dataclass
class Transaction:
    session_id: ua.NodeId
    trust_lists: dict[ua.NodeId, tuple[TrustLists, int]] = field(default_factory=dict)
    certificates: dict[ua.NodeId, PendingCertificate] = field(default_factory=dict)


def encode_trust_list(lists: TrustLists, masks: int) -> bytes:
    data = ua.TrustListDataType()
    data.SpecifiedLists = masks
    data.TrustedCertificates = list(lists.trusted_certificates) if masks & MASK_TRUSTED_CERTIFICATES else []
    data.TrustedCrls = list(lists.trusted_crls) if masks & MASK_TRUSTED_CRLS else []
    data.IssuerCertificates = list(lists.issuer_certificates) if masks & MASK_ISSUER_CERTIFICATES else []
    data.IssuerCrls = list(lists.issuer_crls) if masks & MASK_ISSUER_CRLS else []
    return struct_to_binary(data)


def decode_trust_list(content: bytes) -> tuple[TrustLists, int]:
    try:
        data = struct_from_binary(ua.TrustListDataType, Buffer(content))
    except Exception as error:
        raise _status(_STATUS.BadInvalidArgument) from error
    masks = int(data.SpecifiedLists) & MASK_ALL
    return (
        TrustLists(
            tuple(bytes(item) for item in data.TrustedCertificates or []),
            tuple(bytes(item) for item in data.TrustedCrls or []),
            tuple(bytes(item) for item in data.IssuerCertificates or []),
            tuple(bytes(item) for item in data.IssuerCrls or []),
        ),
        masks,
    )


def merge_lists(current: TrustLists, new: TrustLists, masks: int) -> TrustLists:
    return TrustLists(
        new.trusted_certificates if masks & MASK_TRUSTED_CERTIFICATES else current.trusted_certificates,
        new.trusted_crls if masks & MASK_TRUSTED_CRLS else current.trusted_crls,
        new.issuer_certificates if masks & MASK_ISSUER_CERTIFICATES else current.issuer_certificates,
        new.issuer_crls if masks & MASK_ISSUER_CRLS else current.issuer_crls,
    )


def check_trust_lists(lists: TrustLists, peer_role: PeerRole) -> None:
    """
    Check a trust list as OPC 10000-12, 7.8.2.5 asks: every certificate and list parses, every revocation list is
    signed by a CA of the lists, and every certificate validates with the suppressible errors ignored.
    """
    try:
        trusted = tuple(x509.load_der_x509_certificate(der) for der in lists.trusted_certificates)
        issuers = tuple(x509.load_der_x509_certificate(der) for der in lists.issuer_certificates)
        trusted_crls = tuple(x509.load_der_x509_crl(der) for der in lists.trusted_crls)
        issuer_crls = tuple(x509.load_der_x509_crl(der) for der in lists.issuer_crls)
    except ValueError as error:
        raise _status(_STATUS.BadCertificateInvalid) from error
    authorities = [*trusted, *issuers]
    for crl in (*trusted_crls, *issuer_crls):
        issuer = next((ca for ca in authorities if ca.subject == crl.issuer and _signs_crl(crl, ca)), None)
        if issuer is None:
            raise _status(_STATUS.BadCertificateInvalid)
    snapshot = StoreSnapshot(trusted, issuers, (), (), trusted_crls, issuer_crls)
    validator = CertificateValidator(
        TrustStore.from_snapshot(snapshot),
        suppress=[suppression for suppression in Suppression],
        check_revocation=False,
    )
    for certificate in (*trusted, *issuers):
        if _is_authority(certificate):
            if not any(_issued_by(certificate, ca) for ca in (*authorities, certificate)):
                raise _status(_STATUS.BadCertificateChainIncomplete)
            continue
        outcome = validator.validate_application_certificate(_der(certificate), ValidationContext(peer_role))
        if not outcome.accepted:
            raise _status(outcome.status)


def _is_authority(certificate: x509.Certificate) -> bool:
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _signs_crl(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> bool:
    try:
        return crl.is_signature_valid(ca.public_key())
    except Exception:
        return False


class CertificateManager:
    """The push-management service of one server; create it with `Server.enable_push_management`."""

    def __init__(
        self,
        server: Server,
        *,
        max_trust_list_size: int = DEFAULT_MAX_TRUST_LIST_SIZE,
        min_security_mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
        activity_timeout: float = DEFAULT_ACTIVITY_TIMEOUT,
        close_delay: float = 0.1,
    ) -> None:
        self.server = server
        self.iserver = server.iserver
        self.max_trust_list_size = max_trust_list_size
        self.min_security_mode = min_security_mode
        self.activity_timeout = activity_timeout
        self.close_delay = close_delay
        self.groups: dict[ua.NodeId, Group] = {}
        self.transaction: Transaction | None = None
        self._transaction_session: InternalSession | None = None
        self._root: Path | None = None
        self._configuration: Node | None = None
        self._timers: dict[tuple[ua.NodeId, int], asyncio.TimerHandle] = {}
        self._pending_masks: int = MASK_ALL
        self._lock = asyncio.Lock()

    @property
    def application_store(self) -> TrustStore:
        store = self.iserver.trust_store
        assert store is not None
        return store

    async def enable(self) -> None:
        store = self.iserver.trust_store
        if store is None or store.pki_root is None or self.iserver.certificate is None:
            raise ua.uaerrors.ConfigurationError(
                "Certificate management needs a PKI directory: call set_pki_directory before enable_push_management"
            )
        self._root = store.pki_root
        isession = self.iserver.isession
        configuration = Node(isession, ua.NodeId(ua.ObjectIds.ServerConfiguration))
        self._configuration = configuration
        await self.iserver.file_service.bind_types()
        await self._remove_unsupported(configuration)
        await self._set_properties(configuration)
        await self._bind_methods(configuration)
        folder = Node(isession, ua.NodeId(ua.ObjectIds.ServerConfiguration_CertificateGroups))
        await self._add_group("DefaultApplicationGroup", folder, store, "application")
        if self.iserver.user_trust_store is not None and self.iserver.user_trust_store.pki_root is not None:
            await self._add_group("DefaultUserTokenGroup", folder, self.iserver.user_trust_store, "user")

    async def _remove_unsupported(self, configuration: Node) -> None:
        unsupported = [
            "ConfigurationFile",
            "KeyCredentialConfiguration",
            "AuthorizationServices",
            "TransactionDiagnostics",
            "ResetToServerDefaults",
            "CreateSelfSignedCertificate",
            "DeleteCertificate",
        ]
        for name in unsupported:
            node = await self._child(configuration, name)
            if node is not None:
                await node.delete(recursive=True)
        folder = Node(self.iserver.isession, ua.NodeId(ua.ObjectIds.ServerConfiguration_CertificateGroups))
        keep = {"DefaultApplicationGroup"}
        if self.iserver.user_trust_store is not None:
            keep.add("DefaultUserTokenGroup")
        for child in await folder.get_children():
            if (await child.read_browse_name()).Name not in keep:
                await child.delete(recursive=True)

    async def _child(self, node: Node, name: str) -> Node | None:
        try:
            return await node.get_child(name)
        except ua.uaerrors.UaError:
            return None

    async def _write(self, node: Node, value: Any, variant_type: ua.VariantType) -> None:
        await self.iserver.write_attribute_value(node.nodeid, ua.DataValue(ua.Variant(value, variant_type)))

    async def _set_properties(self, configuration: Node) -> None:
        server = self.server
        values: dict[str, tuple[Any, ua.VariantType]] = {
            "ApplicationUri": (server.get_application_uri(), ua.VariantType.String),
            "ProductUri": (server.product_uri, ua.VariantType.String),
            "ApplicationType": (int(server.application_type), ua.VariantType.Int32),
            "ServerCapabilities": (["NA"], ua.VariantType.String),
            "SupportedPrivateKeyFormats": (["PEM", "PFX"], ua.VariantType.String),
            "MaxTrustListSize": (self.max_trust_list_size, ua.VariantType.UInt32),
            "MulticastDnsEnabled": (False, ua.VariantType.Boolean),
            "HasSecureElement": (False, ua.VariantType.Boolean),
            "SupportsTransactions": (True, ua.VariantType.Boolean),
        }
        for name, (value, variant_type) in values.items():
            child = await self._child(configuration, name)
            if child is None:
                child = await configuration.add_property(
                    ua.NodeId(0, 0), ua.QualifiedName(name, 0), value, variant_type
                )
            await self._write(child, value, variant_type)

    async def _bind_methods(self, configuration: Node) -> None:
        service = self.iserver.file_service
        callbacks = {
            "UpdateCertificate": self.update_certificate,
            "ApplyChanges": self.apply_changes,
            "CancelChanges": self.cancel_changes,
            "CreateSigningRequest": self.create_signing_request,
            "GetRejectedList": self.get_rejected_list,
            "GetCertificates": self.get_certificates,
        }
        if await self._child(configuration, "GetCertificates") is None:
            await self._add_get_certificates(configuration)
        for name, callback in callbacks.items():
            method = await configuration.get_child(name)
            await service._bind_method(method.nodeid, self._guarded(callback))

    async def _add_get_certificates(self, configuration: Node) -> None:
        group_id = ua.Argument()
        group_id.Name = "CertificateGroupId"
        group_id.DataType = ua.NodeId(ua.ObjectIds.NodeId)
        group_id.ValueRank = -1
        types = ua.Argument()
        types.Name = "CertificateTypeIds"
        types.DataType = ua.NodeId(ua.ObjectIds.NodeId)
        types.ValueRank = 1
        certificates = ua.Argument()
        certificates.Name = "Certificates"
        certificates.DataType = ua.NodeId(ua.ObjectIds.ByteString)
        certificates.ValueRank = 1
        await configuration.add_method(
            ua.NodeId(ua.ObjectIds.ServerConfiguration_GetCertificates),
            ua.QualifiedName("GetCertificates", 0),
            self.get_certificates,
            [group_id],
            [types, certificates],
        )

    async def _add_group(self, name: str, folder: Node, store: TrustStore, kind: str) -> None:
        node = await folder.get_child(name)
        trust_list = await node.get_child("TrustList")
        group = Group(name, node, trust_list, store, kind)
        self.groups[node.nodeid] = group
        entry = FileEntry(
            trust_list,
            SizeUnknownFile(),
            writable=True,
            max_byte_string_length=None,
            write_role=UserRole.SecurityAdmin,
            opener=lambda mode, session: self._open_trust_list(group, mode),
        )
        group.entry = entry
        service = self.iserver.file_service
        await service.register_file(entry, callbacks=self._trust_list_callbacks(group))
        for name_ in ("OpenWithMasks", "CloseAndUpdate", "AddCertificate", "RemoveCertificate"):
            method = await trust_list.get_child(name_)
            callback = {
                "OpenWithMasks": self.open_with_masks,
                "CloseAndUpdate": self.close_and_update,
                "AddCertificate": self.add_certificate,
                "RemoveCertificate": self.remove_certificate,
            }[name_]
            await service._bind_method(method.nodeid, self._guarded(self._for_group(group, callback)))
        await self._write(await trust_list.get_child("LastUpdateTime"), MIN_DATE, ua.VariantType.DateTime)
        timeout = await self._child(trust_list, "ActivityTimeout")
        if timeout is not None:
            await self._write(timeout, self.activity_timeout * 1000, ua.VariantType.Double)
        certificate_types = await self._child(node, "CertificateTypes")
        if certificate_types is not None:
            types = [] if kind == "user" else [CERTIFICATE_TYPE]
            await self._write(certificate_types, types, ua.VariantType.NodeId)

    def _for_group(self, group: Group, callback: Callable[..., Any]) -> Callable[..., Any]:
        async def call(parent: ua.NodeId, *args: ua.Variant) -> Any:
            return await callback(group, *args)

        return call

    def _guarded(self, callback: Callable[..., Any]) -> Callable[..., Any]:
        async def call(parent: ua.NodeId, *args: ua.Variant) -> Any:
            self._authorize()
            return await callback(parent, *args)

        return call

    def _authorize(self) -> InternalSession:
        session = current_call_session.get()
        if session is None:
            raise _status(_STATUS.BadInternalError)
        if session.channel_security_mode < self.min_security_mode:
            raise _status(_STATUS.BadSecurityModeInsufficient)
        if session.user is None or session.user.role != UserRole.SecurityAdmin:
            raise _status(_STATUS.BadUserAccessDenied)
        return session

    def _session(self) -> InternalSession:
        session = current_call_session.get()
        assert session is not None
        return session

    def _trust_list_callbacks(self, group: Group) -> dict[str, Callable[..., Any]]:
        service = self.iserver.file_service
        base = service.file_callbacks()

        async def open_(parent: ua.NodeId, mode: ua.Variant) -> Any:
            session = self._authorize()
            requested = int(mode.Value)
            if requested not in (READ, WRITE | 4):
                raise _status(_STATUS.BadNotSupported)
            if requested & WRITE:
                self._check_transaction(session)
            self._pending_masks = MASK_ALL
            result = await base["Open"](parent, mode)
            self._arm(session.session_id, result[0].Value)
            return result

        def wrapped(name: str) -> Callable[..., Any]:
            async def call(parent: ua.NodeId, *args: ua.Variant) -> Any:
                session = self._authorize()
                if args:
                    self._arm(session.session_id, args[0].Value) if name != "Close" else self._disarm(
                        session.session_id, args[0].Value
                    )
                return await base[name](parent, *args)

            return call

        callbacks = {name: wrapped(name) for name in base}
        callbacks["Open"] = open_
        return callbacks

    def _arm(self, session_id: ua.NodeId, handle: int) -> None:
        self._disarm(session_id, handle)
        if self.activity_timeout <= 0:
            return
        loop = asyncio.get_running_loop()
        self._timers[(session_id, handle)] = loop.call_later(self.activity_timeout, self._expire, session_id, handle)

    def _disarm(self, session_id: ua.NodeId, handle: int) -> None:
        timer = self._timers.pop((session_id, handle), None)
        if timer is not None:
            timer.cancel()

    def _expire(self, session_id: ua.NodeId, handle: int) -> None:
        self._timers.pop((session_id, handle), None)
        self.iserver.file_service.release_handle(session_id, handle)

    async def _open_trust_list(self, group: Group, mode: int) -> Any:
        if mode & WRITE:
            limit = self.max_trust_list_size or HARD_TRUST_LIST_LIMIT
            return TrustListBuffer(min(limit, HARD_TRUST_LIST_LIMIT))
        store = group.store
        return TrustListSnapshot(encode_trust_list(store.read_lists(), self._pending_masks), store)

    async def open_with_masks(self, group: Group, masks: ua.Variant) -> list[ua.Variant]:
        session = self._session()
        self._pending_masks = int(masks.Value) & MASK_ALL
        assert group.entry is not None
        handle = await self.iserver.file_service.open_handle(group.entry, READ, session)
        self._arm(session.session_id, handle)
        return [_variant(handle, ua.VariantType.UInt32)]

    def _check_transaction(self, session: InternalSession) -> None:
        if self.transaction is not None and self.transaction.session_id != session.session_id:
            raise _status(_STATUS.BadTransactionPending)

    def _transaction_of(self, session: InternalSession) -> Transaction:
        self._check_transaction(session)
        if self.transaction is None:
            self.transaction = Transaction(session.session_id)
            self._transaction_session = session
            session.add_close_listener(self._session_closed)
        return self.transaction

    def _session_closed(self, session: InternalSession, reason: ua.StatusCode) -> None:
        if self.transaction is not None and self.transaction.session_id == session.session_id:
            _logger.info("The Session that held the certificate transaction ended; its changes are discarded")
            self.transaction = None
            self._transaction_session = None

    def _group(self, nodeid: ua.NodeId | None) -> Group:
        if nodeid is None or nodeid.is_null():
            for group in self.groups.values():
                if group.kind == "application":
                    return group
        group = self.groups.get(nodeid) if nodeid is not None else None
        if group is None:
            raise _status(_STATUS.BadInvalidArgument)
        return group

    def _certificate_group(self, nodeid: ua.NodeId | None, type_id: ua.NodeId | None) -> Group:
        group = self._group(nodeid)
        if group.kind != "application":
            raise _status(_STATUS.BadInvalidArgument)
        if type_id is not None and not type_id.is_null() and type_id != CERTIFICATE_TYPE:
            raise _status(_STATUS.BadInvalidArgument)
        return group

    async def close_and_update(self, group: Group, handle: ua.Variant) -> list[ua.Variant]:
        session = self._session()
        service = self.iserver.file_service
        assert group.entry is not None
        open_handle = service.lookup_handle(session, group.entry, handle.Value)
        self._disarm(session.session_id, handle.Value)
        service.release_handle(session.session_id, handle.Value)
        if not open_handle.mode & WRITE:
            raise _status(_STATUS.BadInvalidState)
        content = bytes(open_handle.provider.content) if isinstance(open_handle.provider, MemoryFile) else b""
        limit = self.max_trust_list_size
        if limit and len(content) > limit:
            raise _status(_STATUS.BadRequestTooLarge)
        new, masks = decode_trust_list(content)
        merged = merge_lists(group.store.read_lists(), new, masks)
        await anyio.to_thread.run_sync(
            check_trust_lists, merged, PeerRole.USER if group.kind == "user" else PeerRole.CLIENT
        )
        transaction = self._transaction_of(session)
        previous = transaction.trust_lists.get(group.node.nodeid)
        queued = merge_lists(previous[0], new, masks) if previous is not None else merged
        transaction.trust_lists[group.node.nodeid] = (queued, (previous[1] if previous else 0) | masks)
        return [_variant(True, ua.VariantType.Boolean)]

    async def add_certificate(self, group: Group, certificate: ua.Variant, is_trusted: ua.Variant) -> list[ua.Variant]:
        self._check_no_transaction()
        self._check_not_open_for_writing(group)
        if not is_trusted.Value:
            raise _status(_STATUS.BadCertificateInvalid)
        der = bytes(certificate.Value or b"")
        try:
            x509.load_der_x509_certificate(der)
        except ValueError as error:
            raise _status(_STATUS.BadCertificateInvalid) from error
        current = group.store.read_lists()
        if der in current.trusted_certificates:
            return []
        updated = TrustLists(
            (*current.trusted_certificates, der), current.trusted_crls, current.issuer_certificates, current.issuer_crls
        )
        self._check_size(updated)
        await anyio.to_thread.run_sync(
            check_trust_lists, updated, PeerRole.USER if group.kind == "user" else PeerRole.CLIENT
        )
        await self._write_store(group, lambda journal: group.store.write_certificate(der, True, journal))
        group.store.remove_rejected(der)
        await self._fire_trust_list_updated(group)
        return []

    async def remove_certificate(
        self, group: Group, thumbprint: ua.Variant, is_trusted: ua.Variant
    ) -> list[ua.Variant]:
        self._check_no_transaction()
        self._check_not_open_for_writing(group)
        wanted = str(thumbprint.Value or "").lower()
        current = group.store.read_lists()
        candidates = current.trusted_certificates if is_trusted.Value else current.issuer_certificates
        der = next((item for item in candidates if certificate_thumbprint(item).hex() == wanted), None)
        if der is None:
            raise _status(_STATUS.BadInvalidArgument)
        certificate = x509.load_der_x509_certificate(der)
        others = [
            x509.load_der_x509_certificate(item)
            for item in (*current.trusted_certificates, *current.issuer_certificates)
            if item != der
        ]
        if any(
            other.issuer == certificate.subject
            and other.subject != certificate.subject
            and _issued_by(other, certificate)
            for other in others
        ):
            raise _status(_STATUS.BadCertificateChainIncomplete)
        await self._write_store(
            group, lambda journal: group.store.remove_certificate_files(der, bool(is_trusted.Value), journal)
        )
        await self._fire_trust_list_updated(group)
        return []

    def _check_no_transaction(self) -> None:
        if self.transaction is not None:
            raise _status(_STATUS.BadTransactionPending)

    def _check_not_open_for_writing(self, group: Group) -> None:
        if group.entry is not None and group.entry.write_handles:
            raise _status(_STATUS.BadInvalidState)

    def _check_size(self, lists: TrustLists) -> None:
        if self.max_trust_list_size and len(encode_trust_list(lists, MASK_ALL)) > self.max_trust_list_size:
            raise _status(_STATUS.BadRequestTooLarge)

    async def _write_store(self, group: Group, operation: Callable[[FileJournal], None]) -> None:
        journal = FileJournal()
        try:
            await anyio.to_thread.run_sync(operation, journal)
        except Exception:
            journal.rollback()
            raise
        journal.commit()
        await group.store.load()
        group.last_update = datetime.now(UTC)
        await self._write(
            await group.trust_list.get_child("LastUpdateTime"), group.last_update, ua.VariantType.DateTime
        )
        await self._revalidate_peers()

    async def update_certificate(
        self,
        parent: ua.NodeId,
        group_id: ua.Variant,
        type_id: ua.Variant,
        certificate: ua.Variant,
        issuer_certificates: ua.Variant,
        private_key_format: ua.Variant,
        private_key: ua.Variant,
    ) -> list[ua.Variant]:
        session = self._session()
        self._check_transaction(session)
        group = self._certificate_group(group_id.Value, type_id.Value)
        chain_data = bytes(certificate.Value or b"")
        try:
            pieces = split_certificate_chain(chain_data)
            leaf = x509.load_der_x509_certificate(pieces[0])
            chain = [x509.load_der_x509_certificate(piece) for piece in pieces[1:]]
        except (ValueError, IndexError, ua.UaError) as error:
            raise _status(_STATUS.BadCertificateInvalid) from error
        await anyio.to_thread.run_sync(self._check_certificate, group, leaf, chain_data)
        key, uses_pending = await anyio.to_thread.run_sync(
            self._key_for, group, leaf, private_key_format.Value, bytes(private_key.Value or b"")
        )
        transaction = self._transaction_of(session)
        transaction.certificates[group.node.nodeid] = PendingCertificate(leaf, chain, key, uses_pending)
        return [_variant(True, ua.VariantType.Boolean)]

    def _check_certificate(self, group: Group, leaf: x509.Certificate, chain: bytes) -> None:
        application_uri = self.server.get_application_uri()
        validator = CertificateValidator(group.store, suppress=[suppression for suppression in Suppression])
        uri = validator.check_application_uri(leaf, application_uri)
        if not uri.accepted:
            raise _status(uri.status)
        policies = {endpoint.SecurityPolicyUri for endpoint in self.iserver.endpoints} - {
            security_policies.SecurityPolicyNone.URI
        }
        for policy_uri in sorted(policies) or [None]:
            outcome = validator.validate_application_certificate(chain, ValidationContext(PeerRole.SERVER, policy_uri))
            if outcome.accepted:
                continue
            if outcome.step is Step.TRUST and outcome.untrusted_chain and leaf.subject == leaf.issuer:
                continue
            raise _status(outcome.status)

    def _key_for(
        self, group: Group, leaf: x509.Certificate, key_format: str | None, key_data: bytes
    ) -> tuple[RSAPrivateKey, bool]:
        public = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

        def matches(key: RSAPrivateKey) -> bool:
            return (
                key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                == public
            )

        if key_data:
            key = self._parse_key(key_format, key_data)
            if not matches(key):
                raise _status(_STATUS.BadSecurityChecksFailed)
            return key, False
        assert self._root is not None
        pending = pki.load_pending_key(self._root, self._key_name(group))
        if pending is not None and matches(pending):
            return pending, True
        current = self.iserver.private_key
        if isinstance(current, RSAPrivateKey) and matches(current):
            return current, False
        raise _status(_STATUS.BadSecurityChecksFailed)

    @staticmethod
    def _key_name(group: Group) -> str:
        return f"{group.name}_RsaSha256"

    @staticmethod
    def _parse_key(key_format: str | None, data: bytes) -> RSAPrivateKey:
        try:
            if (key_format or "").upper() == "PEM":
                key = serialization.load_pem_private_key(data, None)
            elif (key_format or "").upper() in ("PFX", "PKCS12"):
                key = pkcs12.load_key_and_certificates(data, None)[0]
            else:
                raise _status(_STATUS.BadNotSupported)
        except ua.UaStatusCodeError:
            raise
        except (ValueError, TypeError) as error:
            raise _status(_STATUS.BadNotSupported) from error
        if not isinstance(key, RSAPrivateKey):
            raise _status(_STATUS.BadNotSupported)
        return key

    async def create_signing_request(
        self,
        parent: ua.NodeId,
        group_id: ua.Variant,
        type_id: ua.Variant,
        subject_name: ua.Variant,
        regenerate: ua.Variant,
        nonce: ua.Variant,
    ) -> list[ua.Variant]:
        session = self._session()
        self._check_transaction(session)
        group = self._certificate_group(group_id.Value, type_id.Value)
        current = self.iserver.certificate
        assert current is not None and self._root is not None
        try:
            subject = cert_gen.parse_subject_name(subject_name.Value) if subject_name.Value else current.subject
        except ValueError as error:
            raise _status(_STATUS.BadInvalidArgument) from error
        if regenerate.Value:
            if len(bytes(nonce.Value or b"")) < MIN_NONCE_LENGTH:
                raise _status(_STATUS.BadInvalidArgument)
            key = await anyio.to_thread.run_sync(cert_gen.generate_private_key)
            await anyio.to_thread.run_sync(pki.save_pending_key, self._root, self._key_name(group), key)
        else:
            key = self.iserver.private_key
        names, usage = self._request_fields(current)
        request = cert_gen.generate_signing_request(key, subject, names, usage)
        return [_variant(request.public_bytes(serialization.Encoding.DER), ua.VariantType.ByteString)]

    @staticmethod
    def _request_fields(current: x509.Certificate) -> tuple[list[x509.GeneralName], list[x509.ObjectIdentifier]]:
        names: list[x509.GeneralName] = []
        try:
            extension = current.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names.extend(
                x509.UniformResourceIdentifier(value)
                for value in extension.get_values_for_type(x509.UniformResourceIdentifier)
            )
            names.extend(x509.DNSName(value) for value in extension.get_values_for_type(x509.DNSName))
            names.extend(x509.IPAddress(value) for value in extension.get_values_for_type(x509.IPAddress))
        except x509.ExtensionNotFound:
            pass
        try:
            usage = list(current.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        except x509.ExtensionNotFound:
            usage = list(pki.SERVER_USAGE)
        return names, usage

    async def get_rejected_list(self, parent: ua.NodeId) -> list[ua.Variant]:
        store = self.application_store
        limit = max(self._response_limit() - ENCODING_OVERHEAD, 0)
        certificates: list[bytes] = []
        total = 0
        for der in await anyio.to_thread.run_sync(store.rejected_certificates):
            if total + len(der) > limit:
                break
            certificates.append(der)
            total += len(der)
        return [_variant(certificates, ua.VariantType.ByteString)]

    def _response_limit(self) -> int:
        return self.iserver.max_byte_string_length * 8

    async def get_certificates(self, parent: ua.NodeId, group_id: ua.Variant) -> list[ua.Variant]:
        group = self._group(group_id.Value)
        if group.kind != "application" or self.iserver.certificate is None:
            return [_variant([], ua.VariantType.NodeId), _variant([], ua.VariantType.ByteString)]
        chain = [self.iserver.certificate, *self.iserver.certificate_chain]
        der = b"".join(_der(certificate) for certificate in chain)
        return [_variant([CERTIFICATE_TYPE], ua.VariantType.NodeId), _variant([der], ua.VariantType.ByteString)]

    async def cancel_changes(self, parent: ua.NodeId) -> list[ua.Variant]:
        session = self._session()
        self._owned_transaction(session)
        self.transaction = None
        self._transaction_session = None
        return []

    def _owned_transaction(self, session: InternalSession) -> Transaction:
        if self.transaction is None:
            raise _status(_STATUS.BadNothingToDo)
        if self.transaction.session_id != session.session_id:
            raise _status(_STATUS.BadSessionIdInvalid)
        return self.transaction

    async def apply_changes(self, parent: ua.NodeId) -> list[ua.Variant]:
        session = self._session()
        transaction = self._owned_transaction(session)
        for group in self.groups.values():
            self._check_not_open_for_writing(group)
        async with self._lock:
            certificate_changed = await self._apply(transaction)
        self.transaction = None
        self._transaction_session = None
        asyncio.get_running_loop().call_later(
            self.close_delay, lambda: asyncio.ensure_future(self._after_apply(certificate_changed))
        )
        return []

    async def _apply(self, transaction: Transaction) -> bool:
        assert self._root is not None
        journal = FileJournal()
        root = self._root
        try:
            for group_id, (lists, masks) in transaction.trust_lists.items():
                group = self.groups[group_id]
                await anyio.to_thread.run_sync(
                    check_trust_lists, lists, PeerRole.USER if group.kind == "user" else PeerRole.CLIENT
                )
            previous = self.iserver.certificate

            def write() -> None:
                for group_id, (lists, masks) in transaction.trust_lists.items():
                    self.groups[group_id].store.write_lists(lists, masks, journal)
                for group_id, pending in transaction.certificates.items():
                    group = self.groups[group_id]
                    pki.write_own_credentials(root, pending.certificate, pending.chain, pending.key, previous, journal)
                    if pending.uses_pending_key:
                        pki.discard_pending_key(root, self._key_name(group), journal)

            await anyio.to_thread.run_sync(write)
        except Exception as error:
            journal.rollback()
            self.transaction = None
            self._transaction_session = None
            _logger.warning("ApplyChanges failed, nothing was changed: %s", error)
            if isinstance(error, ua.UaStatusCodeError):
                raise
            raise _status(_STATUS.BadInternalError) from error
        journal.commit()
        stores = {self.groups[group_id].store for group_id in transaction.trust_lists}
        for store in stores:
            await store.load()
        for group_id in transaction.trust_lists:
            group = self.groups[group_id]
            group.last_update = datetime.now(UTC)
            await self._write(
                await group.trust_list.get_child("LastUpdateTime"), group.last_update, ua.VariantType.DateTime
            )
        changed = bool(transaction.certificates)
        if changed:
            await self._install_credentials()
        for group_id in transaction.trust_lists:
            await self._fire_trust_list_updated(self.groups[group_id])
        for group_id in transaction.certificates:
            await self._fire_certificate_updated(self.groups[group_id])
        return changed

    async def _install_credentials(self) -> None:
        assert self._root is not None
        credentials = await pki.load_own_credentials(
            self._root,
            application_uri=self.server.get_application_uri(),
            host_names=[],
            usage=pki.SERVER_USAGE,
            create=False,
        )
        self.iserver.certificate = credentials.certificate
        self.iserver.certificate_chain = credentials.chain
        self.iserver.private_key = credentials.private_key
        await self.server._setup_server_nodes()
        if self.server.bserver is not None:
            self.server.bserver.set_policies(self.server._policies)

    async def _after_apply(self, certificate_changed: bool) -> None:
        bserver = self.server.bserver
        if bserver is None:
            return
        if certificate_changed:
            for protocol in list(bserver.clients):
                if protocol.transport is not None:
                    protocol.transport.close()
            return
        await self._revalidate_peers()

    async def _revalidate_peers(self) -> None:
        bserver = self.server.bserver
        validator = self.iserver.certificate_validator
        if bserver is None or validator is None:
            return
        for protocol in list(bserver.clients):
            processor = protocol.processor
            if processor is None or processor.security.certificate is None:
                continue
            security = processor.security
            if security.policy_uri == security_policies.SecurityPolicyNone.URI or security.certificate is None:
                continue
            outcome = validator.validate_application_certificate(
                bytes(security.certificate), ValidationContext(PeerRole.CLIENT, security.policy_uri)
            )
            if not outcome.accepted and outcome.status in (
                _STATUS.BadCertificateUntrusted,
                _STATUS.BadCertificateRevoked,
            ):
                _logger.info("Closing a channel whose client certificate is no longer trusted")
                if protocol.transport is not None:
                    protocol.transport.close()
            await asyncio.sleep(0)

    async def _fire_trust_list_updated(self, group: Group) -> None:
        event: Any = event_objects.TrustListUpdatedAuditEvent(
            sourcenode=group.trust_list.nodeid, message="Trust list updated"
        )
        event.TrustListId = group.trust_list.nodeid
        await self._fire(event)

    async def _fire_certificate_updated(self, group: Group) -> None:
        event: Any = event_objects.CertificateUpdatedAuditEvent(
            sourcenode=ua.NodeId(ua.ObjectIds.ServerConfiguration), message="Certificate updated"
        )
        event.CertificateGroup = group.node.nodeid
        event.CertificateType = CERTIFICATE_TYPE
        await self._fire(event)

    async def _fire(self, event: Any) -> None:
        session = current_call_session.get()
        event.ActionTimeStamp = datetime.now(UTC)
        event.Status = True
        event.ServerId = self.server.get_application_uri()
        event.ClientUserId = session.user.name if session is not None and session.user is not None else None
        generator = await self.server.get_event_generator(event, ua.ObjectIds.Server)
        await generator.trigger()


def _issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        certificate.verify_directly_issued_by(issuer)
    except Exception:
        return False
    return True

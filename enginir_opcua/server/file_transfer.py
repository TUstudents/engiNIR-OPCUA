"""
Server side of OPC UA File Transfer (OPC 10000-20): FileType Objects over a provider, FileDirectoryType Objects
over a directory below which every path is checked, and the handles of the Sessions that opened them.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import anyio

from enginir_opcua import ua
from enginir_opcua.common.node import Node
from enginir_opcua.crypto.permission_rules import ROLE_RANK, UserRole
from enginir_opcua.ua.uaerrors import ConfigurationError

from .internal_session import InternalSession, current_call_session

if TYPE_CHECKING:
    from .internal_server import InternalServer

_logger = logging.getLogger(__name__)

DEFAULT_MAX_BYTE_STRING_LENGTH = 1_048_576
DEFAULT_MAX_HANDLES_PER_SESSION = 16
DEFAULT_MAX_HANDLES_PER_FILE = 64
DEFAULT_MAX_ENTRIES = 10_000
MAX_NAME_BYTES = 255
READ = 1
WRITE = 2
ERASE_EXISTING = 4
APPEND = 8
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_FILE_METHODS = ("Open", "Close", "Read", "Write", "GetPosition", "SetPosition")
_DIRECTORY_METHODS = ("CreateDirectory", "CreateFile", "Delete", "MoveOrCopy")
_DELETE_TYPE_METHOD = "DeleteFileSystemObject"


def _status(code: int) -> ua.UaStatusCodeError:
    return ua.UaStatusCodeError(code)


class FileProvider(Protocol):
    """The storage behind one file. The service keeps the position of every handle; a provider is stateless."""

    def size(self) -> int | None: ...

    def modified(self) -> datetime | None: ...

    async def read(self, offset: int, length: int) -> bytes: ...

    async def write(self, offset: int, data: bytes) -> None: ...

    async def truncate(self) -> None: ...

    async def flush(self) -> None: ...


class MemoryFile:
    """A file held in memory."""

    def __init__(self, content: bytes | bytearray = b"") -> None:
        self.content = bytearray(content)
        self.last_changed: datetime | None = None

    def size(self) -> int | None:
        return len(self.content)

    def modified(self) -> datetime | None:
        return self.last_changed

    async def read(self, offset: int, length: int) -> bytes:
        return bytes(self.content[offset : offset + length])

    async def write(self, offset: int, data: bytes) -> None:
        self.content[offset : offset + len(data)] = data
        self.last_changed = datetime.now(UTC)

    async def truncate(self) -> None:
        self.content.clear()
        self.last_changed = datetime.now(UTC)

    async def flush(self) -> None:
        return None


class PathFile:
    """A regular file on disk, opened for every operation without following a symbolic link."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _open(self, flags: int) -> int:
        descriptor = os.open(self.path, flags | _NOFOLLOW | getattr(os, "O_BINARY", 0))
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("not a regular file")
        except OSError:
            os.close(descriptor)
            raise
        return descriptor

    def size(self) -> int | None:
        descriptor = self._open(os.O_RDONLY)
        try:
            return os.fstat(descriptor).st_size
        finally:
            os.close(descriptor)

    def modified(self) -> datetime | None:
        descriptor = self._open(os.O_RDONLY)
        try:
            return datetime.fromtimestamp(os.fstat(descriptor).st_mtime, UTC)
        finally:
            os.close(descriptor)

    async def read(self, offset: int, length: int) -> bytes:
        def run() -> bytes:
            descriptor = self._open(os.O_RDONLY)
            try:
                return os.pread(descriptor, length, offset)
            finally:
                os.close(descriptor)

        return await anyio.to_thread.run_sync(run)

    async def write(self, offset: int, data: bytes) -> None:
        def run() -> None:
            descriptor = self._open(os.O_WRONLY)
            try:
                view = memoryview(data)
                position = offset
                while view:
                    written = os.pwrite(descriptor, view, position)
                    view = view[written:]
                    position += written
            finally:
                os.close(descriptor)

        await anyio.to_thread.run_sync(run)

    async def truncate(self) -> None:
        def run() -> None:
            os.close(self._open(os.O_WRONLY | os.O_TRUNC))

        await anyio.to_thread.run_sync(run)

    async def flush(self) -> None:
        def run() -> None:
            descriptor = self._open(os.O_WRONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        await anyio.to_thread.run_sync(run)


@dataclass
class FileEntry:
    node: Node
    provider: FileProvider
    writable: bool = False
    max_size: int | None = None
    max_byte_string_length: int | None = None
    write_role: UserRole = UserRole.User
    tree: DirectoryTree | None = None
    rel: tuple[str, ...] = ()
    opener: Callable[[int, InternalSession], Awaitable[FileProvider]] | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    handles: set[tuple[ua.NodeId, int]] = field(default_factory=set)
    write_handles: set[tuple[ua.NodeId, int]] = field(default_factory=set)


@dataclass
class OpenHandle:
    entry: FileEntry
    mode: int
    provider: FileProvider
    position: int = 0


@dataclass
class SessionHandles:
    handles: dict[int, OpenHandle] = field(default_factory=dict)
    next_handle: int = 1


@dataclass
class DirectoryTree:
    root: Path
    node: Node
    namespace: int
    writable: bool
    max_file_size: int | None
    max_entries: int
    write_role: UserRole
    items: dict[ua.NodeId, tuple[str, tuple[str, ...]]] = field(default_factory=dict)
    by_rel: dict[tuple[str, ...], ua.NodeId] = field(default_factory=dict)

    def path_of(self, rel: tuple[str, ...]) -> Path:
        """The path below the root, refused when a component is a symbolic link or the result leaves the root."""
        current = self.root
        for part in rel:
            current = current / part
            try:
                if stat.S_ISLNK(os.lstat(current).st_mode):
                    raise _status(ua.StatusCodes.BadNotFound)
            except FileNotFoundError:
                continue
        resolved = Path(os.path.realpath(current))
        if not resolved.is_relative_to(self.root):
            raise _status(ua.StatusCodes.BadUserAccessDenied)
        return current


def validate_mode(mode: int) -> int:
    if mode < 0 or mode > 255 or mode & 0xF0:
        raise _status(ua.StatusCodes.BadInvalidArgument)
    if not mode & (READ | WRITE):
        raise _status(ua.StatusCodes.BadInvalidArgument)
    if mode & ERASE_EXISTING and not mode & WRITE:
        raise _status(ua.StatusCodes.BadInvalidArgument)
    return mode


def validate_name(name: Any) -> str:
    if not isinstance(name, str) or not name or name in (".", ".."):
        raise _status(ua.StatusCodes.BadInvalidArgument)
    if len(name.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES:
        raise _status(ua.StatusCodes.BadInvalidArgument)
    if any(ch in "/\\" or ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise _status(ua.StatusCodes.BadInvalidArgument)
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        raise _status(ua.StatusCodes.BadInvalidArgument)
    return name


def _regular_file(path: Path) -> Path | None:
    resolved = path.resolve()
    return resolved if resolved.is_file() else None


def _existing_directory(path: Path) -> Path | None:
    resolved = path.resolve()
    return resolved if resolved.is_dir() else None


def _variant(value: Any, variant_type: ua.VariantType) -> ua.Variant:
    return ua.Variant(value, variant_type)


class FileService:
    """All FileType and FileDirectoryType Objects of one server, and the handles of its Sessions."""

    def __init__(self, iserver: InternalServer) -> None:
        self.iserver = iserver
        self.max_open_handles_per_session = DEFAULT_MAX_HANDLES_PER_SESSION
        self.max_open_handles_per_file = DEFAULT_MAX_HANDLES_PER_FILE
        self.files: dict[ua.NodeId, FileEntry] = {}
        self.trees: dict[ua.NodeId, DirectoryTree] = {}
        self._sessions: dict[ua.NodeId, SessionHandles] = {}
        self._watched: set[ua.NodeId] = set()
        self._types_bound = False

    def default_max_byte_string_length(self) -> int:
        return int(getattr(self.iserver, "max_byte_string_length", DEFAULT_MAX_BYTE_STRING_LENGTH))

    def effective_max(self, entry: FileEntry) -> int:
        return entry.max_byte_string_length or self.default_max_byte_string_length()

    async def _bind_method(self, nodeid: ua.NodeId, callback: Callable[..., Any]) -> None:
        """Bind a callback and make the Method executable (SRV-83: the standard Methods are not)."""
        self.iserver.isession.add_method_callback(nodeid, callback)
        for attribute in (ua.AttributeIds.Executable, ua.AttributeIds.UserExecutable):
            await self.iserver.write_attribute_value(
                nodeid, ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)), attribute
            )

    async def _bind(self, node: Node, names: tuple[str, ...], callbacks: dict[str, Callable[..., Any]]) -> None:
        for name in names:
            await self._bind_method((await node.get_child(name)).nodeid, callbacks[name])

    async def bind_types(self) -> None:
        if self._types_bound:
            return
        self._types_bound = True
        file_callbacks = self.file_callbacks()
        for name in _FILE_METHODS:
            await self._bind_method(ua.NodeId(getattr(ua.ObjectIds, f"FileType_{name}")), file_callbacks[name])
        directory_callbacks = self._directory_callbacks()
        for name in _DIRECTORY_METHODS:
            type_name = _DELETE_TYPE_METHOD if name == "Delete" else name
            await self._bind_method(
                ua.NodeId(getattr(ua.ObjectIds, f"FileDirectoryType_{type_name}")), directory_callbacks[name]
            )

    def file_callbacks(self) -> dict[str, Callable[..., Any]]:
        return {
            "Open": self.open,
            "Close": self.close,
            "Read": self.read,
            "Write": self.write,
            "GetPosition": self.get_position,
            "SetPosition": self.set_position,
        }

    def _directory_callbacks(self) -> dict[str, Callable[..., Any]]:
        return {
            "CreateDirectory": self.create_directory,
            "CreateFile": self.create_file,
            "Delete": self.delete,
            "MoveOrCopy": self.move_or_copy,
        }

    async def add_file(
        self,
        parent: Node,
        name: str,
        provider: FileProvider | str | Path,
        *,
        writable: bool = False,
        max_size: int | None = None,
        mime_type: str | None = None,
        max_byte_string_length: int | None = None,
        write_role: UserRole = UserRole.User,
        namespace: int | None = None,
    ) -> Node:
        if isinstance(provider, str | Path):
            path = await anyio.to_thread.run_sync(_regular_file, Path(provider))
            if path is None:
                raise ConfigurationError(f"{provider} is not a regular file")
            provider = PathFile(path)
        idx = namespace if namespace is not None else (parent.nodeid.NamespaceIndex or 2)
        node = await parent.add_object(idx, name, objecttype=ua.NodeId(ua.ObjectIds.FileType))
        entry = FileEntry(node, provider, writable, max_size, max_byte_string_length, write_role)
        await self.register_file(entry, mime_type)
        return node

    async def register_file(self, entry: FileEntry, mime_type: str | None = None) -> None:
        await self.bind_types()
        node = entry.node
        await self._bind(node, _FILE_METHODS, self.file_callbacks())
        self.files[node.nodeid] = entry
        await self._set_value_callback(node, "Size", ua.VariantType.UInt64, lambda: self._size_of(entry))
        await self._set_value_callback(node, "OpenCount", ua.VariantType.UInt16, lambda: len(entry.handles))
        await self._set_value_callback(node, "UserWritable", ua.VariantType.Boolean, lambda: self._user_writable(entry))
        await (await node.get_child("Writable")).write_value(_variant(entry.writable, ua.VariantType.Boolean))
        await self._set_optional(node, "MimeType", mime_type, ua.VariantType.String)
        await self._set_optional(node, "MaxByteStringLength", self.effective_max(entry), ua.VariantType.UInt32)
        if await self._has_child(node, "LastModifiedTime"):
            await self._set_value_callback(
                node, "LastModifiedTime", ua.VariantType.DateTime, lambda: entry.provider.modified()
            )

    async def _has_child(self, node: Node, name: str) -> bool:
        try:
            await node.get_child(name)
        except ua.uaerrors.UaError:
            return False
        return True

    async def _set_optional(self, node: Node, name: str, value: Any, variant_type: ua.VariantType) -> None:
        if not await self._has_child(node, name):
            return
        child = await node.get_child(name)
        if value is None:
            await child.delete()
            return
        await child.write_value(_variant(value, variant_type))

    async def _set_value_callback(
        self, node: Node, name: str, variant_type: ua.VariantType, getter: Callable[[], Any]
    ) -> None:
        child = await node.get_child(name)

        def callback(nodeid: ua.NodeId, attribute: ua.AttributeIds) -> ua.DataValue:
            try:
                value = getter()
            except OSError:
                return ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadNotFound))
            if value is None:
                return ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadNotSupported))
            return ua.DataValue(ua.Variant(value, variant_type), SourceTimestamp=datetime.now(UTC))

        self.iserver.set_attribute_value_callback(child.nodeid, callback)

    @staticmethod
    def _size_of(entry: FileEntry) -> int | None:
        return entry.provider.size()

    @staticmethod
    def _role_allows(entry_role: UserRole, session: InternalSession | None) -> bool:
        if session is None:
            return True
        user = session.user
        return user is not None and user.role in ROLE_RANK and ROLE_RANK[user.role] >= ROLE_RANK[entry_role]

    def _user_writable(self, entry: FileEntry) -> bool:
        return entry.writable and self._role_allows(entry.write_role, current_call_session.get())

    def _caller(self) -> InternalSession:
        session = current_call_session.get()
        if session is None:
            raise _status(ua.StatusCodes.BadInternalError)
        return session

    def _file(self, nodeid: ua.NodeId) -> FileEntry:
        entry = self.files.get(nodeid)
        if entry is None:
            raise _status(ua.StatusCodes.BadNodeIdUnknown)
        return entry

    def _handle(self, session: InternalSession, entry: FileEntry, handle: Any) -> OpenHandle:
        open_handle = self._sessions.get(session.session_id, SessionHandles()).handles.get(handle)
        if open_handle is None or open_handle.entry is not entry:
            raise _status(ua.StatusCodes.BadInvalidArgument)
        return open_handle

    async def open_handle(self, entry: FileEntry, mode: int, session: InternalSession) -> int:
        mode = validate_mode(mode)
        if mode & WRITE:
            if not entry.writable or not self._role_allows(entry.write_role, session):
                raise _status(ua.StatusCodes.BadNotWritable)
            if entry.handles:
                raise _status(ua.StatusCodes.BadNotWritable)
        elif entry.write_handles:
            raise _status(ua.StatusCodes.BadNotReadable)
        sessions = self._sessions.setdefault(session.session_id, SessionHandles())
        if (
            len(sessions.handles) >= self.max_open_handles_per_session
            or len(entry.handles) >= self.max_open_handles_per_file
        ):
            raise _status(ua.StatusCodes.BadResourceUnavailable)
        handle = sessions.next_handle
        sessions.next_handle += 1
        key = (session.session_id, handle)
        entry.handles.add(key)
        if mode & WRITE:
            entry.write_handles.add(key)
        sessions.handles[handle] = OpenHandle(entry, mode, entry.provider)
        self._watch(session)
        try:
            provider = await entry.opener(mode, session) if entry.opener is not None else entry.provider
            sessions.handles[handle].provider = provider
            if mode & ERASE_EXISTING:
                await provider.truncate()
            if mode & APPEND:
                sessions.handles[handle].position = provider.size() or 0
        except Exception as error:
            self._release(session.session_id, handle)
            raise self._as_status(error) from error
        return handle

    @staticmethod
    def _as_status(error: Exception) -> Exception:
        if isinstance(error, ua.UaStatusCodeError):
            return error
        if isinstance(error, FileNotFoundError):
            return _status(ua.StatusCodes.BadNotFound)
        _logger.warning("File operation failed: %s", error)
        return _status(ua.StatusCodes.BadUnexpectedError)

    def _watch(self, session: InternalSession) -> None:
        if session.session_id in self._watched:
            return
        self._watched.add(session.session_id)
        session.add_close_listener(self._session_closed)

    async def _session_closed(self, session: InternalSession, reason: ua.StatusCode) -> None:
        self._watched.discard(session.session_id)
        sessions = self._sessions.get(session.session_id)
        if sessions is None:
            return
        for handle in list(sessions.handles):
            open_handle = sessions.handles[handle]
            await self._flush_quietly(open_handle)
            self._release(session.session_id, handle)
        self._sessions.pop(session.session_id, None)

    @staticmethod
    async def _flush_quietly(open_handle: OpenHandle) -> None:
        if open_handle.mode & WRITE:
            try:
                await open_handle.provider.flush()
            except Exception as error:
                _logger.warning("Flushing a file at the end of a Session failed: %s", error)

    def _release(self, session_id: ua.NodeId, handle: int) -> OpenHandle | None:
        sessions = self._sessions.get(session_id)
        open_handle = sessions.handles.pop(handle, None) if sessions is not None else None
        if open_handle is not None:
            open_handle.entry.handles.discard((session_id, handle))
            open_handle.entry.write_handles.discard((session_id, handle))
        return open_handle

    def take_handle(self, session: InternalSession, entry: FileEntry, handle: int) -> OpenHandle:
        """Remove a handle without flushing it; used by Methods that end a handle themselves (CloseAndUpdate)."""
        open_handle = self._handle(session, entry, handle)
        self._release(session.session_id, handle)
        return open_handle

    def release_file(self, entry: FileEntry) -> None:
        for session_id, handle in list(entry.handles):
            self._release(session_id, handle)

    async def open(self, parent: ua.NodeId, mode: ua.Variant) -> list[ua.Variant]:
        entry = self._file(parent)
        handle = await self.open_handle(entry, int(mode.Value), self._caller())
        return [_variant(handle, ua.VariantType.UInt32)]

    async def close(self, parent: ua.NodeId, handle: ua.Variant) -> list[ua.Variant]:
        entry, session = self._file(parent), self._caller()
        open_handle = self._handle(session, entry, handle.Value)
        self._release(session.session_id, handle.Value)
        if open_handle.mode & WRITE:
            try:
                await open_handle.provider.flush()
            except Exception as error:
                raise self._as_status(error) from error
        return []

    async def read(self, parent: ua.NodeId, handle: ua.Variant, length: ua.Variant) -> list[ua.Variant]:
        entry, session = self._file(parent), self._caller()
        open_handle = self._handle(session, entry, handle.Value)
        if length.Value is None or length.Value <= 0:
            raise _status(ua.StatusCodes.BadInvalidArgument)
        if not open_handle.mode & READ:
            raise _status(ua.StatusCodes.BadInvalidState)
        count = min(int(length.Value), self.effective_max(entry))
        try:
            async with entry.lock:
                data = await open_handle.provider.read(open_handle.position, count)
        except Exception as error:
            raise self._as_status(error) from error
        open_handle.position += len(data)
        return [_variant(data, ua.VariantType.ByteString)]

    async def write(self, parent: ua.NodeId, handle: ua.Variant, data: ua.Variant) -> list[ua.Variant]:
        entry, session = self._file(parent), self._caller()
        open_handle = self._handle(session, entry, handle.Value)
        if not open_handle.mode & WRITE:
            raise _status(ua.StatusCodes.BadInvalidState)
        payload = bytes(data.Value or b"")
        if not payload:
            return []
        if not entry.writable:
            raise _status(ua.StatusCodes.BadNotWritable)
        if len(payload) > self.effective_max(entry):
            raise _status(ua.StatusCodes.BadEncodingLimitsExceeded)
        if entry.max_size is not None and open_handle.position + len(payload) > entry.max_size:
            raise _status(ua.StatusCodes.BadOutOfRange)
        try:
            async with entry.lock:
                await open_handle.provider.write(open_handle.position, payload)
        except Exception as error:
            raise self._as_status(error) from error
        open_handle.position += len(payload)
        return []

    async def get_position(self, parent: ua.NodeId, handle: ua.Variant) -> list[ua.Variant]:
        open_handle = self._handle(self._caller(), self._file(parent), handle.Value)
        return [_variant(open_handle.position, ua.VariantType.UInt64)]

    async def set_position(self, parent: ua.NodeId, handle: ua.Variant, position: ua.Variant) -> list[ua.Variant]:
        open_handle = self._handle(self._caller(), self._file(parent), handle.Value)
        size = open_handle.provider.size()
        target = int(position.Value)
        open_handle.position = target if size is None else min(target, size)
        return []

    async def add_directory(
        self,
        parent: Node,
        name: str,
        root: str | Path,
        *,
        writable: bool = False,
        max_file_size: int | None = None,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        write_role: UserRole = UserRole.User,
        namespace: int | None = None,
    ) -> Node:
        resolved = await anyio.to_thread.run_sync(_existing_directory, Path(root))
        if resolved is None:
            raise ConfigurationError(f"{root} is not an existing directory")
        await self.bind_types()
        idx = namespace if namespace is not None else (parent.nodeid.NamespaceIndex or 2)
        node = await parent.add_object(idx, name, objecttype=ua.NodeId(ua.ObjectIds.FileDirectoryType))
        tree = DirectoryTree(resolved, node, idx, writable, max_file_size, max_entries, write_role)
        tree.items[node.nodeid] = ("dir", ())
        tree.by_rel[()] = node.nodeid
        self.trees[node.nodeid] = tree
        await self._bind(node, _DIRECTORY_METHODS, self._directory_callbacks())
        await self._reconcile(tree, ())
        return node

    def _tree_of(self, nodeid: ua.NodeId) -> tuple[DirectoryTree, tuple[str, ...]]:
        for tree in self.trees.values():
            item = tree.items.get(nodeid)
            if item is not None and item[0] == "dir":
                return tree, item[1]
        raise _status(ua.StatusCodes.BadNodeIdUnknown)

    def _check_write(self, tree: DirectoryTree, session: InternalSession) -> None:
        if not tree.writable or not self._role_allows(tree.write_role, session):
            raise _status(ua.StatusCodes.BadUserAccessDenied)

    async def _node_for(self, tree: DirectoryTree, parent_rel: tuple[str, ...], name: str, kind: str) -> ua.NodeId:
        parent_node = Node(self.iserver.isession, tree.by_rel[parent_rel])
        type_id = ua.ObjectIds.FileDirectoryType if kind == "dir" else ua.ObjectIds.FileType
        node = await parent_node.add_object(tree.namespace, name, objecttype=ua.NodeId(type_id))
        await parent_node.delete_reference(node, ua.ObjectIds.HasComponent, bidirectional=True)
        await parent_node.add_reference(node, ua.ObjectIds.Organizes, bidirectional=True)
        rel = (*parent_rel, name)
        tree.items[node.nodeid] = (kind, rel)
        tree.by_rel[rel] = node.nodeid
        if kind == "dir":
            self.trees[node.nodeid] = tree
            await self._bind(node, _DIRECTORY_METHODS, self._directory_callbacks())
        else:
            provider = PathFileInTree(tree, rel)
            entry = FileEntry(
                node, provider, tree.writable, tree.max_file_size, None, tree.write_role, tree=tree, rel=rel
            )
            await self.register_file(entry)
        return node.nodeid

    async def _forget(self, tree: DirectoryTree, nodeid: ua.NodeId) -> None:
        _kind, rel = tree.items.pop(nodeid)
        tree.by_rel.pop(rel, None)
        self.trees.pop(nodeid, None)
        entry = self.files.pop(nodeid, None)
        if entry is not None:
            self.release_file(entry)

    async def _reconcile(self, tree: DirectoryTree, rel: tuple[str, ...]) -> None:
        path = tree.path_of(rel)

        def scan() -> dict[str, str]:
            found: dict[str, str] = {}
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        found[entry.name] = "dir"
                    elif entry.is_file(follow_symlinks=False):
                        found[entry.name] = "file"
            return found

        try:
            found = await anyio.to_thread.run_sync(scan)
        except OSError:
            found = {}
        known = {
            item_rel[-1]: (nodeid, kind)
            for nodeid, (kind, item_rel) in list(tree.items.items())
            if len(item_rel) == len(rel) + 1 and item_rel[: len(rel)] == rel
        }
        for name, (nodeid, kind) in known.items():
            if found.get(name) != kind:
                await self._delete_subtree(tree, nodeid)
        for name, kind in sorted(found.items()):
            if len(tree.items) >= tree.max_entries:
                _logger.warning(
                    "The directory service of %s holds %s entries; the rest is left out", tree.root, tree.max_entries
                )
                break
            if name not in known or known[name][1] != found[name]:
                try:
                    validate_name(name)
                except ua.UaStatusCodeError:
                    continue
                await self._node_for(tree, rel, name, kind)
        for name, kind in found.items():
            if kind == "dir" and (*rel, name) in tree.by_rel:
                await self._reconcile(tree, (*rel, name))

    async def refresh_directory(self, node: Node) -> None:
        tree, rel = self._tree_of(node.nodeid)
        await self._reconcile(tree, rel)

    async def _delete_subtree(self, tree: DirectoryTree, nodeid: ua.NodeId) -> None:
        _, rel = tree.items[nodeid]
        doomed = [
            (item_nodeid, item_rel) for item_nodeid, (_, item_rel) in tree.items.items() if item_rel[: len(rel)] == rel
        ]
        for item_nodeid, _ in doomed:
            await self._forget(tree, item_nodeid)
        try:
            await Node(self.iserver.isession, nodeid).delete(recursive=True)
        except ua.uaerrors.UaError as error:
            _logger.warning("Removing the node of a file system object failed: %s", error)

    def _locked_below(self, tree: DirectoryTree, rel: tuple[str, ...], write_only: bool = False) -> bool:
        for nodeid, (kind, item_rel) in tree.items.items():
            if kind == "file" and item_rel[: len(rel)] == rel:
                entry = self.files.get(nodeid)
                if entry is not None and (entry.write_handles if write_only else entry.handles):
                    return True
        return False

    async def create_directory(self, parent: ua.NodeId, directory_name: ua.Variant) -> list[ua.Variant]:
        tree, rel = self._tree_of(parent)
        session = self._caller()
        self._check_write(tree, session)
        name = validate_name(directory_name.Value)
        if len(tree.items) >= tree.max_entries:
            raise _status(ua.StatusCodes.BadResourceUnavailable)
        path = tree.path_of((*rel, name))
        mode = 0o700

        def make() -> None:
            os.mkdir(path, mode)

        try:
            await anyio.to_thread.run_sync(make)
        except FileExistsError:
            raise _status(ua.StatusCodes.BadBrowseNameDuplicated) from None
        except OSError as error:
            raise self._as_status(error) from error
        try:
            nodeid = await self._node_for(tree, rel, name, "dir")
        except Exception:
            await anyio.to_thread.run_sync(path.rmdir)
            raise
        return [_variant(nodeid, ua.VariantType.NodeId)]

    async def create_file(
        self, parent: ua.NodeId, file_name: ua.Variant, request_file_open: ua.Variant
    ) -> list[ua.Variant]:
        tree, rel = self._tree_of(parent)
        session = self._caller()
        self._check_write(tree, session)
        name = validate_name(file_name.Value)
        if len(tree.items) >= tree.max_entries:
            raise _status(ua.StatusCodes.BadResourceUnavailable)
        path = tree.path_of((*rel, name))

        def make() -> None:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _NOFOLLOW, 0o600))

        try:
            await anyio.to_thread.run_sync(make)
        except FileExistsError:
            raise _status(ua.StatusCodes.BadBrowseNameDuplicated) from None
        except OSError as error:
            raise self._as_status(error) from error
        nodeid = ua.NodeId()
        try:
            nodeid = await self._node_for(tree, rel, name, "file")
            handle = 0
            if request_file_open.Value:
                handle = await self.open_handle(self.files[nodeid], READ | WRITE, session)
        except Exception:
            if nodeid in tree.items:
                await self._delete_subtree(tree, nodeid)
            await anyio.to_thread.run_sync(lambda: path.unlink(missing_ok=True))
            raise
        return [_variant(nodeid, ua.VariantType.NodeId), _variant(handle, ua.VariantType.UInt32)]

    def _target_below(
        self, tree: DirectoryTree, directory: tuple[str, ...], nodeid: ua.NodeId
    ) -> tuple[str, tuple[str, ...]]:
        item = tree.items.get(nodeid)
        if item is None or len(item[1]) <= len(directory) or item[1][: len(directory)] != directory:
            raise _status(ua.StatusCodes.BadNotFound)
        return item

    async def delete(self, parent: ua.NodeId, object_to_delete: ua.Variant) -> list[ua.Variant]:
        tree, rel = self._tree_of(parent)
        self._check_write(tree, self._caller())
        nodeid = object_to_delete.Value
        if tree.items.get(nodeid, ("", None))[1] == rel:
            raise _status(ua.StatusCodes.BadUserAccessDenied)
        kind, target_rel = self._target_below(tree, rel, nodeid)
        if self._locked_below(tree, target_rel):
            raise _status(ua.StatusCodes.BadInvalidState)
        path = tree.path_of(target_rel)

        def remove() -> None:
            if kind == "dir":
                shutil.rmtree(path)
            else:
                path.unlink()

        try:
            await anyio.to_thread.run_sync(remove)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise self._as_status(error) from error
        await self._delete_subtree(tree, nodeid)
        return []

    async def move_or_copy(
        self,
        parent: ua.NodeId,
        object_to_move_or_copy: ua.Variant,
        target_directory: ua.Variant,
        create_copy: ua.Variant,
        new_name: ua.Variant,
    ) -> list[ua.Variant]:
        tree, rel = self._tree_of(parent)
        self._check_write(tree, self._caller())
        nodeid = object_to_move_or_copy.Value
        kind, source_rel = self._target_below(tree, rel, nodeid)
        target = tree.items.get(target_directory.Value)
        if target is None or target[0] != "dir":
            raise _status(ua.StatusCodes.BadNotFound)
        name = validate_name(new_name.Value) if new_name.Value else source_rel[-1]
        destination_rel = (*target[1], name)
        if kind == "dir" and destination_rel[: len(source_rel)] == source_rel:
            raise _status(ua.StatusCodes.BadInvalidArgument)
        copy = bool(create_copy.Value)
        if self._locked_below(tree, source_rel, write_only=copy):
            raise _status(ua.StatusCodes.BadInvalidState)
        source = tree.path_of(source_rel)
        destination = tree.path_of(destination_rel)
        if destination_rel == source_rel and not copy:
            return [_variant(nodeid, ua.VariantType.NodeId)]

        def transfer() -> None:
            if os.path.lexists(destination):
                raise FileExistsError
            if copy:
                if kind == "dir":
                    shutil.copytree(source, destination, symlinks=True)
                else:
                    shutil.copy2(source, destination, follow_symlinks=False)
            else:
                os.rename(source, destination)

        try:
            await anyio.to_thread.run_sync(transfer)
        except FileExistsError:
            raise _status(ua.StatusCodes.BadBrowseNameDuplicated) from None
        except Exception as error:
            await anyio.to_thread.run_sync(lambda: self._discard(destination, copy))
            raise self._as_status(error) from error
        if copy:
            await self._reconcile(tree, target[1])
            return [_variant(tree.by_rel[destination_rel], ua.VariantType.NodeId)]
        await self._rename_nodes(tree, nodeid, source_rel, destination_rel)
        return [_variant(nodeid, ua.VariantType.NodeId)]

    @staticmethod
    def _discard(destination: Path, copy: bool) -> None:
        if copy and os.path.lexists(destination):
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination, ignore_errors=True)
            else:
                destination.unlink(missing_ok=True)

    async def _rename_nodes(
        self, tree: DirectoryTree, nodeid: ua.NodeId, source_rel: tuple[str, ...], destination_rel: tuple[str, ...]
    ) -> None:
        for item_nodeid, (kind, item_rel) in list(tree.items.items()):
            if item_rel[: len(source_rel)] == source_rel:
                new_rel = (*destination_rel, *item_rel[len(source_rel) :])
                tree.by_rel.pop(item_rel, None)
                tree.items[item_nodeid] = (kind, new_rel)
                tree.by_rel[new_rel] = item_nodeid
                entry = self.files.get(item_nodeid)
                if entry is not None:
                    entry.rel = new_rel
        node = Node(self.iserver.isession, nodeid)
        name = destination_rel[-1]
        await node.write_attribute(
            ua.AttributeIds.BrowseName, ua.DataValue(ua.Variant(ua.QualifiedName(name, tree.namespace)))
        )
        await node.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(name))))
        old_parent = tree.by_rel.get(source_rel[:-1])
        new_parent = tree.by_rel.get(destination_rel[:-1])
        if old_parent is not None and new_parent is not None and old_parent != new_parent:
            await Node(self.iserver.isession, old_parent).delete_reference(
                nodeid, ua.ObjectIds.Organizes, bidirectional=True
            )
            await Node(self.iserver.isession, new_parent).add_reference(
                nodeid, ua.ObjectIds.Organizes, bidirectional=True
            )


class PathFileInTree(PathFile):
    """A file of a directory tree: its path is looked up, checked against the root, at every operation."""

    def __init__(self, tree: DirectoryTree, rel: tuple[str, ...]) -> None:
        super().__init__(tree.root.joinpath(*rel))
        self.tree = tree
        self.rel = rel

    def _open(self, flags: int) -> int:
        item = self.tree.by_rel.get(self.rel)
        if item is None:
            raise FileNotFoundError(self.path)
        self.path = self.tree.path_of(self.rel)
        return super()._open(flags)

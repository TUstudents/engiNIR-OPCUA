"""The server side of FileType and FileDirectoryType (OPC 10000-20): handles, limits, roles and directories."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_file_transfer import UaDirectory, UaFile
from enginir_opcua.common.node import Node
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.server.file_transfer import MemoryFile
from tests.conftest import PermissiveUserManager, find_free_port
from tests.waiting import wait_until

READ, WRITE, ERASE, APPEND = 1, 2, 4, 8


@dataclass
class Rig:
    server: Server
    port: int
    admin: Client
    user: Client
    root: Path

    def url(self, user: str) -> str:
        return f"opc.tcp://{user}@127.0.0.1:{self.port}"

    def node(self, client: Client, node: Node) -> Node:
        return client.get_node(node.nodeid)


@pytest.fixture(scope="module")
async def rig(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Rig]:
    port = find_free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await server.start()
    admin = Client(f"opc.tcp://admin@127.0.0.1:{port}")
    user = Client(f"opc.tcp://someone@127.0.0.1:{port}")
    await admin.connect()
    await user.connect()
    yield Rig(server, port, admin, user, tmp_path_factory.mktemp("files"))
    await user.disconnect()
    await admin.disconnect()
    await server.stop()


_counter = iter(range(10_000))


async def make_file(rig: Rig, content: bytes = b"hello world", **options: Any) -> tuple[Node, MemoryFile]:
    provider = MemoryFile(content)
    node = await rig.server.add_file(rig.server.nodes.objects, f"File{next(_counter)}", provider, **options)
    return node, provider


async def call(client: Client, file_node: Node, method: str, *args: ua.Variant) -> Any:
    target = client.get_node(file_node.nodeid)
    return await target.call_method(ua.QualifiedName(method, 0), *args)


def byte(value: int) -> ua.Variant:
    return ua.Variant(value, ua.VariantType.Byte)


def handle(value: int) -> ua.Variant:
    return ua.Variant(value, ua.VariantType.UInt32)


async def open_file(client: Client, node: Node, mode: int) -> int:
    return int(await call(client, node, "Open", byte(mode)))


async def status_of(awaitable: Any) -> int:
    with pytest.raises(ua.UaStatusCodeError) as caught:
        await awaitable
    return caught.value.code


async def test_open_read_and_close_a_memory_file(rig: Rig) -> None:
    node, _ = await make_file(rig, b"0123456789")
    async with UaFile(rig.admin.get_node(node.nodeid)) as file:
        assert await file.read() == b"0123456789"
        assert await file.get_size() == 10
        assert await file.get_open_count() == 1
    assert await UaFile(rig.admin.get_node(node.nodeid)).get_open_count() == 0


@pytest.mark.parametrize(
    "mode", [0, 4, 16, 3 + 32, 256], ids=["zero", "erase_alone", "reserved_4", "reserved_5", "wide"]
)
async def test_open_rejects_invalid_modes(rig: Rig, mode: int) -> None:
    node, _ = await make_file(rig, writable=True)
    target = rig.admin.get_node(node.nodeid)
    code = await status_of(target.call_method(ua.QualifiedName("Open", 0), ua.Variant(mode % 256, ua.VariantType.Byte)))
    assert code == ua.StatusCodes.BadInvalidArgument


async def test_handle_is_unknown_in_another_session_and_after_close(rig: Rig) -> None:
    node, _ = await make_file(rig)
    first = await open_file(rig.admin, node, READ)
    assert await status_of(call(rig.user, node, "Close", handle(first))) == ua.StatusCodes.BadInvalidArgument
    await call(rig.admin, node, "Close", handle(first))
    assert await status_of(call(rig.admin, node, "Close", handle(first))) == ua.StatusCodes.BadInvalidArgument


async def test_one_writer_excludes_everyone_and_readers_exclude_writers(rig: Rig) -> None:
    node, _ = await make_file(rig, writable=True)
    writer = await open_file(rig.admin, node, WRITE)
    assert await status_of(open_file(rig.admin, node, WRITE)) == ua.StatusCodes.BadNotWritable
    assert await status_of(open_file(rig.user, node, READ)) == ua.StatusCodes.BadNotReadable
    await call(rig.admin, node, "Close", handle(writer))
    first, second = await open_file(rig.admin, node, READ), await open_file(rig.user, node, READ)
    assert await status_of(open_file(rig.admin, node, WRITE)) == ua.StatusCodes.BadNotWritable
    assert first != second
    await call(rig.admin, node, "Close", handle(first))
    await call(rig.user, node, "Close", handle(second))


async def test_handle_limits_per_session_and_per_file(rig: Rig) -> None:
    node, _ = await make_file(rig)
    service = rig.server.iserver.file_service
    old = service.max_open_handles_per_session, service.max_open_handles_per_file
    service.max_open_handles_per_session, service.max_open_handles_per_file = 2, 3
    try:
        first, second = await open_file(rig.admin, node, READ), await open_file(rig.admin, node, READ)
        assert await status_of(open_file(rig.admin, node, READ)) == ua.StatusCodes.BadResourceUnavailable
        third = await open_file(rig.user, node, READ)
        assert await status_of(open_file(rig.user, node, READ)) == ua.StatusCodes.BadResourceUnavailable
        for client, value in ((rig.admin, first), (rig.admin, second), (rig.user, third)):
            await call(client, node, "Close", handle(value))
    finally:
        service.max_open_handles_per_session, service.max_open_handles_per_file = old


async def test_read_is_capped_and_ends_with_an_empty_bytestring(rig: Rig) -> None:
    node, _ = await make_file(rig, bytes(range(100)), max_byte_string_length=40)
    opened = await open_file(rig.admin, node, READ)
    length = ua.Variant(1000, ua.VariantType.Int32)
    first = await call(rig.admin, node, "Read", handle(opened), length)
    assert first == bytes(range(40))
    await call(rig.admin, node, "Read", handle(opened), length)
    last = await call(rig.admin, node, "Read", handle(opened), length)
    assert last == bytes(range(80, 100))
    assert await call(rig.admin, node, "Read", handle(opened), length) in (b"", None)
    assert await status_of(call(rig.admin, node, "Read", handle(opened), ua.Variant(0, ua.VariantType.Int32))) == (
        ua.StatusCodes.BadInvalidArgument
    )
    await call(rig.admin, node, "Close", handle(opened))


async def test_read_without_the_read_bit_and_write_without_the_write_bit_are_invalid_state(rig: Rig) -> None:
    node, _ = await make_file(rig, writable=True)
    writer = await open_file(rig.admin, node, WRITE)
    code = await status_of(call(rig.admin, node, "Read", handle(writer), ua.Variant(10, ua.VariantType.Int32)))
    assert code == ua.StatusCodes.BadInvalidState
    await call(rig.admin, node, "Close", handle(writer))
    reader = await open_file(rig.admin, node, READ)
    data = ua.Variant(b"x", ua.VariantType.ByteString)
    assert await status_of(call(rig.admin, node, "Write", handle(reader), data)) == ua.StatusCodes.BadInvalidState
    await call(rig.admin, node, "Close", handle(reader))


async def test_set_position_above_the_end_goes_to_the_end(rig: Rig) -> None:
    node, _ = await make_file(rig, b"abc")
    opened = await open_file(rig.admin, node, READ)
    await call(rig.admin, node, "SetPosition", handle(opened), ua.Variant(2**40, ua.VariantType.UInt64))
    assert await call(rig.admin, node, "GetPosition", handle(opened)) == 3
    await call(rig.admin, node, "Close", handle(opened))


async def test_write_empty_over_the_limit_and_over_max_size(rig: Rig) -> None:
    node, provider = await make_file(rig, b"", writable=True, max_size=10, max_byte_string_length=8)
    opened = await open_file(rig.admin, node, WRITE)
    await call(rig.admin, node, "Write", handle(opened), ua.Variant(b"", ua.VariantType.ByteString))
    big = ua.Variant(b"123456789", ua.VariantType.ByteString)
    assert await status_of(call(rig.admin, node, "Write", handle(opened), big)) == (
        ua.StatusCodes.BadEncodingLimitsExceeded
    )
    await call(rig.admin, node, "Write", handle(opened), ua.Variant(b"12345678", ua.VariantType.ByteString))
    over = ua.Variant(b"abc", ua.VariantType.ByteString)
    assert await status_of(call(rig.admin, node, "Write", handle(opened), over)) == ua.StatusCodes.BadOutOfRange
    await call(rig.admin, node, "Close", handle(opened))
    assert bytes(provider.content) == b"12345678"


async def test_erase_existing_and_append(rig: Rig) -> None:
    node, provider = await make_file(rig, b"old content", writable=True)
    async with UaFile(rig.admin.get_node(node.nodeid), WRITE | APPEND) as file:
        await file.write(b"!")
    assert bytes(provider.content) == b"old content!"
    async with UaFile(rig.admin.get_node(node.nodeid), WRITE | ERASE) as file:
        await file.write(b"new")
    assert bytes(provider.content) == b"new"


async def test_user_without_the_role_cannot_open_for_writing_and_user_writable_follows(rig: Rig) -> None:
    node, _ = await make_file(rig, writable=True, write_role=UserRole.Admin)
    assert await status_of(open_file(rig.user, node, WRITE)) == ua.StatusCodes.BadNotWritable
    admin_handle = await open_file(rig.admin, node, WRITE)
    await call(rig.admin, node, "Close", handle(admin_handle))
    user_node, admin_node = rig.user.get_node(node.nodeid), rig.admin.get_node(node.nodeid)
    assert await (await user_node.get_child("Writable")).read_value() is True
    assert await (await user_node.get_child("UserWritable")).read_value() is False
    assert await (await admin_node.get_child("UserWritable")).read_value() is True


async def test_srv82_handles_are_released_when_the_session_closes(rig: Rig) -> None:
    node, _ = await make_file(rig, writable=True)
    other = Client(rig.url("someone"))
    await other.connect()
    await open_file(other, node, WRITE)
    assert await UaFile(rig.admin.get_node(node.nodeid)).get_open_count() == 1
    await other.disconnect()
    await wait_until(lambda: not rig.server.iserver.file_service.files[node.nodeid].handles)
    assert await open_file(rig.admin, node, WRITE) > 0


async def test_methods_work_with_the_type_method_id_and_are_executable(rig: Rig) -> None:
    node, _ = await make_file(rig, b"abc")
    target = rig.admin.get_node(node.nodeid)
    opened = await target.call_method(ua.NodeId(ua.ObjectIds.FileType_Open), byte(READ))
    assert await target.call_method(ua.NodeId(ua.ObjectIds.FileType_GetPosition), handle(opened)) == 0
    await target.call_method(ua.NodeId(ua.ObjectIds.FileType_Close), handle(opened))
    method = await target.get_child("Open")
    assert await method.read_attribute(ua.AttributeIds.Executable) == ua.DataValue(
        ua.Variant(True, ua.VariantType.Boolean)
    )


async def test_file_properties_have_their_types(rig: Rig) -> None:
    node, _ = await make_file(rig, b"abc", mime_type="text/plain")
    file = UaFile(rig.admin.get_node(node.nodeid))
    assert await file.get_mime_type() == "text/plain"
    assert await file.get_writable() is False
    max_length = await (await rig.admin.get_node(node.nodeid).get_child("MaxByteStringLength")).read_value()
    assert max_length == rig.server.iserver.max_byte_string_length


async def test_file_object_that_was_not_registered_is_not_supported(rig: Rig) -> None:
    folder = await rig.server.nodes.objects.add_object(2, f"Plain{next(_counter)}", objecttype=ua.ObjectIds.FileType)
    code = await status_of(call(rig.admin, folder, "Open", byte(READ)))
    assert code == ua.StatusCodes.BadNotSupported


async def new_directory(rig: Rig, writable: bool = True, **options: Any) -> tuple[Node, Path]:
    path = rig.root / f"dir{next(_counter)}"
    path.mkdir()
    node = await rig.server.add_directory(rig.server.nodes.objects, "FileSystem", path, writable=writable, **options)
    return node, path


async def children(rig: Rig, node: Node) -> dict[str, ua.NodeId]:
    result: dict[str, ua.NodeId] = {}
    for child in await rig.admin.get_node(node.nodeid).get_children(ua.ObjectIds.Organizes):
        result[str((await child.read_browse_name()).Name)] = child.nodeid
    return result


async def test_directory_create_file_delete_move_copy(rig: Rig) -> None:
    node, path = await new_directory(rig)
    directory = UaDirectory(rig.admin.get_node(node.nodeid))
    sub = await directory.create_directory("sub")
    file_id, opened = await directory.create_file("a.txt", True)
    assert opened > 0
    assert (path / "a.txt").is_file() and (path / "sub").is_dir()
    await call(rig.admin, Node(rig.server.iserver.isession, file_id), "Close", handle(opened))
    async with UaFile(rig.admin.get_node(file_id), WRITE) as file:
        await file.write(b"content")
    copied = await directory.move_or_copy(file_id, sub, True, "b.txt")
    assert (path / "sub" / "b.txt").read_bytes() == b"content"
    moved = await directory.move_or_copy(file_id, sub, False, "")
    assert not (path / "a.txt").exists() and (path / "sub" / "a.txt").read_bytes() == b"content"
    assert moved == file_id
    assert copied != moved
    assert set(await children(rig, Node(rig.server.iserver.isession, sub))) == {"a.txt", "b.txt"}
    await directory.delete(sub)
    assert not (path / "sub").exists()
    assert set(await children(rig, node)) == set()


async def test_directory_duplicate_names_and_read_only_directories(rig: Rig) -> None:
    node, _ = await new_directory(rig)
    directory = UaDirectory(rig.admin.get_node(node.nodeid))
    await directory.create_file("x")
    with pytest.raises(ua.uaerrors.BadBrowseNameDuplicated):
        await directory.create_file("x")
    with pytest.raises(ua.uaerrors.BadBrowseNameDuplicated):
        await directory.create_directory("x")
    read_only, _ = await new_directory(rig, writable=False)
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await UaDirectory(rig.admin.get_node(read_only.nodeid)).create_file("y")
    restricted, _ = await new_directory(rig, write_role=UserRole.Admin)
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await UaDirectory(rig.user.get_node(restricted.nodeid)).create_directory("z")


async def test_delete_is_refused_while_a_handle_is_open_and_the_root_cannot_be_deleted(rig: Rig) -> None:
    node, path = await new_directory(rig)
    directory = UaDirectory(rig.admin.get_node(node.nodeid))
    file_id, _ = await directory.create_file("busy.txt")
    opened = await UaFile(rig.admin.get_node(file_id), READ).open()
    with pytest.raises(ua.uaerrors.BadInvalidState):
        await directory.delete(file_id)
    await call(rig.admin, Node(rig.server.iserver.isession, file_id), "Close", handle(opened))
    await directory.delete(file_id)
    assert not (path / "busy.txt").exists()
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await directory.delete(node.nodeid)


async def test_move_into_the_own_subtree_is_invalid_and_copy_of_a_directory_is_recursive(rig: Rig) -> None:
    node, path = await new_directory(rig)
    directory = UaDirectory(rig.admin.get_node(node.nodeid))
    outer = await directory.create_directory("outer")
    inner = await UaDirectory(rig.admin.get_node(outer)).create_directory("inner")
    with pytest.raises(ua.uaerrors.BadInvalidArgument):
        await directory.move_or_copy(outer, inner, False, "")
    (path / "outer" / "inner" / "f.bin").write_bytes(b"data")
    await rig.server.refresh_directory(node)
    copy = await directory.move_or_copy(outer, node.nodeid, True, "copy")
    assert (path / "copy" / "inner" / "f.bin").read_bytes() == b"data"
    assert copy in (await children(rig, node)).values()


async def test_reconcile_shows_files_added_by_another_process(rig: Rig) -> None:
    node, path = await new_directory(rig)
    (path / "late.txt").write_text("hi")
    assert "late.txt" not in await children(rig, node)
    await rig.server.refresh_directory(node)
    names = await children(rig, node)
    assert "late.txt" in names
    async with UaFile(rig.admin.get_node(names["late.txt"])) as file:
        assert await file.read() == b"hi"
    (path / "late.txt").unlink()
    await rig.server.refresh_directory(node)
    assert "late.txt" not in await children(rig, node)


async def test_failed_create_file_with_open_leaves_nothing(rig: Rig) -> None:
    node, path = await new_directory(rig)
    service = rig.server.iserver.file_service
    old = service.max_open_handles_per_session
    service.max_open_handles_per_session = 0
    try:
        with pytest.raises(ua.uaerrors.BadResourceUnavailable):
            await UaDirectory(rig.admin.get_node(node.nodeid)).create_file("never", True)
    finally:
        service.max_open_handles_per_session = old
    assert not (path / "never").exists()
    assert "never" not in await children(rig, node)

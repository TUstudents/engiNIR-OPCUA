"""A path or name sent by a client cannot reach a file outside the directory the application exposed."""

from __future__ import annotations

import asyncio
import os
import stat
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_file_transfer import FileTransferError, UaDirectory, UaFile
from enginir_opcua.common.node import Node
from enginir_opcua.server.file_transfer import MemoryFile
from tests.conftest import PermissiveUserManager, find_free_port

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX symbolic links and modes")


@dataclass
class Rig:
    server: Server
    client: Client
    base: Path
    count: int = 0

    async def directory(self) -> tuple[Node, UaDirectory, Path, Path]:
        self.count += 1
        outside = self.base / f"outside{self.count}"
        root = self.base / f"root{self.count}"
        outside.mkdir()
        root.mkdir()
        node = await self.server.add_directory(self.server.nodes.objects, "FileSystem", root, writable=True)
        return node, UaDirectory(self.client.get_node(node.nodeid)), root, outside


@pytest.fixture(scope="module")
async def rig(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Rig]:
    port = find_free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await server.start()
    client = Client(f"opc.tcp://admin@127.0.0.1:{port}")
    await client.connect()
    yield Rig(server, client, tmp_path_factory.mktemp("sandbox"))
    await client.disconnect()
    await server.stop()


BAD_NAMES = [
    pytest.param("", id="empty"),
    pytest.param(".", id="dot"),
    pytest.param("..", id="dotdot"),
    pytest.param("a/b", id="slash"),
    pytest.param("..\\x", id="backslash"),
    pytest.param("../escape", id="parent_slash"),
    pytest.param("/etc/passwd", id="absolute"),
    pytest.param("C:evil", id="drive"),
    pytest.param("a\x00b", id="nul"),
    pytest.param("a\nb", id="control"),
    pytest.param("x" * 256, id="too_long"),
]


@pytest.mark.parametrize("name", BAD_NAMES)
async def test_names_with_dots_separators_or_control_characters_are_refused(rig: Rig, name: str) -> None:
    _, directory, root, outside = await rig.directory()
    with pytest.raises(ua.UaStatusCodeError) as refused:
        await directory.create_directory(name)
    assert refused.value.code == ua.StatusCodes.BadInvalidArgument
    with pytest.raises(ua.UaStatusCodeError):
        await directory.create_file(name)
    assert list(root.iterdir()) == []
    assert list(outside.iterdir()) == []


async def test_root_must_be_an_existing_directory_and_a_file_a_regular_file(rig: Rig, tmp_path: Path) -> None:
    with pytest.raises(Exception, match="not an existing directory"):
        await rig.server.add_directory(rig.server.nodes.objects, "FileSystem", tmp_path / "missing")
    with pytest.raises(Exception, match="not a regular file"):
        await rig.server.add_file(rig.server.nodes.objects, "NoFile", tmp_path)


@posix_only
async def test_symlink_below_the_root_is_not_shown_or_followed(rig: Rig) -> None:
    node, _directory, root, outside = await rig.directory()
    (outside / "secret.txt").write_text("secret")
    (root / "link_dir").symlink_to(outside, target_is_directory=True)
    (root / "link_file").symlink_to(outside / "secret.txt")
    await rig.server.refresh_directory(node)
    names = {
        (await child.read_browse_name()).Name
        for child in await rig.client.get_node(node.nodeid).get_children(ua.ObjectIds.Organizes)
    }
    assert names == set()


@posix_only
async def test_symlink_swapped_in_after_registration_is_refused(rig: Rig) -> None:
    _node, directory, root, outside = await rig.directory()
    sub = await directory.create_directory("sub")
    file_id, _ = await directory.create_file("data.txt")
    (outside / "secret.txt").write_text("secret")
    (root / "data.txt").unlink()
    (root / "data.txt").symlink_to(outside / "secret.txt")
    file = UaFile(rig.client.get_node(file_id))
    await file.open()
    with pytest.raises(FileTransferError) as refused:
        await file.read()
    assert isinstance(refused.value.__cause__, ua.uaerrors.BadNotFound)
    await file.close()
    (root / "sub").rmdir()
    (root / "sub").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ua.uaerrors.BadNotFound):
        await UaDirectory(rig.client.get_node(sub)).create_file("planted")
    assert list(outside.iterdir()) == [outside / "secret.txt"]


async def test_no_method_takes_a_path_and_a_foreign_nodeid_is_not_found(rig: Rig) -> None:
    node, directory, root, outside = await rig.directory()
    other = await rig.server.add_file(rig.server.nodes.objects, "Other", MemoryFile(b"x"))
    for victim in (ua.NodeId("../outside", 2), other.nodeid, ua.NodeId(1, 0)):
        with pytest.raises(ua.UaStatusCodeError) as refused:
            await directory.delete(victim)
        assert refused.value.code == ua.StatusCodes.BadNotFound
        with pytest.raises(ua.UaStatusCodeError) as refused:
            await directory.move_or_copy(victim, node.nodeid, False, "stolen")
        assert refused.value.code == ua.StatusCodes.BadNotFound
    assert root.exists() and outside.exists()


async def test_two_clients_racing_for_one_name_get_one_duplicate(rig: Rig) -> None:
    _, directory, root, _ = await rig.directory()
    results = await asyncio.gather(
        directory.create_file("race"),
        directory.create_file("race"),
        directory.create_file("race"),
        return_exceptions=True,
    )
    duplicates = [r for r in results if isinstance(r, ua.uaerrors.BadBrowseNameDuplicated)]
    assert len(duplicates) == 2
    assert [p.name for p in root.iterdir()] == ["race"]


@posix_only
async def test_created_files_and_directories_are_private(rig: Rig) -> None:
    _, directory, root, _ = await rig.directory()
    await directory.create_file("private.txt")
    await directory.create_directory("private_dir")
    assert stat.S_IMODE(os.stat(root / "private.txt").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(root / "private_dir").st_mode) == 0o700


@posix_only
async def test_delete_and_copy_do_not_follow_links_inside_the_tree(rig: Rig) -> None:
    node, directory, root, outside = await rig.directory()
    (outside / "keep.txt").write_text("keep")
    sub = await directory.create_directory("sub")
    (root / "sub" / "link").symlink_to(outside, target_is_directory=True)
    copy = await directory.move_or_copy(sub, node.nodeid, True, "copy")
    assert (root / "copy" / "link").is_symlink()
    await directory.delete(sub)
    await directory.delete(copy)
    assert (outside / "keep.txt").read_text() == "keep"

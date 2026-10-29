"""Client side of the FileType and FileDirectoryType model."""

from __future__ import annotations

import asyncio
import contextlib
import warnings
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_file_transfer import (
    FileTransferError,
    InvalidStateError,
    UaDirectory,
    UaFile,
)
from enginir_opcua.ua import OpenFileMode
from tests.conftest import PermissiveUserManager, find_free_port
from tests.file_rig import DirectoryRig, FileRig

pytestmark = pytest.mark.slow("enginir_opcua/client/ua_file_transfer.py", "enginir_opcua/client/ua_file.py")


@dataclass
class Rig:
    server: Server
    client: Client
    file: FileRig
    directory: DirectoryRig
    file_node: Any
    directory_node: Any


@contextlib.asynccontextmanager
async def build_rig() -> AsyncIterator[Rig]:
    port = find_free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    file_rig = FileRig(server, bytes(range(256)) * 41)
    directory_rig = DirectoryRig(server)
    file_node = await file_rig.attach()
    directory_node = await directory_rig.attach()
    await server.start()
    client = Client(f"opc.tcp://admin@127.0.0.1:{port}")
    await client.connect()
    yield Rig(
        server,
        client,
        file_rig,
        directory_rig,
        client.get_node(file_node.nodeid),
        client.get_node(directory_node.nodeid),
    )
    await client.disconnect()
    await server.stop()


@pytest.fixture(scope="module")
async def shared_rig() -> AsyncIterator[Rig]:
    async with build_rig() as built:
        yield built


@pytest.fixture
async def fresh_rig() -> AsyncIterator[Rig]:
    async with build_rig() as built:
        yield built


@pytest.fixture
async def rig(shared_rig: Rig) -> Rig:
    await shared_rig.file.reset()
    shared_rig.directory.reset()
    return shared_rig


async def test_cli12_read_loops_until_an_empty_bytestring(rig: Rig) -> None:
    """OPC 10000-5 C.2.3: a Read may return fewer bytes than asked; only an empty ByteString ends the file."""
    rig.file.read_cap = 1000
    expected = bytes(rig.file.content)
    assert len(expected) == 10496
    async with UaFile(rig.file_node) as remote:
        assert await remote.read() == expected
    assert len(rig.file.calls_of("Read")) == 12


async def test_cli12_empty_file_reads_as_empty_bytes(rig: Rig) -> None:
    """OPC 10000-5 C.2.3: an empty file is read with one call that comes back empty, never with a length of 0."""
    rig.file.content.clear()
    await rig.file.publish_size()
    async with UaFile(rig.file_node) as remote:
        assert await remote.read() == b""
    assert len(rig.file.calls_of("Read")) == 1
    assert rig.file.calls_of("Read")[0][1].Value > 0


async def test_cli12_size_above_2_gib_is_not_encoded_as_int32(rig: Rig) -> None:
    """OPC 10000-5 C.2: Size is a UInt64 and doesn't set the Read length."""
    await rig.file.publish_size(3_000_000_000)
    async with UaFile(rig.file_node) as remote:
        assert await remote.read() == bytes(rig.file.content)
        assert await remote.get_size() == 3_000_000_000


async def test_cli12_read_starts_at_the_current_position(rig: Rig) -> None:
    """OPC 10000-5 C.2.3: Read starts where the handle is."""
    async with UaFile(rig.file_node) as remote:
        await remote.set_position(10_000)
        assert await remote.read() == bytes(rig.file.content[10_000:])
        assert await remote.get_position() == len(rig.file.content)


async def test_read_failure_carries_partial_data(rig: Rig) -> None:
    """A failed Read reports what was read so far."""
    rig.file.read_cap = 1000
    rig.file.fail_read_after = 3
    async with UaFile(rig.file_node) as remote:
        with pytest.raises(FileTransferError) as raised:
            await remote.read()
    assert raised.value.partial_data == bytes(rig.file.content[:3000])
    assert isinstance(raised.value.__cause__, ua.UaStatusCodeError)


async def test_read_max_bytes_stops_a_large_file(rig: Rig) -> None:
    """A guard against a server that sends more than the caller wants to hold."""
    rig.file.read_cap = 1000
    async with UaFile(rig.file_node) as remote:
        with pytest.raises(ValueError):
            await remote.read(max_bytes=2500)
    assert len(rig.file.calls_of("Read")) <= 3


async def test_iter_chunks_streams_the_file(rig: Rig) -> None:
    rig.file.read_cap = 4000
    async with UaFile(rig.file_node, chunk_size=5000) as remote:
        chunks = [chunk async for chunk in remote.iter_chunks()]
    assert b"".join(chunks) == bytes(rig.file.content)
    assert max(len(c) for c in chunks) == 4000


@pytest.mark.parametrize("mode", [0, 4, 6 | 16, 256, 1 | 128, -1])
async def test_cli45_invalid_modes_are_value_errors(rig: Rig, mode: int) -> None:
    """OPC 10000-5 C.2.1: a mode needs Read or Write, EraseExisting only with Write, no reserved bits."""
    with pytest.raises(ValueError):
        UaFile(rig.file_node, mode)
    assert rig.file.calls == []


@pytest.mark.parametrize("mode", [1, 2, 3, 6, 10, 11, OpenFileMode.Write | OpenFileMode.EraseExisting])
async def test_cli45_valid_modes_are_accepted(rig: Rig, mode: int) -> None:
    UaFile(rig.file_node, mode)


async def test_cli42_open_on_an_open_file_raises_and_sends_nothing(rig: Rig) -> None:
    """OPC 10000-5 C.2.1: a second Open would leak the first handle, so it's refused locally."""
    remote = UaFile(rig.file_node)
    handle = await remote.open()
    with pytest.raises(InvalidStateError):
        await remote.open()
    assert len(rig.file.calls_of("Open")) == 1
    assert remote.handle == handle
    await remote.close()


async def test_cli42_close_twice_sends_one_call(rig: Rig) -> None:
    """OPC 10000-5 C.2.2: the handle is gone after Close, so the second close does nothing."""
    remote = UaFile(rig.file_node)
    await remote.open()
    await remote.close()
    await remote.close()
    assert len(rig.file.calls_of("Close")) == 1
    assert not remote.is_open


async def test_cli42_close_after_failed_open_sends_nothing(rig: Rig) -> None:
    """A close without a handle must not send a null handle."""
    rig.file.refuse_open_with = ua.StatusCodes.BadNotWritable
    remote = UaFile(rig.file_node, OpenFileMode.Write)
    with pytest.raises(ua.uaerrors.BadNotWritable):
        await remote.open()
    await remote.close()
    assert rig.file.calls_of("Close") == []


async def test_operation_on_a_closed_file_is_an_invalid_state(rig: Rig) -> None:
    remote = UaFile(rig.file_node)
    with pytest.raises(InvalidStateError):
        await remote.read()
    with pytest.raises(InvalidStateError):
        await remote.write(b"x")


async def test_async_with_closes_when_the_body_raises(rig: Rig) -> None:
    with pytest.raises(RuntimeError, match="body"):
        async with UaFile(rig.file_node):
            raise RuntimeError("body")
    assert len(rig.file.calls_of("Close")) == 1
    assert rig.file.handles == {}


async def test_cli43_write_is_chunked(rig: Rig) -> None:
    """OPC 10000-5 C.2.4: a Write carries at most what the server accepts, so larger data is split."""
    rig.file.write_cap = 4096
    data = bytes(range(256)) * 50
    async with UaFile(rig.file_node, OpenFileMode.Write | OpenFileMode.EraseExisting, chunk_size=4096) as remote:
        await remote.write(data)
    assert bytes(rig.file.content) == data
    assert len(rig.file.calls_of("Write")) == 4


async def test_write_empty_data_sends_no_call(rig: Rig) -> None:
    async with UaFile(rig.file_node, OpenFileMode.Write) as remote:
        await remote.write(b"")
    assert rig.file.calls_of("Write") == []


async def test_write_failure_reports_bytes_written(rig: Rig) -> None:
    rig.file.write_cap = 100
    async with UaFile(rig.file_node, OpenFileMode.Write, chunk_size=100) as remote:
        await remote.write(b"a" * 100)
        rig.file.write_cap = 10
        with pytest.raises(FileTransferError) as raised:
            await remote.write(b"b" * 250)
    assert raised.value.bytes_written == 0


async def test_chunk_size_follows_max_byte_string_length(fresh_rig: Rig) -> None:
    """OPC 10000-5, 6.3.2: the default chunk size is at most the server's MaxByteStringLength."""
    limit = fresh_rig.client.get_node(ua.NodeId(ua.ObjectIds.Server_ServerCapabilities_MaxByteStringLength))
    limit_on_server = fresh_rig.server.get_node(limit.nodeid)
    await limit_on_server.write_value(ua.Variant(2048, ua.VariantType.UInt32))
    fresh_rig.file.write_cap = 2048
    async with UaFile(fresh_rig.file_node, OpenFileMode.Write | OpenFileMode.EraseExisting) as remote:
        await remote.write(b"z" * 5000)
        assert remote.chunk_size == 2048
    assert len(fresh_rig.file.calls_of("Write")) == 3


async def test_chunk_size_default_without_the_property(rig: Rig) -> None:
    async with UaFile(rig.file_node) as remote:
        await remote.read()
    assert remote.chunk_size == 65536


async def test_cli44_methods_are_resolved_once(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every operation used to browse for its Method again."""
    lookups: list[str] = []
    original = rig.file_node.get_child

    async def counting(path: Any) -> Any:
        lookups.append(str(path))
        return await original(path)

    monkeypatch.setattr(rig.file_node, "get_child", counting)
    rig.file.read_cap = 1000
    async with UaFile(rig.file_node) as remote:
        await remote.read()
        await remote.get_position()
    assert sorted(lookups) == ["Close", "GetPosition", "Open", "Read"]


async def test_cli44_fallback_to_type_method_ids(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.12.2: the Method of the ObjectType may be called instead of the instance's own."""
    other = FileRig(rig.server, b"hello world")
    node = await other.attach("TypeOnlyFile", link_type=True)
    remote_node = rig.client.get_node(node.nodeid)

    async def missing(path: Any) -> Any:
        raise ua.UaError("no such child")

    monkeypatch.setattr(remote_node, "get_child", missing)
    async with UaFile(remote_node) as remote:
        assert await remote.read() == b"hello world"


async def test_cli44_missing_method_names_it(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    other = FileRig(rig.server, b"x")
    node = await other.attach("NoMethods")
    remote_node = rig.client.get_node(node.nodeid)

    async def missing(path: Any) -> Any:
        raise ua.UaError("no such child")

    monkeypatch.setattr(remote_node, "get_child", missing)
    monkeypatch.setattr("enginir_opcua.client.ua_file_transfer.METHOD_FALLBACKS", {})
    with pytest.raises(ua.UaError, match="Open"):
        await UaFile(remote_node).open()


async def test_argument_types_on_the_wire(rig: Rig) -> None:
    """OPC 10000-5 C.2: the Methods take Byte, UInt32, Int32, ByteString and UInt64 arguments."""
    async with UaFile(rig.file_node, OpenFileMode.Read | OpenFileMode.Write) as remote:
        await remote.set_position(3)
        await remote.read_chunk(10)
        await remote.write(b"abc")
        await remote.get_position()
    types = {name: [v.VariantType for v in args] for name, args in rig.file.calls}
    assert types["Open"] == [ua.VariantType.Byte]
    assert types["Read"] == [ua.VariantType.UInt32, ua.VariantType.Int32]
    assert types["Write"] == [ua.VariantType.UInt32, ua.VariantType.ByteString]
    assert types["SetPosition"] == [ua.VariantType.UInt32, ua.VariantType.UInt64]
    assert types["GetPosition"] == [ua.VariantType.UInt32]
    assert types["Close"] == [ua.VariantType.UInt32]


async def test_set_position_beyond_end_goes_to_end(rig: Rig) -> None:
    async with UaFile(rig.file_node) as remote:
        await remote.set_position(10**9)
        assert await remote.get_position() == len(rig.file.content)
        with pytest.raises(ValueError):
            await remote.set_position(2**64)
        with pytest.raises(ValueError):
            await remote.set_position(-1)


async def test_concurrent_reads_on_one_file_are_serialised(rig: Rig) -> None:
    """The position belongs to the handle, so two reads on one UaFile can't interleave."""
    rig.file.read_cap = 1000
    async with UaFile(rig.file_node) as remote:
        first, second = await asyncio.gather(remote.read(), remote.read())
    assert sorted([len(first), len(second)]) == [0, len(rig.file.content)]


async def test_file_call_timeout_is_per_call(rig: Rig) -> None:
    rig.file.read_delay = 0.5
    async with UaFile(rig.file_node, timeout=0.1) as remote:
        with pytest.raises(TimeoutError):
            await remote.read_chunk(10)


async def test_file_properties_have_the_right_types(rig: Rig) -> None:
    async with UaFile(rig.file_node) as remote:
        assert isinstance(await remote.get_size(), int)
        assert isinstance(await remote.get_writable(), bool)
        assert isinstance(await remote.get_user_writable(), bool)
        assert isinstance(await remote.get_open_count(), int)
        assert await remote.get_mime_type() is None


async def test_directory_create_delete_move_copy(rig: Rig) -> None:
    """OPC 10000-5 C.3: the four FileDirectoryType Methods."""
    directory = UaDirectory(rig.directory_node)
    folder = await directory.create_directory("data")
    assert isinstance(folder, ua.NodeId)
    node_id, handle = await directory.create_file("a.txt", False)
    assert isinstance(node_id, ua.NodeId)
    assert handle == 0
    copy = await directory.move_or_copy(node_id, folder, True, "b.txt")
    assert copy in rig.directory.names.values()
    await directory.delete(node_id)
    with pytest.raises(ua.uaerrors.BadNotFound):
        await directory.delete(node_id)
    assert len(rig.directory.calls) == 5


async def test_directory_duplicate_name_is_browse_name_duplicated(rig: Rig) -> None:
    directory = UaDirectory(rig.directory_node)
    await directory.create_directory("same")
    with pytest.raises(ua.uaerrors.BadBrowseNameDuplicated):
        await directory.create_directory("same")


async def test_create_file_with_open_request_adopt_and_close(rig: Rig) -> None:
    """The handle of a file created open is adopted by a UaFile so it can be closed."""
    directory = UaDirectory(rig.directory_node)
    _node_id, handle = await directory.create_file("opened.txt", True)
    assert handle == 7
    remote = UaFile(rig.client.get_node(rig.file_node.nodeid))
    remote.adopt(handle)
    assert remote.is_open
    assert remote.handle == 7
    with pytest.raises(InvalidStateError):
        remote.adopt(8)
    remote._file_handle = None


async def test_cli13_ua_file_warns_and_delegates(rig: Rig) -> None:
    """The old module is a deprecated wrapper over ua_file_transfer."""
    from enginir_opcua.client.ua_file import UaFile as OldUaFile

    rig.file.read_cap = 1000
    with pytest.warns(DeprecationWarning):
        old = OldUaFile(rig.file_node, "r")
    async with old:
        assert await old.read() == bytes(rig.file.content)
        assert await old.get_size() == len(rig.file.content)


async def test_cli13_manual_open_then_close_uses_the_handle(rig: Rig) -> None:
    from enginir_opcua.client.ua_file import UaFile as OldUaFile

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old = OldUaFile(rig.file_node, "r")
    handle = await old.open(1)
    await old.close()
    closes = rig.file.calls_of("Close")
    assert len(closes) == 1
    assert closes[0][0].Value == handle


async def test_cli13_old_string_modes(rig: Rig) -> None:
    from enginir_opcua.client.ua_file import UaFile as OldUaFile

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(ValueError):
            OldUaFile(rig.file_node, "x")
        async with OldUaFile(rig.file_node, "w") as writer:
            await writer.write(b"x")
    assert rig.file.calls_of("Open")[0][0].Value == 2


async def test_cli60_handle_is_tied_to_the_session_generation(rig: Rig) -> None:
    """Part 4, 5.7.4: the handles of a Session end with it; a new Session invalidates them."""
    remote = UaFile(rig.file_node)
    await remote.open()
    rig.client.uaclient.session.session_generation += 1
    with pytest.raises(ConnectionError):
        await remote.read_chunk(10)


async def test_cli33_method_calls_use_the_per_call_timeout(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """The timeout of a file operation is the timeout of the call, not a wrapper around it."""
    keywords: list[dict[str, Any]] = []
    original = rig.file_node.call_method

    async def recording(method: Any, *args: Any, **kwargs: Any) -> Any:
        keywords.append(kwargs)
        return await original(method, *args, **kwargs)

    monkeypatch.setattr(rig.file_node, "call_method", recording)
    async with UaFile(rig.file_node, timeout=7) as remote:
        await remote.read()
    assert keywords and all(k == {"timeout": 7} for k in keywords)


async def test_chunk_size_is_clamped_to_the_transport_limits(fresh_rig: Rig) -> None:
    """OPC 10000-5, C.2: a chunk plus overhead has to fit the message sizes the channel agreed on."""
    limits = fresh_rig.client.uaclient.protocol._channel.limits  # type: ignore[union-attr]
    limits.send_max_message_size = 5000
    async with UaFile(fresh_rig.file_node, OpenFileMode.Write, chunk_size=60000) as remote:
        assert await remote._resolve_chunk_size() <= 5000 - 1024
    async with UaFile(fresh_rig.file_node, OpenFileMode.Read) as remote:
        assert await remote._resolve_chunk_size() <= 5000 - 1024

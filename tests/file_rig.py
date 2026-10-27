"""A small FileType and FileDirectoryType server used by the file transfer tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from enginir_opcua import Server, ua
from enginir_opcua.common.node import Node


async def make_executable(method_node: Node) -> None:
    for attribute in (ua.AttributeIds.Executable, ua.AttributeIds.UserExecutable):
        await method_node.write_attribute(attribute, ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)))


class FileRig:
    def __init__(self, server: Server, content: bytes = b"") -> None:
        self.server = server
        self.content = bytearray(content)
        self.read_cap: int | None = None
        self.write_cap: int | None = None
        self.fail_read_after: int | None = None
        self.read_delay = 0.0
        self.refuse_open_with: int | None = None
        self.calls: list[tuple[str, list[ua.Variant]]] = []
        self.handles: dict[int, dict[str, Any]] = {}
        self.next_handle = 1
        self.reads = 0
        self.node: Node | None = None

    async def attach(self, name: str = "RigFile", link_type: bool = False) -> Node:
        node = await self.server.nodes.objects.add_object(2, name, objecttype=ua.ObjectIds.FileType)
        self.node = node
        callbacks: dict[str, Callable[..., Any]] = {
            "Open": self.open,
            "Close": self.close,
            "Read": self.read,
            "Write": self.write,
            "GetPosition": self.get_position,
            "SetPosition": self.set_position,
        }
        for method_name, callback in callbacks.items():
            method_node = await node.get_child(method_name)
            self.server.link_method(method_node, self._recorded(method_name, callback))
            await make_executable(method_node)
            if link_type:
                type_node = self.server.get_node(ua.NodeId(getattr(ua.ObjectIds, f"FileType_{method_name}")))
                self.server.link_method(type_node, self._recorded(method_name, callback))
                await make_executable(type_node)
        await self.publish_size()
        await (await node.get_child("Writable")).write_value(ua.Variant(True, ua.VariantType.Boolean))
        await (await node.get_child("UserWritable")).write_value(ua.Variant(True, ua.VariantType.Boolean))
        await (await node.get_child("OpenCount")).write_value(ua.Variant(0, ua.VariantType.UInt16))
        return node

    def _recorded(self, name: str, callback: Callable[..., Any]) -> Callable[..., Any]:
        async def wrapper(parent: ua.NodeId, *args: ua.Variant) -> Any:
            self.calls.append((name, list(args)))
            result = callback(*args)
            if asyncio.iscoroutine(result):
                result = await result
            return result

        return wrapper

    def calls_of(self, name: str) -> list[list[ua.Variant]]:
        return [args for method, args in self.calls if method == name]

    async def publish_size(self, size: int | None = None) -> None:
        assert self.node is not None
        value = len(self.content) if size is None else size
        await (await self.node.get_child("Size")).write_value(ua.Variant(value, ua.VariantType.UInt64))

    def open(self, mode: ua.Variant) -> list[ua.Variant]:
        if self.refuse_open_with is not None:
            raise ua.UaStatusCodeError(self.refuse_open_with)
        handle = self.next_handle
        self.next_handle += 1
        if mode.Value & 4:
            self.content.clear()
        position = len(self.content) if mode.Value & 8 else 0
        self.handles[handle] = {"mode": mode.Value, "position": position}
        return [ua.Variant(handle, ua.VariantType.UInt32)]

    def _handle(self, variant: ua.Variant) -> dict[str, Any]:
        state = self.handles.get(variant.Value)
        if state is None:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)
        return state

    def close(self, handle: ua.Variant) -> list[ua.Variant]:
        self._handle(handle)
        del self.handles[handle.Value]
        return []

    async def read(self, handle: ua.Variant, length: ua.Variant) -> list[ua.Variant]:
        state = self._handle(handle)
        if length.Value <= 0:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)
        self.reads += 1
        if self.fail_read_after is not None and self.reads > self.fail_read_after:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadUnexpectedError)
        if self.read_delay:
            await asyncio.sleep(self.read_delay)
        count = length.Value if self.read_cap is None else min(length.Value, self.read_cap)
        start = state["position"]
        data = bytes(self.content[start : start + count])
        state["position"] = start + len(data)
        return [ua.Variant(data, ua.VariantType.ByteString)]

    def write(self, handle: ua.Variant, data: ua.Variant) -> list[ua.Variant]:
        state = self._handle(handle)
        payload = data.Value or b""
        if self.write_cap is not None and len(payload) > self.write_cap:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadInvalidArgument)
        start = state["position"]
        self.content[start : start + len(payload)] = payload
        state["position"] = start + len(payload)
        return []

    def get_position(self, handle: ua.Variant) -> list[ua.Variant]:
        return [ua.Variant(self._handle(handle)["position"], ua.VariantType.UInt64)]

    def set_position(self, handle: ua.Variant, position: ua.Variant) -> list[ua.Variant]:
        state = self._handle(handle)
        state["position"] = min(position.Value, len(self.content))
        return []


class DirectoryRig:
    def __init__(self, server: Server) -> None:
        self.server = server
        self.names: dict[str, ua.NodeId] = {}
        self.calls: list[tuple[str, list[ua.Variant]]] = []
        self.node: Node | None = None

    async def attach(self, name: str = "RigDirectory") -> Node:
        node = await self.server.nodes.objects.add_object(2, name, objecttype=ua.ObjectIds.FileDirectoryType)
        self.node = node
        callbacks: dict[str, Callable[..., Any]] = {
            "CreateDirectory": self.create_directory,
            "CreateFile": self.create_file,
            "Delete": self.delete,
            "MoveOrCopy": self.move_or_copy,
        }
        for method_name, callback in callbacks.items():
            method_node = await node.get_child(method_name)
            self.server.link_method(method_node, self._recorded(method_name, callback))
            await make_executable(method_node)
        return node

    def _recorded(self, name: str, callback: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(parent: ua.NodeId, *args: ua.Variant) -> Any:
            self.calls.append((name, list(args)))
            return callback(*args)

        return wrapper

    def _new(self, name: str) -> ua.NodeId:
        if name in self.names:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadBrowseNameDuplicated)
        node_id = ua.NodeId(f"rig-{name}", 2)
        self.names[name] = node_id
        return node_id

    def create_directory(self, name: ua.Variant) -> list[ua.Variant]:
        return [ua.Variant(self._new(name.Value), ua.VariantType.NodeId)]

    def create_file(self, name: ua.Variant, request_open: ua.Variant) -> list[ua.Variant]:
        node_id = self._new(name.Value)
        handle = 7 if request_open.Value else 0
        return [ua.Variant(node_id, ua.VariantType.NodeId), ua.Variant(handle, ua.VariantType.UInt32)]

    def delete(self, target: ua.Variant) -> list[ua.Variant]:
        for name, node_id in list(self.names.items()):
            if node_id == target.Value:
                del self.names[name]
                return []
        raise ua.UaStatusCodeError(ua.StatusCodes.BadNotFound)

    def move_or_copy(
        self, target: ua.Variant, directory: ua.Variant, create_copy: ua.Variant, new_name: ua.Variant
    ) -> list[ua.Variant]:
        for name, node_id in list(self.names.items()):
            if node_id == target.Value:
                if not create_copy.Value:
                    del self.names[name]
                return [ua.Variant(self._new(new_name.Value or name + "-copy"), ua.VariantType.NodeId)]
        raise ua.UaStatusCodeError(ua.StatusCodes.BadNotFound)

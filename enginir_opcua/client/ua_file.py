"""
Deprecated: use `enginir_opcua.client.ua_file_transfer`. This module is removed in 4.0.0.
"""

import warnings
from types import TracebackType
from typing import Any

from enginir_opcua import ua
from enginir_opcua.common.node import Node

from .ua_file_transfer import UaFile as _UaFile

_MODES = {"r": ua.OpenFileMode.Read, "w": ua.OpenFileMode.Write}


class UaFile:
    """
    Deprecated wrapper over `ua_file_transfer.UaFile` with the string modes "r" (Read) and "w" (Write).
    Mode "w" does not erase an existing file; open `ua_file_transfer.UaFile` with
    `OpenFileMode.Write | OpenFileMode.EraseExisting` for that.
    """

    def __init__(self, file_node: Node, open_mode: str) -> None:
        warnings.warn(
            "enginir_opcua.client.ua_file is deprecated, use enginir_opcua.client.ua_file_transfer",
            DeprecationWarning,
            stacklevel=2,
        )
        if open_mode not in _MODES:
            raise ValueError("file mode is not supported")
        self._file = _UaFile(file_node, _MODES[open_mode])

    async def __aenter__(self) -> "UaFile":
        await self._file.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Any:
        return await self._file.close()

    async def open(self, open_mode: int) -> Any:
        """open file method"""
        return await self._file.open(open_mode)

    async def close(self) -> Any:
        """close file method"""
        return await self._file.close()

    async def read(self) -> Any:
        """reads file contents"""
        return await self._file.read()

    async def write(self, data: bytes) -> Any:
        """writes file contents"""
        return await self._file.write(data)

    async def get_size(self) -> Any:
        """gets size of file"""
        return await self._file.get_size()

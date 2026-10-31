"""Writes and removals of files that can be undone together, for changes that must apply all or nothing."""

import functools
import os
import stat
from collections.abc import Callable
from pathlib import Path

from enginir_opcua.crypto.cert_gen import write_atomic


class FileJournal:
    """Every operation records how to undo it; `rollback` undoes them in reverse order, `commit` forgets them."""

    def __init__(self) -> None:
        self._undo: list[Callable[[], None]] = []

    def write(self, path: Path, data: bytes, mode: int) -> None:
        previous = self._remember(path)
        write_atomic(path, data, mode)
        self._undo.append(lambda: self._restore(path, previous))

    def remove(self, path: Path) -> None:
        previous = self._remember(path)
        if previous is None:
            return
        path.unlink()
        self._undo.append(lambda: self._restore(path, previous))

    def create_directory(self, path: Path, mode: int = 0o777) -> None:
        missing = []
        current = path
        while not current.exists():
            missing.append(current)
            current = current.parent
        path.mkdir(mode=mode, parents=True, exist_ok=True)
        for directory in missing:
            self._undo.append(functools.partial(self._remove_directory, directory))

    @staticmethod
    def _remember(path: Path) -> tuple[bytes, int] | None:
        try:
            return path.read_bytes(), stat.S_IMODE(os.stat(path).st_mode)
        except FileNotFoundError:
            return None

    @staticmethod
    def _restore(path: Path, previous: tuple[bytes, int] | None) -> None:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            write_atomic(path, previous[0], previous[1])

    @staticmethod
    def _remove_directory(path: Path) -> None:
        try:
            path.rmdir()
        except OSError:
            pass

    def rollback(self) -> None:
        undo, self._undo = self._undo, []
        for operation in reversed(undo):
            try:
                operation()
            except OSError:
                pass

    def commit(self) -> None:
        self._undo = []

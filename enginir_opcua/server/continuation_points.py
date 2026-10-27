"""The Browse continuation points of one Session (Part 4, 7.9)."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from enginir_opcua import ua

TOKEN_LENGTH = 16


@dataclass
class BrowseCursor:
    node_id: ua.NodeId
    direction: ua.BrowseDirection
    reference_type: ua.NodeId
    include_subtypes: bool
    node_class_mask: int
    result_mask: int
    page_limit: int
    position: int
    version: int


class ContinuationPoints:
    def __init__(self, limit: Callable[[], int]) -> None:
        self._limit = limit
        self._entries: dict[bytes, BrowseCursor] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, token: bytes | None) -> BrowseCursor | None:
        return self._entries.get(token) if token else None

    def take(self, token: bytes | None) -> BrowseCursor | None:
        return self._entries.pop(token, None) if token else None

    def has_room(self) -> bool:
        return len(self._entries) < self._limit()

    def release_oldest(self, keep: set[bytes]) -> bool:
        for token in self._entries:
            if token not in keep:
                del self._entries[token]
                return True
        return False

    def add(self, cursor: BrowseCursor) -> bytes:
        token = secrets.token_bytes(TOKEN_LENGTH)
        self._entries[token] = cursor
        return token

    def renew(self, token: bytes) -> bytes:
        renewed = secrets.token_bytes(TOKEN_LENGTH)
        self._entries = {(renewed if key == token else key): cursor for key, cursor in self._entries.items()}
        return renewed

    def clear(self) -> None:
        self._entries.clear()

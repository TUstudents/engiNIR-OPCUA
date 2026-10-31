"""The Browse and history continuation points of one Session (OPC 10000-4 v1.05, 7.9)."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from enginir_opcua import ua

TOKEN_LENGTH = 16


@dataclass
class BrowseCursor:
    """Where a Browse stopped: the node, the filter of the request, the position and the reference_version then."""

    node_id: ua.NodeId
    direction: ua.BrowseDirection
    reference_type: ua.NodeId
    include_subtypes: bool
    node_class_mask: int
    result_mask: int
    page_limit: int
    position: int
    version: int


class ContinuationPoints[T]:
    """
    The continuation points of a session: random tokens that name a cursor, at most limit() of them. The order of
    insertion is the age, oldest first.
    """

    def __init__(self, limit: Callable[[], int]) -> None:
        self._limit = limit
        self._entries: dict[bytes, T] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, token: bytes | None) -> T | None:
        """The cursor of a token, None for an unknown or empty one."""
        return self._entries.get(token) if token else None

    def take(self, token: bytes | None) -> T | None:
        """Release a token and return its cursor."""
        return self._entries.pop(token, None) if token else None

    def has_room(self) -> bool:
        """Whether another point fits."""
        return len(self._entries) < self._limit()

    def release_oldest(self, keep: set[bytes]) -> bool:
        """Release the oldest point not in keep (the points of the running request); whether one was released."""
        for token in self._entries:
            if token not in keep:
                del self._entries[token]
                return True
        return False

    def add(self, cursor: T) -> bytes:
        """Keep a cursor and return its new token."""
        token = secrets.token_bytes(TOKEN_LENGTH)
        self._entries[token] = cursor
        return token

    def renew(self, token: bytes) -> bytes:
        """Give the cursor of a token a new token, keeping its age; a point cannot be used twice."""
        renewed = secrets.token_bytes(TOKEN_LENGTH)
        self._entries = {(renewed if key == token else key): cursor for key, cursor in self._entries.items()}
        return renewed

    def clear(self) -> None:
        """Release every point."""
        self._entries.clear()

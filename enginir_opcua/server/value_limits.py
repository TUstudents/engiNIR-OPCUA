from __future__ import annotations

from dataclasses import fields, is_dataclass
from typing import Any

from enginir_opcua import ua
from enginir_opcua.ua.ua_binary import DecodeLimits

MAX_DEPTH = 100


def _leaves(value: Any) -> int:
    if isinstance(value, (list, tuple)):
        return sum(_leaves(item) for item in value)
    return 1


def exceeds_limits(value: Any, limits: DecodeLimits, depth: int = 0) -> bool:
    """
    True if a value from a request is longer than a server limit (Part 5, 6.3.2): a String or LocalizedText text
    over `max_string_length` bytes, a ByteString over `max_byte_string_length` bytes, or an array over
    `max_array_length` elements in all dimensions together.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return False
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="surrogateescape")) > limits.max_string_length
    if isinstance(value, (bytes, bytearray)):
        return len(value) > limits.max_byte_string_length
    if isinstance(value, ua.Variant):
        if isinstance(value.Value, (list, tuple)) and _leaves(value.Value) > limits.max_array_length:
            return True
        return exceeds_limits(value.Value, limits, depth + 1)
    if isinstance(value, ua.DataValue):
        return exceeds_limits(value.Value, limits, depth + 1)
    if isinstance(value, (list, tuple)):
        return any(exceeds_limits(item, limits, depth + 1) for item in value)
    if is_dataclass(value) and not isinstance(value, type):
        return any(exceeds_limits(getattr(value, f.name), limits, depth + 1) for f in fields(value))
    return False

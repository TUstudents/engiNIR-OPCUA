from __future__ import annotations

from typing import Any

from enginir_opcua import ua

Ranges = list[tuple[int, int]]


def parse_index_range(text: str) -> Ranges | None:
    ranges: Ranges = []
    for part in text.split(","):
        low, separator, high = part.partition(":")
        if not low.isascii() or not low.isdigit() or (separator and (not high.isascii() or not high.isdigit())):
            return None
        start = int(low)
        end = int(high) if separator else start
        if end < start or (separator and end == start) or end > 0xFFFFFFFF:
            return None
        ranges.append((start, end))
    return ranges


def select_index_range(value: Any, text: str) -> tuple[int, Any]:
    ranges = parse_index_range(text)
    if ranges is None:
        return ua.StatusCodes.BadIndexRangeInvalid, None
    if len(ranges) != 1 or not isinstance(value, list | str | bytes):
        return ua.StatusCodes.BadIndexRangeNoData, None
    start, end = ranges[0]
    if start >= len(value):
        return ua.StatusCodes.BadIndexRangeNoData, None
    return ua.StatusCodes.Good, value[start : end + 1]

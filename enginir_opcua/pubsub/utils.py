import datetime
import logging
import time
from collections import Counter
from typing import Any

from enginir_opcua.ua import VersionTime

LOG_INTERVAL = 10.0


def version_time_now() -> VersionTime:
    """Seconds since 2000-01-01, OPC 10000-4 v1.05, 7.43"""
    return VersionTime(
        (datetime.datetime.now(datetime.UTC) - datetime.datetime(2000, 1, 1, 0, 0, 0, 0, datetime.UTC)).total_seconds()
    )


class RateLimitedLog:
    """Logs the first event of a kind, then at most one more every `interval` seconds with the number it skipped"""

    def __init__(self, logger: logging.Logger, interval: float = LOG_INTERVAL) -> None:
        self._logger = logger
        self._interval = interval
        self._last: dict[str, float] = {}
        self._skipped: Counter[str] = Counter()

    def warning(self, key: str, message: str, *args: Any) -> None:
        now = time.monotonic()
        last = self._last.get(key)
        if last is not None and now - last < self._interval:
            self._skipped[key] += 1
            return
        skipped = self._skipped.pop(key, 0)
        self._last[key] = now
        if skipped:
            self._logger.warning("%s (%d similar events not logged)", message % args, skipped)
        else:
            self._logger.warning(message, *args)

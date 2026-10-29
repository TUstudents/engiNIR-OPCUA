import asyncio
import time
from collections.abc import Callable


async def until(condition: Callable[[], bool], timeout: float = 5.0, interval: float = 0.005) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(interval)


def until_sync(condition: Callable[[], bool], timeout: float = 5.0, interval: float = 0.005) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise TimeoutError("condition not met")
        time.sleep(interval)

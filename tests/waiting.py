import asyncio
import time
from collections.abc import Awaitable, Callable


async def wait_until(
    condition: Callable[[], Awaitable[bool] | bool], timeout: float = 10.0, interval: float = 0.01
) -> None:
    deadline = time.monotonic() + timeout
    while True:
        result = condition()
        if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
            result = await result
        if result:
            return
        if time.monotonic() > deadline:
            raise TimeoutError("condition not met within the timeout")
        await asyncio.sleep(interval)

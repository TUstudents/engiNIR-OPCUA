import time
from collections.abc import Callable


def wait_until_sync(condition: Callable[[], bool], timeout: float = 5.0, interval: float = 0.005) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise TimeoutError("condition not met within the timeout")
        time.sleep(interval)

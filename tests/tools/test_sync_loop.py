import asyncio
import gc
import subprocess
import sys
import threading
import time
import warnings

import pytest

from enginir_opcua.sync import ThreadLoop, ThreadLoopNotRunning


def run_with_deadline(function, seconds: float = 5.0) -> None:
    errors: list[BaseException] = []

    def target() -> None:
        try:
            function()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "the call did not return"
    if errors:
        raise errors[0]


def test_syn5_a_forgotten_threadloop_does_not_block_exit():
    """A program that never stops its ThreadLoop still exits."""
    code = "from enginir_opcua.sync import ThreadLoop\nThreadLoop().start()\n"
    result = subprocess.run([sys.executable, "-c", code], timeout=10, capture_output=True)
    assert result.returncode == 0


def test_syn1_a_sync_call_on_the_loop_thread_raises_instead_of_deadlocking():
    """Part 4 has no say here; a blocking call made on the loop thread could only wait for itself."""
    with ThreadLoop(timeout=3) as tloop:

        async def inner() -> int:
            return 1

        async def outer() -> int:
            return tloop.post(inner())

        with pytest.raises(RuntimeError, match="loop thread"):
            tloop.post(outer())


def test_syn2_a_timed_out_call_is_cancelled_before_post_raises():
    """Part 4, 5.7.5: a call that was reported as timed out must not run on."""
    state = {"cancelled": False, "finished": False}

    async def slow() -> None:
        try:
            await asyncio.sleep(5)
            state["finished"] = True
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    with ThreadLoop(timeout=0.2) as tloop:
        with pytest.raises(TimeoutError, match=r"0\.2 s"):
            tloop.post(slow())
        assert state == {"cancelled": True, "finished": False}


def test_syn2_a_call_may_carry_its_own_timeout():
    async def quick() -> int:
        await asyncio.sleep(0.3)
        return 7

    with ThreadLoop(timeout=0.1) as tloop:
        assert tloop.post(quick(), timeout=2) == 7
        assert tloop.post(quick(), timeout=None) == 7


def test_syn4_start_raises_when_the_thread_fails(monkeypatch):
    def broken_loop():
        raise OSError("no loop for you")

    monkeypatch.setattr(asyncio, "new_event_loop", broken_loop)
    tloop = ThreadLoop()
    with pytest.raises(OSError, match="no loop for you"):
        run_with_deadline(tloop.start)


def test_syn4_stop_cancels_pending_tasks():
    state = {"cancelled": False}

    async def forever() -> None:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    tloop = ThreadLoop()
    tloop.start()
    asyncio.run_coroutine_threadsafe(forever(), tloop.loop)
    time.sleep(0.2)
    tloop.stop()
    assert state["cancelled"]


def test_syn6_stop_is_idempotent_and_the_loop_restarts():
    async def answer() -> int:
        return 42

    tloop = ThreadLoop()
    tloop.start()
    tloop.stop()
    tloop.stop()
    tloop.start()
    assert tloop.post(answer()) == 42
    tloop.stop()


def test_syn6_post_on_a_stopped_loop_leaves_no_unawaited_coroutine():
    async def answer() -> int:
        return 1

    tloop = ThreadLoop()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(ThreadLoopNotRunning):
            tloop.post(answer())
        gc.collect()
    assert not [w for w in caught if issubclass(w.category, RuntimeWarning)]


def test_syn1_stop_from_the_loop_thread_raises():
    with ThreadLoop() as tloop:

        async def stopper() -> None:
            tloop.stop()

        with pytest.raises(RuntimeError, match="loop thread"):
            tloop.post(stopper())

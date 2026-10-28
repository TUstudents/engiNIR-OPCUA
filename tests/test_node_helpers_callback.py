from typing import Any

import pytest

from enginir_opcua.common.callback import Callback, CallbackService


async def test_com4_two_listeners_with_the_same_priority_both_run_in_insertion_order() -> None:
    """Part 4 has no rule here; design: all listeners stay registered."""
    service = CallbackService()
    calls: list[str] = []
    service.addListener("e", lambda event, svc: calls.append("a"))
    service.addListener("e", lambda event, svc: calls.append("b"))
    await service.dispatch("e")
    assert calls == ["a", "b"]


async def test_com4_priority_orders_listeners() -> None:
    service = CallbackService()
    calls: list[str] = []
    service.addListener("e", lambda event, svc: calls.append("late"), 5)
    service.addListener("e", lambda event, svc: calls.append("first"), -1)
    service.addListener("e", lambda event, svc: calls.append("mid"), 0)
    await service.dispatch("e")
    assert calls == ["first", "mid", "late"]


async def test_com4_remove_listener_by_identity() -> None:
    service = CallbackService()
    calls: list[str] = []

    def one(event: Callback, svc: CallbackService) -> None:
        calls.append("one")

    service.addListener("e", one)
    service.addListener("e", lambda event, svc: calls.append("two"))
    service.removeListener("e", one)
    service.removeListener("e", lambda event, svc: None)
    await service.dispatch("e")
    assert calls == ["two"]
    service.removeListener("e")
    await service.dispatch("e")
    assert calls == ["two"]


async def test_com5_object_with_async_call_is_awaited() -> None:
    service = CallbackService()
    calls: list[str] = []

    class Listener:
        async def __call__(self, event: Callback, svc: CallbackService) -> None:
            calls.append("async")

    service.addListener("e", Listener())
    await service.dispatch("e")
    assert calls == ["async"]


async def test_com99_listener_may_add_a_listener_during_dispatch() -> None:
    service = CallbackService()
    calls: list[str] = []

    def adder(event: Callback, svc: CallbackService) -> None:
        calls.append("adder")
        service.addListener("e", lambda e, s: calls.append("added"), 9)

    service.addListener("e", adder)
    service.addListener("e", lambda e, s: calls.append("other"), 1)
    await service.dispatch("e")
    assert calls == ["adder", "other"]
    await service.dispatch("e")
    assert calls == ["adder", "other", "adder", "other", "added"]


async def test_com5_failing_listener_stops_dispatch_and_propagates() -> None:
    service = CallbackService()
    calls: list[str] = []

    def failing(event: Callback, svc: CallbackService) -> Any:
        raise RuntimeError("no")

    service.addListener("e", failing, 0)
    service.addListener("e", lambda event, svc: calls.append("after"), 1)
    with pytest.raises(RuntimeError):
        await service.dispatch("e")
    assert calls == []

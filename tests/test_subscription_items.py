"""Monitored item bookkeeping of the client Subscription (modify, revised values)."""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime
from typing import Any, get_overloads

import pytest

from enginir_opcua import ua
from enginir_opcua.common.subscription import Subscription, SubscriptionItemData

from .test_subscriptions import MySubHandler


def capture_modify(sub: Subscription, monkeypatch: pytest.MonkeyPatch) -> list[ua.ModifyMonitoredItemsParameters]:
    sent: list[ua.ModifyMonitoredItemsParameters] = []
    original = sub.server.modify_monitored_items

    async def modify(params: ua.ModifyMonitoredItemsParameters) -> Any:
        sent.append(params)
        return await original(params)

    monkeypatch.setattr(sub.server, "modify_monitored_items", modify)
    return sent


async def test_com31_unknown_handle_is_value_error(opc) -> None:
    """Part 4, 5.13.3: only an existing item can be modified; the client refuses an unknown handle itself."""
    sub = await opc.opc.create_subscription(100, MySubHandler())
    with pytest.raises(ValueError):
        await sub.modify_monitored_item(123456, 100)
    await sub.delete()


async def test_com30_modify_keeps_event_decoding(opc) -> None:
    """Part 4, 5.13.3: Modify must not replace the stored EventFilter by the server's FilterResult."""
    handler = MySubHandler()
    sub = await opc.opc.create_subscription(100, handler)
    handle = await sub.subscribe_events()
    await sub.modify_monitored_item(handle, 0, 10)
    item = next(i for i in sub._monitored_items.values() if i.server_handle == handle)
    assert isinstance(item.mfilter, ua.EventFilter)
    evgen = await opc.server.get_event_generator()
    await evgen.trigger(datetime.now(UTC), "after modify")
    event = await handler.result()
    assert event.Message.Text == "after modify"
    await sub.delete()


async def test_cli22_second_modify_resends_the_requested_filter(opc, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.13.3: every Modify carries the filter as requested, never an earlier FilterResult."""
    node = await opc.opc.nodes.objects.add_variable(3, "Cli22Var", 1.0)
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handle = await sub.deadband_monitor(node, 0.5, queuesize=3)
    sent = capture_modify(sub, monkeypatch)
    await sub.modify_monitored_item(handle, 200)
    await sub.modify_monitored_item(handle, 300)
    for params in sent:
        sent_filter = params.ItemsToModify[0].RequestedParameters.Filter
        assert isinstance(sent_filter, ua.DataChangeFilter)
        assert sent_filter.DeadbandValue == 0.5
    await sub.delete()
    await opc.opc.delete_nodes([node])


async def test_com70_modify_keeps_timestamps_queue_size_and_discard_policy(
    opc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.13.3: Modify replaces all parameters, so the stored ones are sent again."""
    node = await opc.opc.nodes.objects.add_variable(3, "Com70Var", 1.0)
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handle = await sub.subscribe_data_change(node, queuesize=5)
    item = next(i for i in sub._monitored_items.values() if i.server_handle == handle)
    item.discard_oldest = False
    sent = capture_modify(sub, monkeypatch)
    await sub.modify_monitored_item(handle, 250)
    params = sent[0]
    assert params.TimestampsToReturn == ua.TimestampsToReturn.Both
    requested = params.ItemsToModify[0].RequestedParameters
    assert requested.QueueSize == 5
    assert requested.DiscardOldest is False
    assert requested.SamplingInterval == 250
    assert item.queuesize == 5
    assert item.sampling_interval == 250
    await sub.delete()
    await opc.opc.delete_nodes([node])


async def test_cli22_modify_without_filter_keeps_the_deadband(opc, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.13.3: a null filter removes the filter, so only an explicit None may send one."""
    node = await opc.opc.nodes.objects.add_variable(3, "Cli22Var2", 1.0)
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handle = await sub.deadband_monitor(node, 2.0)
    sent = capture_modify(sub, monkeypatch)
    await sub.modify_monitored_item(handle, 100)
    await sub.modify_monitored_item(handle, 100, mod_filter_val=None)
    assert isinstance(sent[0].ItemsToModify[0].RequestedParameters.Filter, ua.DataChangeFilter)
    assert not isinstance(sent[1].ItemsToModify[0].RequestedParameters.Filter, ua.DataChangeFilter)
    await sub.delete()
    await opc.opc.delete_nodes([node])


async def test_com73_revised_sampling_interval_and_queue_size_are_stored(opc) -> None:
    """Part 4, 5.13.2: the item keeps what the server revised next to what was requested."""
    node = await opc.opc.nodes.objects.add_variable(3, "Com73Var", 1.0)
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handle = await sub.subscribe_data_change(node, queuesize=7, sampling_interval=1)
    await asyncio.sleep(0)
    item = next(i for i in sub._monitored_items.values() if i.server_handle == handle)
    assert item.sampling_interval == 1
    assert item.queuesize == 7
    assert item.revised_sampling_interval is not None
    assert item.revised_queuesize == 7
    await sub.delete()
    await opc.opc.delete_nodes([node])


async def test_com69_unsubscribe_accepts_a_generator(opc) -> None:
    """Part 4, 5.13.6: every item the server deleted leaves the local map, whatever the iterable."""
    nodes = [await opc.opc.nodes.objects.add_variable(3, f"Com69Var{i}", 1.0) for i in range(2)]
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handles = await sub.subscribe_data_change(nodes)
    assert len(sub._monitored_items) == 2
    await sub.unsubscribe(h for h in handles if isinstance(h, int))
    assert sub._monitored_items == {}
    await sub.delete()
    await opc.opc.delete_nodes(nodes)


async def test_com34_unsubscribe_keeps_items_the_server_could_not_delete(opc, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.13.6: the per-item results decide which items are removed locally."""
    nodes = [await opc.opc.nodes.objects.add_variable(3, f"Com34Var{i}", 1.0) for i in range(2)]
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handles = await sub.subscribe_data_change(nodes)

    async def delete_items(params: ua.DeleteMonitoredItemsParameters) -> list[ua.StatusCode]:
        return [ua.StatusCode(ua.StatusCodes.Good), ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)]

    monkeypatch.setattr(sub.server, "delete_monitored_items", delete_items)
    with pytest.raises(ua.UaStatusCodeError):
        await sub.unsubscribe(handles)
    assert [i.server_handle for i in sub._monitored_items.values()] == [handles[1]]
    monkeypatch.undo()
    await sub.delete()
    await opc.opc.delete_nodes(nodes)


async def test_unsubscribe_of_an_unknown_handle_sends_nothing(opc, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.13.6: a handle that isn't an item of this Subscription is skipped."""
    sub = await opc.opc.create_subscription(100, MySubHandler())
    sent: list[Any] = []

    async def delete_items(params: ua.DeleteMonitoredItemsParameters) -> list[ua.StatusCode]:
        sent.append(params)
        return []

    monkeypatch.setattr(sub.server, "delete_monitored_items", delete_items)
    await sub.unsubscribe([4242])
    assert sent == []
    monkeypatch.undo()
    await sub.delete()


async def test_com34_set_monitoring_mode_updates_stored_mode_and_survives_recreate(
    opc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.12.4: the mode the server confirmed is the mode a recreated item gets."""
    node = await opc.opc.nodes.objects.add_variable(3, "Com34Mode", 1.0)
    sub = await opc.opc.create_subscription(100, MySubHandler())
    await sub.subscribe_data_change(node)
    if not sub._remote:
        pytest.skip("in-process subscriptions have no monitoring mode service")
    results = await sub.set_monitoring_mode(ua.MonitoringMode.Disabled)
    assert results[0].is_good()
    item = next(iter(sub._monitored_items.values()))
    assert item.monitoring_mode == ua.MonitoringMode.Disabled
    sent: list[ua.CreateMonitoredItemsParameters] = []
    original = sub.server.create_monitored_items

    async def create_items(params: ua.CreateMonitoredItemsParameters) -> Any:
        sent.append(params)
        return await original(params)

    monkeypatch.setattr(sub.server, "create_monitored_items", create_items)
    await sub.recreate()
    assert sent[0].ItemsToCreate[0].MonitoringMode == ua.MonitoringMode.Disabled
    monkeypatch.undo()
    await sub.delete()
    await opc.opc.delete_nodes([node])


async def test_com34_set_monitoring_mode_skips_items_without_server_handle(
    opc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.12.4: only items the server knows are sent."""
    sub = await opc.opc.create_subscription(100, MySubHandler())
    if not sub._remote:
        pytest.skip("in-process subscriptions have no monitoring mode service")
    pending = SubscriptionItemData()
    pending.client_handle = 999
    sub._monitored_items[999] = pending
    sent: list[Any] = []

    async def set_mode(params: ua.SetMonitoringModeParameters) -> list[ua.StatusCode]:
        sent.append(params)
        return []

    monkeypatch.setattr(sub.server, "set_monitoring_mode", set_mode)
    assert await sub.set_monitoring_mode(ua.MonitoringMode.Disabled) == []
    assert sent == []
    monkeypatch.undo()
    del sub._monitored_items[999]
    await sub.delete()


async def test_com34_recreate_keeps_discard_oldest(opc, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.13.1.5: a recreated item uses the discard policy it was created with."""
    node = await opc.opc.nodes.objects.add_variable(3, "Com34Discard", 1.0)
    sub = await opc.opc.create_subscription(100, MySubHandler())
    await sub.subscribe_data_change(node, queuesize=4)
    next(iter(sub._monitored_items.values())).discard_oldest = False
    sent: list[ua.CreateMonitoredItemsParameters] = []
    original = sub.server.create_monitored_items

    async def create_items(params: ua.CreateMonitoredItemsParameters) -> Any:
        sent.append(params)
        return await original(params)

    monkeypatch.setattr(sub.server, "create_monitored_items", create_items)
    await sub.recreate()
    assert sent[0].ItemsToCreate[0].RequestedParameters.DiscardOldest is False
    assert sent[0].ItemsToCreate[0].RequestedParameters.QueueSize == 4
    monkeypatch.undo()
    await sub.delete()
    await opc.opc.delete_nodes([node])


async def test_com35_default_sampling_interval_follows_the_publishing_interval(
    opc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.21: a sampling interval of -1 means the publishing interval of the Subscription."""
    node = await opc.opc.nodes.objects.add_variable(3, "Com35Var", 1.0)
    sub = await opc.opc.create_subscription(100, MySubHandler())
    sent: list[ua.CreateMonitoredItemsParameters] = []
    original = sub.server.create_monitored_items

    async def create_items(params: ua.CreateMonitoredItemsParameters) -> Any:
        sent.append(params)
        return await original(params)

    monkeypatch.setattr(sub.server, "create_monitored_items", create_items)
    await sub.subscribe_data_change(node)
    await sub.deadband_monitor(node, 1.0)
    assert [p.ItemsToCreate[0].RequestedParameters.SamplingInterval for p in sent] == [-1, -1]
    monkeypatch.undo()
    await sub.delete()
    await opc.opc.delete_nodes([node])


def test_com35_overloads_declare_the_same_default_as_the_implementation() -> None:
    """Part 4, 7.21: the signatures the type checker sees say -1, like the code."""
    defaults = {
        inspect.signature(f).parameters["sampling_interval"].default
        for f in [*get_overloads(Subscription.subscribe_data_change), Subscription.subscribe_data_change]
    }
    assert defaults == {-1}

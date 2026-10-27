"""Monitored item bookkeeping of the client Subscription (modify, revised values)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.subscription import Subscription

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

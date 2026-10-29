from __future__ import annotations

import asyncio
import inspect
from asyncio import Future, sleep, wait_for
from collections.abc import AsyncIterator
from copy import copy
from datetime import UTC, datetime, timedelta
from typing import Any, get_overloads
from unittest.mock import AsyncMock

import pytest

import enginir_opcua
from enginir_opcua import Client, Server, ua
from enginir_opcua.common.subscription import (
    DataChangeEvent,
    Subscription,
    SubscriptionItemData,
)
from enginir_opcua.server.internal_server import InternalServer
from enginir_opcua.ua.ua_binary import nodeid_from_binary, struct_from_binary
from tests.conftest import Opc, find_free_port
from tests.waiting import wait_until

try:
    from unittest.mock import AsyncMock
except ImportError:
    from asynctest import CoroutineMock as AsyncMock  # type: ignore[no-redef]


class MySubHandler:
    """
    More advanced subscription client using Future, so we can await events in tests.
    """

    def __init__(self):
        self.future = Future()

    def reset(self):
        self.future = Future()

    async def result(self):
        return await wait_for(self.future, 2)

    def datachange_notification(self, node, val, data):
        if not self.future.done():
            self.future.set_result((node, val, data))

    def event_notification(self, event):
        if not self.future.done():
            self.future.set_result(event)


class MySubHandler2:
    def __init__(self, limit=None):
        self.results = []
        self.limit = limit
        self._done = asyncio.Event()

    async def done(self):
        return await wait_for(self._done.wait(), 2)

    def check_done(self):
        if self.limit and len(self.results) == self.limit and not self._done.is_set():
            self._done.set()

    def datachange_notification(self, node, val, data):
        self.results.append((node, val))
        self.check_done()

    def event_notification(self, event):
        self.results.append(event)
        self.check_done()


class MySubHandlerCounter:
    def __init__(self):
        self.datachange_count = 0
        self.event_count = 0

    def datachange_notification(self, node, val, data):
        self.datachange_count += 1

    def event_notification(self, event):
        self.event_count += 1


class MySubHandlerCounterAsync(MySubHandlerCounter):
    async def datachange_notification(self, node, val, data):
        self.datachange_count += 1

    async def event_notification(self, event):
        self.event_count += 1


async def test_subscription_failure(opc):
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    sub = await opc.opc.create_subscription(100, myhandler)
    with pytest.raises(ua.UaStatusCodeError):
        # we can only subscribe to variables so this should fail
        await sub.subscribe_data_change(o)
    await sub.delete()


@pytest.mark.parametrize("handler_class", [MySubHandlerCounter, MySubHandlerCounterAsync])
async def test_subscription_overload(opc, handler_class):
    nb = 10
    myhandler = handler_class()
    o = opc.opc.nodes.objects
    sub = await opc.opc.create_subscription(1, myhandler)
    variables = []
    subs = []
    for i in range(nb):
        v = await o.add_variable(3, f"SubscriptionVariableOverload{i}", 99)
        variables.append(v)
    for i in range(nb):
        await sub.subscribe_data_change(variables)
    for i in range(nb):
        for j in range(nb):
            await variables[i].write_value(j)
        s = await opc.opc.create_subscription(1, myhandler)
        await s.subscribe_data_change(variables)
        subs.append(s)
        await sub.subscribe_data_change(variables[i])
    for i in range(nb):
        for j in range(nb):
            await variables[i].write_value(j)
    # await asyncio.sleep(4)
    await sub.delete()
    for s in subs:
        await s.delete()
    # assert myhandler.datachange_count == 1000
    # assert myhandler.event_count == 0
    await opc.opc.delete_nodes(variables)


@pytest.mark.parametrize("handler_class", [MySubHandlerCounter, MySubHandlerCounterAsync])
async def test_subscription_count(opc, handler_class):
    myhandler = handler_class()
    sub = await opc.opc.create_subscription(1, myhandler)
    o = opc.opc.nodes.objects
    var = await o.add_variable(3, "SubVarCounter", 0.1)
    await sub.subscribe_data_change(var, queuesize=1000)
    nb = 100
    for i in range(nb):
        val = await var.read_value()
        await var.write_value(val + 1)
    await wait_until(lambda: myhandler.datachange_count >= nb + 1)
    assert nb + 1 == myhandler.datachange_count
    await sub.delete()
    await opc.opc.delete_nodes([var])


@pytest.mark.parametrize("handler_class", [MySubHandlerCounter, MySubHandlerCounterAsync])
async def test_subscription_count_list(opc, handler_class):
    myhandler = handler_class()
    sub = await opc.opc.create_subscription(1, myhandler)
    o = opc.opc.nodes.objects
    var = await o.add_variable(3, "SubVarCounter1", [0.1, 0.2])
    await sub.subscribe_data_change(var, queuesize=1000)
    nb = 12
    for i in range(nb):
        val = await var.read_value()
        #  we do not want to modify object in our db, we need a copy in order to generate event
        val = copy(val)
        val.append(i)
        await var.write_value(copy(val))
    await wait_until(lambda: myhandler.datachange_count >= nb + 1)
    assert nb + 1 == myhandler.datachange_count
    await sub.delete()
    await opc.opc.delete_nodes([var])


@pytest.mark.parametrize("handler_class", [MySubHandlerCounter, MySubHandlerCounterAsync])
async def test_subscription_count_no_change(opc, handler_class):
    myhandler = handler_class()
    sub = await opc.opc.create_subscription(1, myhandler)
    o = opc.opc.nodes.objects
    var = await o.add_variable(3, "SubVarCounter2", [0.1, 0.2])
    await sub.subscribe_data_change(var)
    nb = 12
    for i in range(nb):
        val = await var.read_value()
        await var.write_value(val)
    await sleep(0.2)  # let last event arrive
    assert 1 == myhandler.datachange_count
    await sub.delete()
    await opc.opc.delete_nodes([var])


@pytest.mark.parametrize("handler_class", [MySubHandlerCounter, MySubHandlerCounterAsync])
async def test_subscription_count_empty(opc, handler_class):
    myhandler = handler_class()
    sub = await opc.opc.create_subscription(1, myhandler)
    o = opc.opc.nodes.objects
    var = await o.add_variable(3, "SubVarCounter3", [0.1, 0.2, 0.3])
    await sub.subscribe_data_change(var, queuesize=1000)
    while True:
        val = await var.read_value()
        # we do not want to modify object in our db, we need a copy in order to generate event
        val = copy(val)
        val.pop()
        await var.write_value(val, ua.VariantType.Double)
        if not val:
            break
    await wait_until(lambda: myhandler.datachange_count >= 4)
    assert 4 == myhandler.datachange_count
    await sub.delete()
    await opc.opc.delete_nodes([var])


async def test_subscription_overload_simple(opc):
    nb = 10
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    sub = await opc.opc.create_subscription(1, myhandler)
    variables = []
    for i in range(nb):
        variables.append(await o.add_variable(3, f"SubVarOverload{i}", i))
    for i in range(nb):
        await sub.subscribe_data_change(variables)
    await sub.delete()


async def test_subscription_data_change(opc):
    """
    test subscriptions. This is far too complicated for
    a unittest but, setting up subscriptions requires a lot
    of code, so when we first set it up, it is best
    to test as many things as possible
    """
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    # subscribe to a variable
    startv1 = [1, 2, 3]
    v1 = await o.add_variable(3, "SubscriptionVariableV1", startv1)
    sub = await opc.opc.create_subscription(100, myhandler)
    handle1 = await sub.subscribe_data_change(v1)
    # Now check we get the start value
    node, val, _data = await myhandler.result()
    assert startv1 == val
    assert v1 == node
    myhandler.reset()  # reset future object
    # modify v1 and check we get value
    await v1.write_value([5])
    node, val, _data = await myhandler.result()
    assert v1 == node
    assert [5] == val
    await sub.unsubscribe(999)  # non existing handle is skipped
    await sub.unsubscribe(handle1)
    await sub.unsubscribe(handle1)  # a second try is skipped as well
    await sub.delete()
    await sub.unsubscribe(handle1)  # sub does not exist anymore, nothing is sent
    await opc.opc.delete_nodes([v1])


async def test_subscription_monitored_item(opc: Opc):
    """
    test subscriptions with a monitored item with a datachange filter.

    filter is Trigger=ua.DataChangeTrigger.StatusValueTimestamp (Part 4 7.17.2 DataChangeFilter)
    """
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    # subscribe to a variable, adding the variable will also set a sourcetimestamp on the value
    startv1 = [1, 2, 3]
    v1 = await o.add_variable(3, "SubscriptionVariableV1", startv1)
    sub: Subscription = await opc.opc.create_subscription(100, myhandler)

    mfilter = ua.DataChangeFilter(Trigger=ua.DataChangeTrigger.StatusValueTimestamp)

    # For creating monitor items create_monitored_items is availablem, but that one is not very easy in use.
    # So use the internal function instead.
    # TODO: Should there be an easy shorthand for making monitored items with filter?
    handles = await sub._subscribe(nodes=v1, mfilter=mfilter)

    # # Now check we get the start value
    node, val, _data = await myhandler.result()
    assert startv1 == val
    assert v1 == node
    myhandler.reset()  # reset future object

    # modify v1 and check we get value
    # Instead of  v1.write_value([5]) use the datavalue to prevent setting a source stamp
    await v1.write_value(ua.DataValue([5]))

    # first change will trigger an event (now the new sourcetimestamp becomes not set)
    node, val, _data = await myhandler.result()
    assert v1 == node
    assert [5] == val
    myhandler.reset()  # reset future object

    # second update; again use the datavalue to prevent setting a source stamp
    await v1.write_value(ua.DataValue([6]))

    # seccond change will trigger based on value (no change in sourcetimestamp)
    node, val, _data = await myhandler.result()
    assert v1 == node
    assert [6] == val

    await sub.unsubscribe(handles)  # typing issues
    await sub.delete()
    await opc.opc.delete_nodes([v1])


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_create_subscription_publishing(opc):
    """
    Test the publishing argument is set during subscription creation
    """
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    _ = await o.add_variable(3, "SubscriptionVariable", 123)
    # publishing default to True
    sub = await opc.opc.create_subscription(100, myhandler)
    assert sub.parameters.PublishingEnabled
    await sub.delete()
    sub = await opc.opc.create_subscription(100, myhandler, publishing=False)
    assert not sub.parameters.PublishingEnabled
    await sub.delete()


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_set_monitoring_mode(opc, mocker):
    """
    test set_monitoring_mode parameter for all MIs of a subscription
    """
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    monitoring_mode = ua.SetMonitoringModeParameters()
    _ = mocker.patch.object(ua, "SetMonitoringModeParameters", return_value=monitoring_mode)
    _ = mocker.patch("enginir_opcua.client.ua_session.UaSession.set_monitoring_mode", new=AsyncMock())
    var = await o.add_variable(3, "SubscriptionVariable2", 123)
    sub = await opc.opc.create_subscription(100, myhandler)
    await sub.subscribe_data_change(var)

    await sub.set_monitoring_mode(ua.MonitoringMode.Disabled)
    assert monitoring_mode.MonitoringMode == ua.MonitoringMode.Disabled

    await sub.set_monitoring_mode(ua.MonitoringMode.Reporting)
    assert monitoring_mode.MonitoringMode == ua.MonitoringMode.Reporting

    await sub.delete()


async def test_monitored_item_created_disabled_does_not_report(opc):
    """
    A monitored item created with MonitoringMode.Disabled must not be reported.
    """
    myhandler = MySubHandlerCounter()
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "SubscriptionVariableDisabled", 123)
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_data_change(v, monitoring=ua.MonitoringMode.Disabled)
    await sleep(0.3)
    assert myhandler.datachange_count == 0
    await v.write_value(456)
    await sleep(0.3)
    assert myhandler.datachange_count == 0
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([v])


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_monitored_item_enabled_after_disabled_reports_initial_sample(opc):
    """
    Switching a monitored item from Disabled to Reporting must report the current value.
    """
    myhandler = MySubHandlerCounter()
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "SubscriptionVariableDisabledThenEnabled", 123)
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_data_change(v, monitoring=ua.MonitoringMode.Disabled)
    await sleep(0.3)
    assert myhandler.datachange_count == 0
    results = await sub.set_monitoring_mode(ua.MonitoringMode.Reporting)
    assert all(res.is_good() for res in results)
    await wait_until(lambda: myhandler.datachange_count >= 1)
    assert myhandler.datachange_count == 1
    await v.write_value(456)
    await wait_until(lambda: myhandler.datachange_count >= 2)
    assert myhandler.datachange_count == 2
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([v])


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_publishing_disabled_queues_until_reenabled(opc):
    """
    With publishing disabled the server sends no notifications, but queued data
    changes are delivered once publishing is enabled again.
    """
    myhandler = MySubHandlerCounter()
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "SubscriptionVariablePublishingMode", 123)
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_data_change(v)
    await wait_until(lambda: myhandler.datachange_count >= 1)
    assert myhandler.datachange_count == 1
    results = await sub.set_publishing_mode(False)
    assert all(res.is_good() for res in results)
    await v.write_value(456)
    await sleep(0.3)
    assert myhandler.datachange_count == 1
    results = await sub.set_publishing_mode(True)
    assert all(res.is_good() for res in results)
    await wait_until(lambda: myhandler.datachange_count >= 2)
    assert myhandler.datachange_count == 2
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([v])


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_set_publishing_mode(opc, mocker):
    """
    test flipping the publishing parameter for an existing subscription
    """
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    publishing_mode = ua.SetPublishingModeParameters()
    _ = mocker.patch.object(ua, "SetPublishingModeParameters", return_value=publishing_mode)
    _ = mocker.patch("enginir_opcua.client.ua_session.UaSession.set_publishing_mode", new=AsyncMock())
    _ = await o.add_variable(3, "SubscriptionVariable3", 123)
    sub = await opc.opc.create_subscription(100, myhandler)

    await sub.set_publishing_mode(False)
    assert not publishing_mode.PublishingEnabled

    await sub.set_publishing_mode(True)
    assert publishing_mode.PublishingEnabled

    await sub.delete()


async def test_subscription_data_change_bool(opc):
    """
    test subscriptions. This is far too complicated for
    a unittest but, setting up subscriptions requires a lot
    of code, so when we first set it up, it is best
    to test as many things as possible
    """
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    # subscribe to a variable
    startv1 = True
    v1 = await o.add_variable(3, "SubscriptionVariableBool", startv1)
    sub = await opc.opc.create_subscription(100, myhandler)
    _ = await sub.subscribe_data_change(v1)
    # Now check we get the start value
    node, val, _data = await myhandler.result()
    assert startv1 == val
    assert v1 == node
    myhandler.reset()  # reset future object
    # modify v1 and check we get value
    await v1.write_value(False)
    node, val, _data = await myhandler.result()
    assert v1 == node
    assert val is False
    await sub.delete()  # should delete our monitoreditem too
    await opc.opc.delete_nodes([v1])


async def test_subscription_data_change_complex(opc):
    """
    test subscriptions. This is far too complicated for
    a unittest but, setting up subscriptions requires a lot
    of code, so when we first set it up, it is best
    to test as many things as possible.
    Check if a mutable object is handeled corretly
    """
    myhandler = MySubHandler()
    o = opc.opc.nodes.objects
    # subscribe to a variable
    startv1 = ua.BuildInfo("ABC")
    v1 = await o.add_variable(3, "SubscriptionVariableLoc", startv1)
    sub = await opc.opc.create_subscription(100, myhandler)
    _ = await sub.subscribe_data_change(v1)
    # Now check we get the start value
    node, val, _data = await myhandler.result()
    assert startv1 == val
    assert v1 == node
    myhandler.reset()  # reset future object
    # modify v1 and check we get value
    startv1.ProductUri = "BB"
    await v1.write_value(startv1)
    node, val, _data = await myhandler.result()
    assert v1 == node
    assert startv1 == val
    assert val.ProductUri == "BB"
    await sub.delete()  # should delete our monitoreditem too
    await opc.opc.delete_nodes([v1])


async def test_subscription_data_change_many(opc):
    """
    test subscriptions. This is far too complicated for
    a unittest but, setting up subscriptions requires a lot
    of code, so when we first set it up, it is best
    to test as many things as possible
    """
    myhandler = MySubHandler2()
    o = opc.opc.nodes.objects
    startv1 = True
    v1 = await o.add_variable(3, "SubscriptionVariableMany1", startv1)
    startv2 = [1.22, 1.65]
    v2 = await o.add_variable(3, "SubscriptionVariableMany2", startv2)
    sub = await opc.opc.create_subscription(100, myhandler)
    _handle1, _handle2 = await sub.subscribe_data_change([v1, v2])
    # Now check we get the start values
    nodes = [v1, v2]
    count = 0
    while not len(myhandler.results) > 1:
        count += 1
        await sleep(0.1)
        if count > 100:
            raise RuntimeError("Did not get result from subscription")
    for node, val in myhandler.results:
        assert node in nodes
        nodes.remove(node)
        if node == v1:
            assert val == startv1
        elif node == v2:
            assert val == startv2
        else:
            raise RuntimeError(f"Error node {node} is neither {v1} nor {v2}")
    await sub.delete()
    await opc.opc.delete_nodes([v1, v2])


@pytest.mark.parametrize(
    ("session_timeout", "period", "keep_alive", "lifetime"),
    [(3_600_000, 1000, 10, 300), (20_000, 1000, 5, 300), (3_600_000, 100, 100, 3000), (3_600_000, 0, 10, 300)],
)
async def test_cli10_create_subscription_uses_the_time_based_counts(
    session_timeout: int, period: int, keep_alive: int, lifetime: int
) -> None:
    """Part 4, 5.14.2.2: keep-alive about every 10 s (at most a quarter of the session timeout), lifetime 3x or more."""
    client = Client("opc.tcp://fake")
    client.session_timeout = session_timeout
    created: list[ua.CreateSubscriptionParameters] = []

    async def create_subscription(
        params: ua.CreateSubscriptionParameters, callback: object
    ) -> ua.CreateSubscriptionResult:
        created.append(params)
        return ua.CreateSubscriptionResult(
            SubscriptionId=1,
            RevisedPublishingInterval=params.RequestedPublishingInterval,
            RevisedLifetimeCount=params.RequestedLifetimeCount,
            RevisedMaxKeepAliveCount=params.RequestedMaxKeepAliveCount,
        )

    client.uaclient.session.create_subscription = create_subscription  # type: ignore[method-assign]
    await client.create_subscription(period)
    assert created[0].RequestedMaxKeepAliveCount == keep_alive
    assert created[0].RequestedLifetimeCount >= lifetime
    assert created[0].RequestedLifetimeCount >= 3 * keep_alive


async def test_subscribe_server_time(opc):
    """
    Test the subscription of the `Server_ServerStatus_CurrentTime` objects `Value` attribute.
    """
    myhandler = MySubHandler()
    server_time_node = opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
    sub = await opc.opc.create_subscription(200, myhandler)
    handle = await sub.subscribe_data_change(server_time_node)
    assert isinstance(handle, int)
    node, val, _data = await myhandler.result()
    assert server_time_node == node
    delta = datetime.now(UTC) - val
    assert delta < timedelta(seconds=2)
    await sub.unsubscribe(handle)
    await sub.delete()


async def test_modify_monitored_item(opc):
    """
    Test that the subscription of the `Server_ServerStatus_CurrentTime` object can be modified.
    """
    myhandler = MySubHandler()
    server_time_node = opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
    sub = await opc.opc.create_subscription(1000, myhandler)
    handle = await sub.subscribe_data_change(server_time_node)
    await myhandler.result()
    myhandler.reset()
    results = await sub.modify_monitored_item(handle, 2000)
    assert results
    assert len(results) == 1
    assert type(results[0]) is ua.MonitoredItemModifyResult
    assert results[0].RevisedSamplingInterval == 2000
    await sub.unsubscribe(handle)
    await sub.delete()


async def test_create_delete_subscription(opc):
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "SubscriptionVariable4", [1, 2, 3])
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handle = await sub.subscribe_data_change(v)
    await sleep(0.1)
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([v])


async def test_unsubscribe_two_objects_simultaneously(opc):
    """
    Test the subscription/unsub. of the `ServerStatus_StartTime` and `ServerStatus_State` objects.
    Unsubscribe from both Nodes simultaneously.
    """
    handler = MySubHandler2(limit=1)
    nodes = [
        opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_StartTime)),
        opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_State)),
    ]
    sub = await opc.opc.create_subscription(100, handler)
    handles = await sub.subscribe_data_change(nodes, queuesize=1)
    await handler.done()
    assert handler.results[0][0] == nodes[0]
    assert handler.results[1][0] == nodes[1]
    await sub.unsubscribe(handles)
    await sub.delete()


async def test_unsubscribe_two_objects_consecutively(opc):
    """
    Test the subscription/unsub. of the `ServerStatus_StartTime` and `ServerStatus_State` objects.
    Unsubscribe from both Nodes consecutively.
    """
    handler = MySubHandler2(limit=1)
    nodes = [
        opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_StartTime)),
        opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_State)),
    ]
    sub = await opc.opc.create_subscription(100, handler)
    handles = await sub.subscribe_data_change(nodes, queuesize=1)
    assert isinstance(handles, list)
    await handler.done()
    for handle in handles:
        await sub.unsubscribe(handle)
    await sub.delete()


async def test_subscribe_events(opc):
    sub = await opc.opc.create_subscription(100, MySubHandler())
    handle = await sub.subscribe_events()
    await sleep(0.1)
    await sub.unsubscribe(handle)
    await sub.delete()


async def test_subscribe_events_to_wrong_node(opc):
    sub = await opc.opc.create_subscription(100, MySubHandler())
    with pytest.raises(ua.UaStatusCodeError):
        _ = await sub.subscribe_events(opc.opc.get_node("i=85"))
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "VariableNoEventNofierAttribute", 4)
    with pytest.raises(ua.UaStatusCodeError):
        _ = await sub.subscribe_events(v)
    await sub.delete()
    await opc.opc.delete_nodes([v])


async def test_get_event_attributes_from_type_node_BaseEvent(opc):
    etype = opc.opc.get_node(ua.ObjectIds.BaseEventType)
    properties = await enginir_opcua.common.events.get_event_properties_from_type_node(etype)
    for child in await etype.get_properties():
        assert child in properties


async def test_get_event_attributes_from_type_node_AlarmConditionType(opc):
    alarmType = opc.opc.get_node(ua.ObjectIds.AlarmConditionType)
    ackType = opc.opc.get_node(ua.ObjectIds.AcknowledgeableConditionType)
    condType = opc.opc.get_node(ua.ObjectIds.ConditionType)
    baseType = opc.opc.get_node(ua.ObjectIds.BaseEventType)
    allProperties = await enginir_opcua.common.events.get_event_properties_from_type_node(alarmType)
    propertiesToCheck = await alarmType.get_properties()
    propertiesToCheck.extend(await ackType.get_properties())
    propertiesToCheck.extend(await condType.get_properties())
    propertiesToCheck.extend(await baseType.get_properties())
    for child in propertiesToCheck:
        assert child in allProperties
    allVariables = await enginir_opcua.common.events.get_event_variables_from_type_node(alarmType)
    variablesToCheck = await alarmType.get_variables()
    variablesToCheck.extend(await ackType.get_variables())
    variablesToCheck.extend(await condType.get_variables())
    variablesToCheck.extend(await baseType.get_variables())
    for child in await alarmType.get_variables():
        assert child in allVariables


async def test_get_filter(opc):
    auditType = opc.opc.get_node(ua.ObjectIds.AuditEventType)
    baseType = opc.opc.get_node(ua.ObjectIds.BaseEventType)
    properties = await baseType.get_properties()
    properties.extend(await auditType.get_properties())
    evfilter = await enginir_opcua.common.events.get_filter_from_event_type([auditType])
    # Check number of elements in select clause
    assert len(evfilter.SelectClauses) == len(properties)


async def test_get_filter_from_ConditionType(opc):
    condType = opc.opc.get_node(ua.ObjectIds.ConditionType)
    baseType = opc.opc.get_node(ua.ObjectIds.BaseEventType)
    properties = await baseType.get_properties()
    properties.extend(await condType.get_properties())
    variables = await baseType.get_variables()
    variables.extend(await condType.get_variables())
    subproperties = []
    for var in variables:
        subproperties.extend(await var.get_properties())
    evfilter = await enginir_opcua.common.events.get_filter_from_event_type([condType])
    # Check number of elements in select clause FIXME: broken since 1.0.5
    # assert len(evfilter.SelectClauses) == (len(properties) + len(variables) + len(subproperties) + 1)
    # Check browse path variable with property
    browsePathList = [o.BrowsePath for o in evfilter.SelectClauses if o.BrowsePath]
    browsePathEnabledState = [ua.uatypes.QualifiedName("EnabledState")]
    browsePathEnabledStateId = [ua.uatypes.QualifiedName("EnabledState"), ua.uatypes.QualifiedName("Id")]
    assert browsePathEnabledState in browsePathList
    assert browsePathEnabledStateId in browsePathList
    # Check for additional NodeId attribute, which is not directly contained in ConditionType
    assert len([o for o in evfilter.SelectClauses if o.AttributeId == ua.AttributeIds.NodeId]) == 1
    # The where clause asks the server for the type and its subtypes with OfType (Part 4, 7.7.3)
    element = evfilter.WhereClause.Elements[0]
    assert element.FilterOperator == ua.FilterOperator.OfType
    assert element.FilterOperands[0].Value.Value == condType.nodeid


async def test_get_event_contains_object(opc):
    """Shelving State is a object this should be in the filter list!"""
    alarm_type = opc.opc.get_node(ua.ObjectIds.AlarmConditionType)
    evfilter = await enginir_opcua.common.events.get_filter_from_event_type([alarm_type])
    browsePathList = [o.BrowsePath for o in evfilter.SelectClauses if o.BrowsePath]
    browsePathId = [ua.QualifiedName("ShelvingState"), ua.QualifiedName("CurrentState"), ua.QualifiedName("Id")]
    assert browsePathId in browsePathList


async def test_get_filter_typedefinitionid_is_defining_type(opc):
    """Select clauses must use the EventType that introduces each field (Part 4 SimpleAttributeOperand)."""
    alarm_type = opc.opc.get_node(ua.ObjectIds.AlarmConditionType)
    evfilter = await enginir_opcua.common.events.get_filter_from_event_type([alarm_type])
    type_by_path = {
        tuple(bp.Name for bp in op.BrowsePath): op.TypeDefinitionId for op in evfilter.SelectClauses if op.BrowsePath
    }
    expected = {
        ("EventId",): ua.ObjectIds.BaseEventType,
        ("Message",): ua.ObjectIds.BaseEventType,
        ("Severity",): ua.ObjectIds.BaseEventType,
        ("ConditionName",): ua.ObjectIds.ConditionType,
        ("BranchId",): ua.ObjectIds.ConditionType,
        ("EnabledState",): ua.ObjectIds.ConditionType,
        ("EnabledState", "Id"): ua.ObjectIds.ConditionType,
        ("Quality",): ua.ObjectIds.ConditionType,
        ("Comment",): ua.ObjectIds.ConditionType,
        ("AckedState",): ua.ObjectIds.AcknowledgeableConditionType,
        ("AckedState", "Id"): ua.ObjectIds.AcknowledgeableConditionType,
        ("ConfirmedState",): ua.ObjectIds.AcknowledgeableConditionType,
        ("ActiveState",): ua.ObjectIds.AlarmConditionType,
        ("ActiveState", "Id"): ua.ObjectIds.AlarmConditionType,
        ("InputNode",): ua.ObjectIds.AlarmConditionType,
    }
    for path, type_id in expected.items():
        assert type_by_path[path] == ua.NodeId(type_id)


async def test_get_event_from_type_node_CustomEvent(opc):
    etype = await opc.server.create_custom_event_type(
        2,
        "MyEvent",
        ua.ObjectIds.AuditEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    properties = await enginir_opcua.common.events.get_event_properties_from_type_node(etype)
    for child in await opc.opc.get_node(ua.ObjectIds.BaseEventType).get_properties():
        assert child in properties
    for child in await opc.opc.get_node(ua.ObjectIds.AuditEventType).get_properties():
        assert child in properties
    for child in await opc.opc.get_node(etype.nodeid).get_properties():
        assert child in properties
    assert await etype.get_child("2:PropertyNum") in properties
    assert await etype.get_child("2:PropertyString") in properties
    await opc.opc.delete_nodes([etype])


async def test_events_default(opc):
    evgen = await opc.server.get_event_generator()
    myhandler = MySubHandler()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events()
    tid = datetime.now(UTC)
    msg = "this is my msg "
    await evgen.trigger(tid, msg)
    ev = await myhandler.result()
    assert ev is not None  # we did not receive event
    assert ua.NodeId(ua.ObjectIds.BaseEventType) == ev.EventType
    assert 1 == ev.Severity
    assert (await opc.opc.nodes.server.read_browse_name()).Name == ev.SourceName
    assert opc.opc.nodes.server.nodeid == ev.SourceNode
    assert msg == ev.Message.Text
    assert tid == ev.Time
    await sub.unsubscribe(handle)
    await sub.delete()


async def test_events_MyObject(opc):
    objects = opc.server.nodes.objects
    o = await objects.add_object(3, "MyObject")
    evgen = await opc.server.get_event_generator(emitting_node=o)
    myhandler = MySubHandler()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events(o)
    tid = datetime.now(UTC)
    msg = "this is my msg "
    await evgen.trigger(tid, msg)
    ev = await myhandler.result()
    assert ev is not None  # we did not receive event
    assert ua.NodeId(ua.ObjectIds.BaseEventType) == ev.EventType
    assert 1 == ev.Severity
    assert "MyObject" == ev.SourceName
    assert o.nodeid == ev.SourceNode
    assert msg == ev.Message.Text
    assert tid == ev.Time
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([o])


async def test_srv23_events_of_any_source_reach_the_server_object(opc):
    """Part 3, 7.17: the Server Object has an implied HasEventSource to every source."""
    objects = opc.server.nodes.objects
    o = await objects.add_object(3, "MyObject")
    evgen = await opc.server.get_event_generator(emitting_node=o)
    myhandler = MySubHandler()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events()
    tid = datetime.now(UTC)
    msg = "this is my msg "
    await evgen.trigger(tid, msg)
    ev = await myhandler.result()
    assert ev.Message.Text == msg
    assert ev.SourceName == "MyObject"
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([o])


async def test_events_CustomEvent(opc):
    etype = await opc.server.create_custom_event_type(
        2,
        "MyEvent",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    evgen = await opc.server.get_event_generator(etype)
    myhandler = MySubHandler()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events(evtypes=etype)
    propertynum = 2
    propertystring = "This is my test"
    evgen.event.PropertyNum = propertynum
    evgen.event.PropertyString = propertystring
    serverity = 500
    evgen.event.Severity = serverity
    tid = datetime.now(UTC)
    msg = "this is my msg "
    await evgen.trigger(tid, msg)
    ev = await myhandler.result()
    assert ev is not None  # we did not receive event
    assert etype.nodeid == ev.EventType
    assert serverity == ev.Severity
    assert (await opc.opc.nodes.server.read_browse_name()).Name == ev.SourceName
    assert opc.opc.nodes.server.nodeid == ev.SourceNode
    assert msg == ev.Message.Text
    assert tid == ev.Time
    assert propertynum == ev.PropertyNum
    assert propertystring == ev.PropertyString
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([etype])


async def test_events_CustomEvent_CustomFilter(opc):
    etype = await opc.server.create_custom_event_type(
        2,
        "MyEventCustom",
        ua.ObjectIds.ProgramTransitionAuditEventType,
        [("NodeId", ua.VariantType.NodeId), ("PropertyString", ua.VariantType.String)],
    )
    # Create Custom Event filter including AttributeId.NodeId
    efilter = ua.EventFilter()
    browsePathes = [
        [ua.uatypes.QualifiedName("PropertyString", 2)],
        [ua.uatypes.QualifiedName("Transition"), ua.uatypes.QualifiedName("Id")],
        [ua.uatypes.QualifiedName("Message")],
        [ua.uatypes.QualifiedName("EventType")],
    ]
    # SelectClause
    for bp in browsePathes:
        op = ua.SimpleAttributeOperand()
        op.AttributeId = ua.AttributeIds.Value
        op.BrowsePath = bp
        efilter.SelectClauses.append(op)
    op = ua.SimpleAttributeOperand()  # For NodeId
    op.AttributeId = ua.AttributeIds.NodeId
    op.TypeDefinitionId = ua.NodeId(ua.ObjectIds.BaseEventType)
    efilter.SelectClauses.append(op)
    # WhereClause
    el = ua.ContentFilterElement()
    el.FilterOperator = ua.FilterOperator.OfType
    op = ua.LiteralOperand()
    op.Value = ua.Variant(etype.nodeid)  # Define type
    el.FilterOperands.append(op)
    efilter.WhereClause.Elements.append(el)
    # Create Subscription
    myhandler = MySubHandler()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events(evtypes=etype, evfilter=efilter)
    # Create Custom Event
    evgen = await opc.server.get_event_generator(etype)
    propertystring = "This is my test"
    msg = "this is my msg "
    myNodeId = ua.NodeId(8)
    transId = ua.NodeId(99)
    evgen.event.PropertyString = propertystring
    evgen.event.Message = ua.LocalizedText(msg)
    evgen.event.NodeId = myNodeId
    setattr(evgen.event, "Transition/Id", transId)
    # Fire Custom Event
    await evgen.trigger()
    ev = await myhandler.result()
    # Perform tests
    assert ev is not None  # we did not receive event
    assert etype.nodeid == ev.EventType
    assert msg == ev.Message.Text
    assert propertystring == ev.PropertyString
    assert myNodeId == ev.NodeId
    assert transId == getattr(ev, "Transition/Id")
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([etype])


async def test_events_CustomEvent_MyObject(opc):
    objects = opc.server.nodes.objects
    o = await objects.add_object(3, "MyObject")
    etype = await opc.server.create_custom_event_type(
        2,
        "MyEvent",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    evgen = await opc.server.get_event_generator(etype, emitting_node=o)
    myhandler = MySubHandler()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events(o, etype)
    propertynum = 2
    propertystring = "This is my test"
    evgen.event.PropertyNum = propertynum
    evgen.event.PropertyString = propertystring
    tid = datetime.now(UTC)
    msg = "this is my msg "
    await evgen.trigger(tid, msg)
    ev = await myhandler.result()
    assert ev is not None  # we did not receive event
    assert etype.nodeid == ev.EventType
    assert 1 == ev.Severity
    assert "MyObject" == ev.SourceName
    assert o.nodeid == ev.SourceNode
    assert msg == ev.Message.Text
    assert tid == ev.Time
    assert propertynum == ev.PropertyNum
    assert propertystring == ev.PropertyString
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([etype, o])


async def test_several_different_events(opc):
    objects = opc.server.nodes.objects
    o = await objects.add_object(3, "MyObject")
    etype1 = await opc.server.create_custom_event_type(
        2,
        "MyEvent1",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    evgen1 = await opc.server.get_event_generator(etype1, o)
    etype2 = await opc.server.create_custom_event_type(
        2,
        "MyEvent2",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    evgen2 = await opc.server.get_event_generator(etype2, o)
    myhandler = MySubHandler2()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events(o, etype1)
    propertynum1 = 1
    propertystring1 = "This is my test 1"
    evgen1.event.PropertyNum = propertynum1
    evgen1.event.PropertyString = propertystring1
    propertynum2 = 2
    propertystring2 = "This is my test 2"
    evgen2.event.PropertyNum = propertynum2
    evgen2.event.PropertyString = propertystring2
    for i in range(3):
        await evgen1.trigger()
        await evgen2.trigger()
    await wait_until(lambda: len(myhandler.results) >= 3)
    assert 3 == len(myhandler.results)
    ev = myhandler.results[-1]
    assert etype1.nodeid == ev.EventType
    handle = await sub.subscribe_events(o, etype2)
    for i in range(4):
        await evgen1.trigger()
        await evgen2.trigger()
    await wait_until(lambda: len(myhandler.results) >= 11)
    ev1s = [ev for ev in myhandler.results if ev.EventType == etype1.nodeid]
    ev2s = [ev for ev in myhandler.results if ev.EventType == etype2.nodeid]
    assert 11 == len(myhandler.results)
    assert 4 == len(ev2s)
    assert 7 == len(ev1s)
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([etype1, etype2])
    await opc.opc.delete_nodes([o])


async def test_several_different_events_2(opc):
    objects = opc.server.nodes.objects
    o = await objects.add_object(3, "MyObject")
    etype1 = await opc.server.create_custom_event_type(
        2,
        "MyEvent1",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    evgen1 = await opc.server.get_event_generator(etype1, o)
    etype2 = await opc.server.create_custom_event_type(
        2,
        "MyEvent2",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum2", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    evgen2 = await opc.server.get_event_generator(etype2, o)
    etype3 = await opc.server.create_custom_event_type(
        2,
        "MyEvent3",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum3", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    evgen3 = await opc.server.get_event_generator(etype3, o)
    myhandler = MySubHandler2()
    sub = await opc.opc.create_subscription(100, myhandler)
    handle = await sub.subscribe_events(o, [etype1, etype3])
    propertynum1 = 1
    propertystring1 = "This is my test 1"
    evgen1.event.PropertyNum = propertynum1
    evgen1.event.PropertyString = propertystring1
    propertynum2 = 2
    propertystring2 = "This is my test 2"
    evgen2.event.PropertyNum2 = propertynum2
    evgen2.event.PropertyString = propertystring2
    propertynum3 = 3
    propertystring3 = "This is my test 3"
    evgen3.event.PropertyNum3 = propertynum3
    evgen3.event.PropertyString = propertystring3
    for i in range(3):
        await evgen1.trigger()
        await evgen2.trigger()
        await evgen3.trigger()
    evgen3.event.PropertyNum3 = 9999
    await evgen3.trigger()
    await wait_until(lambda: len(myhandler.results) >= 7)
    ev1s = [ev for ev in myhandler.results if ev.EventType == etype1.nodeid]
    ev2s = [ev for ev in myhandler.results if ev.EventType == etype2.nodeid]
    ev3s = [ev for ev in myhandler.results if ev.EventType == etype3.nodeid]
    assert 7 == len(myhandler.results)
    assert 3 == len(ev1s)
    assert 0 == len(ev2s)
    assert 4 == len(ev3s)
    assert propertynum1 == ev1s[0].PropertyNum
    assert propertynum3 == ev3s[0].PropertyNum3
    assert 9999 == ev3s[-1].PropertyNum3
    assert ev1s[0].PropertyNum3 is None
    await sub.unsubscribe(handle)
    await sub.delete()
    await opc.opc.delete_nodes([etype1, etype2, etype3])
    await opc.opc.delete_nodes([o])


async def test_internal_server_subscription(opc):
    """
    Test that an internal server subscription is handled correctly when
    data of a node changes (by external client and internally).
    """
    sub_handler = MySubHandler2()
    uri = "http://examples.freeopcua.github.io"
    idx = await opc.server.register_namespace(uri)
    objects = opc.server.nodes.objects
    sub_obj = await objects.add_object(idx, "SubTestObject")
    sub_var = await sub_obj.add_variable(idx, "SubTestVariable", 0)
    await sub_var.set_writable()
    sub = await opc.server.create_subscription(1, sub_handler)
    # Server subscribes to own variable data changes
    await sub.subscribe_data_change([sub_var], queuesize=100)
    client_var = await opc.opc.nodes.objects.get_child([f"{idx}:SubTestObject", f"{idx}:SubTestVariable"])
    for i in range(10):
        await client_var.write_value(i)
        await asyncio.sleep(0.01)
    async with asyncio.timeout(5):
        while len(sub_handler.results) < 10:
            await asyncio.sleep(0.01)
    assert [v for n, v in sub_handler.results] == list(range(10))
    internal_sub = opc.server.iserver.subscription_service.subscriptions[sub.subscription_id]
    # Check that the results are not left un-acknowledged on internal Server Subscriptions.
    assert len(internal_sub._not_acknowledged_results) == 0
    await opc.opc.delete_nodes([sub_obj])
    await sub.delete()


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_publish_without_subscription(opc):
    assert opc.server.iserver.subscription_service.subscriptions == {}, (
        "Some prior test has left subscriptions on the server"
    )
    with pytest.raises(ua.UaStatusCodeError) as excinfo:
        _ = await opc.opc.uaclient.session.publish([])
    assert excinfo.value.code == ua.StatusCodes.BadNoSubscription


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_too_many_publish(opc, mocker):
    assert opc.server.iserver.subscription_service.subscriptions == {}, (
        "Some prior test has left subscriptions on the server"
    )
    mocker.patch.object(opc.opc.uaclient.session, "ensure_publish_loop", lambda: None)
    sub_handler = MySubHandler()
    sub = await opc.opc.create_subscription(500, sub_handler)
    try:
        requests = [asyncio.create_task(opc.opc.uaclient.session.publish([])) for _ in range(11)]
        while True:
            done, pending = await asyncio.wait(requests, timeout=5, return_when=asyncio.FIRST_COMPLETED)
            for task in [task for task in requests if task in done]:
                exception = task.exception()
                if exception is None:
                    requests.remove(task)
                    requests.append(asyncio.create_task(opc.opc.uaclient.session.publish([])))
                else:
                    assert isinstance(exception, ua.UaStatusCodeError)
                    assert exception.code == ua.StatusCodes.BadTooManyPublishRequests
                    assert task is requests[0]
                    break
            else:
                continue
            for task in pending:
                task.cancel()
            break
    finally:
        await sub.delete()


@pytest.mark.parametrize("opc", ["client"], indirect=True, scope="function")
async def test_timeout_publish(opc, mocker):
    mocker.patch.object(opc.opc.uaclient.session, "ensure_publish_loop", lambda: None)

    sub_handler = MySubHandler()
    sub = await opc.opc.create_subscription(1000, sub_handler)

    o = opc.opc.nodes.objects
    var = await o.add_variable(3, "SubVarPublishTimeout", -1)
    try:
        await sub.subscribe_data_change(var)

        protocol = opc.opc.uaclient.protocol
        assert protocol is not None

        for value in range(2):
            request = ua.PublishRequest()
            fut = protocol._send_request(request, 0.001, ua.MessageType.SecureMessage)

            done, _ = await asyncio.wait([fut], return_when=asyncio.FIRST_COMPLETED, timeout=1)
            if done:
                data = fut.result()
            else:
                await var.write_value(value)
                data = await asyncio.wait_for(fut, timeout=5)
            typeid = nodeid_from_binary(data)
            if typeid.Identifier != ua.ObjectIds.PublishResponse_Encoding_DefaultBinary:
                break
        header = struct_from_binary(ua.ResponseHeader, data)
        assert header.ServiceResult.value == ua.StatusCodes.BadTimeout
    finally:
        await sub.delete()
        await opc.opc.delete_nodes([var])


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_subscription_lifetime_count_is_clamped(opc):
    """Server must cap RequestedLifetimeCount so an orphaned subscription cannot live forever."""
    cap = opc.server.iserver.max_lifetime_count
    sub = await opc.opc.create_subscription(
        ua.CreateSubscriptionParameters(
            RequestedPublishingInterval=100,
            RequestedLifetimeCount=cap * 100,
            RequestedMaxKeepAliveCount=10,
            MaxNotificationsPerPublish=10,
            PublishingEnabled=True,
            Priority=0,
        )
    )
    try:
        internal = opc.server.iserver.subscription_service.subscriptions[sub.subscription_id]
        assert internal.data.RevisedLifetimeCount == cap
    finally:
        await sub.delete()


@pytest.mark.parametrize("opc", ["client"], indirect=True)
async def test_create_subscription_rejected_past_cap(opc):
    """CreateSubscription must return BadTooManySubscriptions past iserver.max_subscriptions."""
    iserver = opc.server.iserver
    original_cap = iserver.max_subscriptions
    iserver.max_subscriptions = 1
    sub = await opc.opc.create_subscription(50)
    try:
        with pytest.raises(ua.UaStatusCodeError) as exc:
            await opc.opc.create_subscription(50)
        assert exc.value.code == ua.StatusCodes.BadTooManySubscriptions
    finally:
        iserver.max_subscriptions = original_cap
        await sub.delete()


class _FakeSession:
    def __init__(self, create_items):
        self._create_items = create_items
        self.recreated_with = []

    async def create_subscription(self, params, callback):
        result = ua.CreateSubscriptionResult()
        result.SubscriptionId = 7
        result.RevisedPublishingInterval = params.RequestedPublishingInterval
        result.RevisedLifetimeCount = params.RequestedLifetimeCount
        result.RevisedMaxKeepAliveCount = params.RequestedMaxKeepAliveCount
        return result

    async def create_monitored_items(self, params):
        return await self._create_items(params)


def _make_subscription(session) -> Subscription:
    params = ua.CreateSubscriptionParameters()
    params.RequestedPublishingInterval = 100
    params.RequestedLifetimeCount = 3000
    params.RequestedMaxKeepAliveCount = 1000
    return Subscription(session, params, MySubHandler())


def _item_request(client_handle: int) -> ua.MonitoredItemCreateRequest:
    mir = ua.MonitoredItemCreateRequest()
    mir.ItemToMonitor = ua.ReadValueId()
    mir.ItemToMonitor.NodeId = ua.NodeId(85, 0)
    mir.ItemToMonitor.AttributeId = ua.AttributeIds.Value
    mir.MonitoringMode = ua.MonitoringMode.Reporting
    mir.RequestedParameters = ua.MonitoringParameters()
    mir.RequestedParameters.ClientHandle = client_handle
    return mir


async def test_failed_create_monitored_items_leaves_no_items():
    async def failing(params):
        raise ua.UaStatusCodeError(ua.StatusCodes.BadSubscriptionIdInvalid)

    session = _FakeSession(failing)
    sub = _make_subscription(session)
    await sub.init()

    with pytest.raises(ua.UaStatusCodeError):
        await sub.create_monitored_items([_item_request(201)])

    assert sub._monitored_items == {}


async def test_recreate_completes_while_a_create_call_is_stuck():
    release = asyncio.Event()
    calls = []

    async def first_call_hangs(params):
        calls.append(params)
        if len(calls) == 1:
            await release.wait()
        return [ua.MonitoredItemCreateResult() for _ in params.ItemsToCreate]

    session = _FakeSession(first_call_hangs)
    sub = _make_subscription(session)
    await sub.init()

    stuck = asyncio.create_task(sub.create_monitored_items([_item_request(201)]))
    await asyncio.sleep(0)

    await asyncio.wait_for(sub.recreate(), timeout=3)

    release.set()
    with pytest.raises(ua.UaStatusCodeError):
        await stuck
    assert sub._monitored_items == {}, "the stale call leaves nothing behind"


async def test_recreate_does_not_adopt_items_of_a_failing_call():
    release = asyncio.Event()

    async def scripted(params):
        if not release.is_set():
            await release.wait()
            raise ua.UaStatusCodeError(ua.StatusCodes.BadSubscriptionIdInvalid)
        session.recreated_with.append([mi.RequestedParameters.ClientHandle for mi in params.ItemsToCreate])
        return [ua.MonitoredItemCreateResult() for _ in params.ItemsToCreate]

    session = _FakeSession(scripted)
    sub = _make_subscription(session)
    await sub.init()

    doomed = asyncio.create_task(sub.create_monitored_items([_item_request(201)]))
    await asyncio.sleep(0)
    recreate = asyncio.create_task(sub.recreate())
    await asyncio.sleep(0)
    release.set()

    with pytest.raises(ua.UaStatusCodeError):
        await doomed
    await recreate

    assert sub._monitored_items == {}
    assert session.recreated_with in ([], [[]])


SESSION = ua.NodeId(1, 1)


@pytest.fixture
async def iserver() -> AsyncIterator[InternalServer]:
    server = InternalServer()
    yield server
    for sub in list(server.subscription_service.subscriptions.values()):
        await sub.stop()
    server.subscription_service.subscriptions.clear()


def create_params(interval: float = 100, lifetime: int = 30, keepalive: int = 10) -> ua.CreateSubscriptionParameters:
    return ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=interval,
        RequestedLifetimeCount=lifetime,
        RequestedMaxKeepAliveCount=keepalive,
        MaxNotificationsPerPublish=0,
        PublishingEnabled=True,
        Priority=0,
    )


async def create(iserver: InternalServer, params: ua.CreateSubscriptionParameters) -> ua.CreateSubscriptionResult:
    return await iserver.subscription_service.create_subscription(
        params, AsyncMock(), SESSION, request_callback=lambda _id: None
    )


@pytest.mark.parametrize("requested", [0.0, -5.0, float("nan"), 1.0])
async def test_srv11_publishing_interval_below_the_minimum_is_revised_up(
    iserver: InternalServer, requested: float
) -> None:
    """Part 4, 5.14.2.2: the server revises the interval to the fastest one it supports."""
    result = await create(iserver, create_params(interval=requested))
    assert result.RevisedPublishingInterval == iserver.min_publishing_interval_ms


async def test_srv11_publishing_interval_is_clamped_to_the_maximum(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the server revises the interval to the slowest one it supports."""
    result = await create(iserver, create_params(interval=1e9, lifetime=3, keepalive=1))
    assert result.RevisedPublishingInterval == iserver.max_publishing_interval_ms


async def test_srv33_keepalive_zero_becomes_one(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: a keep-alive count of 0 is revised to the smallest supported count."""
    result = await create(iserver, create_params(keepalive=0))
    assert result.RevisedMaxKeepAliveCount == 1


async def test_srv33_lifetime_is_at_least_three_times_keepalive(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the lifetime count is revised to at least three times the keep-alive count."""
    result = await create(iserver, create_params(lifetime=1, keepalive=5))
    assert result.RevisedLifetimeCount == 15


async def test_srv33_interval_times_lifetime_is_capped(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the server may lower the lifetime so an abandoned subscription does not live for days."""
    iserver.max_subscription_lifetime_ms = 60_000
    result = await create(iserver, create_params(interval=1000, lifetime=1000, keepalive=2))
    assert result.RevisedLifetimeCount == 60
    assert result.RevisedLifetimeCount * result.RevisedPublishingInterval <= 60_000


async def test_srv33_lifetime_cap_lowers_keepalive_when_three_times_it_does_not_fit(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the lifetime count stays at least three times the keep-alive count."""
    iserver.max_subscription_lifetime_ms = 60_000
    result = await create(iserver, create_params(interval=10_000, lifetime=1000, keepalive=100))
    assert result.RevisedLifetimeCount >= 3 * result.RevisedMaxKeepAliveCount
    assert result.RevisedLifetimeCount * result.RevisedPublishingInterval <= 60_000


async def test_srv11_modify_applies_revised_values(iserver: InternalServer) -> None:
    """Part 4, 5.14.3.2: ModifySubscription revises and applies the new parameters."""
    created = await create(iserver, create_params(interval=100, lifetime=30, keepalive=10))
    modify = ua.ModifySubscriptionParameters(
        SubscriptionId=created.SubscriptionId,
        RequestedPublishingInterval=0,
        RequestedLifetimeCount=1,
        RequestedMaxKeepAliveCount=0,
        MaxNotificationsPerPublish=7,
        Priority=9,
    )
    result = iserver.subscription_service.modify_subscription(modify, SESSION)
    assert result.RevisedPublishingInterval == iserver.min_publishing_interval_ms
    assert result.RevisedMaxKeepAliveCount == 1
    assert result.RevisedLifetimeCount == 3
    sub = iserver.subscription_service.subscriptions[created.SubscriptionId]
    assert sub.data.RevisedPublishingInterval == result.RevisedPublishingInterval
    assert sub.max_notifications_per_publish == 7
    assert sub.priority == 9


"""Tests for the async-iterator subscription API."""


async def _start_server(port: int) -> Server:
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await srv.start()
    return srv


async def test_iterator_yields_data_changes() -> None:
    """Iterator-mode subscription yields DataChangeEvent for monitored variable writes."""
    port = find_free_port()
    srv = await _start_server(port)
    objects = srv.get_objects_node()
    var = await objects.add_variable(2, "IterVar", 0)
    await var.set_writable()

    client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=1.0, watchdog_intervall=0.3)
    await client.connect()
    try:
        sub = await client.create_subscription(50)  # no handler -> iterator mode
        async with sub:
            await sub.subscribe_data_change(client.get_node(var.nodeid))
            # First arrival is the initial value (0).
            first = await asyncio.wait_for(sub.next_event(), timeout=3.0)
            assert isinstance(first, DataChangeEvent)
            assert first.value == 0
            # Then writes propagate as DataChangeEvents.
            await var.write_value(7)
            seen: list[int] = []
            while 7 not in seen:
                ev = await asyncio.wait_for(sub.next_event(), timeout=3.0)
                if isinstance(ev, DataChangeEvent):
                    seen.append(ev.value)
            assert 7 in seen
    finally:
        await client.disconnect()
        await srv.stop()


async def test_iterator_async_for_loop_exits_on_delete() -> None:
    """`async for ev in sub` ends cleanly when the subscription is deleted."""
    port = find_free_port()
    srv = await _start_server(port)
    objects = srv.get_objects_node()
    var = await objects.add_variable(2, "IterVar2", 0)
    await var.set_writable()

    client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=1.0, watchdog_intervall=0.3)
    await client.connect()
    try:
        sub = await client.create_subscription(50)
        await sub.subscribe_data_change(client.get_node(var.nodeid))
        consumed: list[object] = []
        pending: list[asyncio.Task[None]] = []

        async def consumer() -> None:
            async for ev in sub:
                consumed.append(ev)
                if isinstance(ev, DataChangeEvent) and ev.value == 1:
                    # Trigger delete from inside the loop (a common pattern).
                    pending.append(asyncio.create_task(sub.delete()))

        consumer_task = asyncio.create_task(consumer())
        # Wait for initial value, then poke a new one to trigger delete.
        await asyncio.sleep(0.2)
        await var.write_value(1)
        await asyncio.wait_for(consumer_task, timeout=3.0)
        # consumer ended naturally via StopAsyncIteration; loop got at least
        # the initial value (0) and the trigger value (1).
        assert any(isinstance(ev, DataChangeEvent) and ev.value == 1 for ev in consumed)
    finally:
        await srv.stop()


async def test_iterator_context_manager_deletes_on_exit() -> None:
    """`async with sub:` exit deletes the server-side subscription."""
    port = find_free_port()
    srv = await _start_server(port)
    client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=1.0, watchdog_intervall=0.3)
    await client.connect()
    try:
        sub = await client.create_subscription(50)
        assert sub.is_deleted is False
        async with sub:
            assert sub.subscription_id is not None
        assert sub.is_deleted is True
    finally:
        await client.disconnect()
        await srv.stop()


async def test_iterator_rejects_handler_mode() -> None:
    """Trying to iterate a handler-mode subscription is a hard error."""
    port = find_free_port()
    srv = await _start_server(port)

    class _Noop:
        def datachange_notification(self, _n, _v, _d) -> None:
            pass

    client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=1.0, watchdog_intervall=0.3)
    await client.connect()
    try:
        sub = await client.create_subscription(50, _Noop())
        with pytest.raises(RuntimeError, match="handler mode"):
            sub.__aiter__()
        await sub.delete()
    finally:
        await client.disconnect()
        await srv.stop()


"""Monitored item bookkeeping of the client Subscription (modify, revised values)."""


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

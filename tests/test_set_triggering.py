"""SetTriggering and the triggering behaviour of monitored items."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import utils

from .conftest import find_free_port
from .harness import SessionProbe
from .monitoring import SESSION, create_items, item_request, make_server, open_subscription, publish

MODE = ua.MonitoringMode


@pytest.fixture(scope="module")
async def server() -> AsyncIterator[Server]:
    srv = await make_server()
    yield srv


async def variable(server: Server, name: str) -> ua.NodeId:
    return (await server.nodes.objects.add_variable(2, name, 0)).nodeid


async def write(server: Server, nodeid: ua.NodeId, value: int) -> None:
    dv = ua.DataValue(ua.Variant(value, ua.VariantType.Int64))
    await server.iserver.aspace.write_attribute_value(nodeid, ua.AttributeIds.Value, dv)


async def set_triggering(
    server: Server, sub: Any, triggering: int, add: list[int], remove: list[int] | None = None
) -> ua.SetTriggeringResult:
    params = ua.SetTriggeringParameters(
        SubscriptionId=sub.data.SubscriptionId,
        TriggeringItemId=triggering,
        LinksToAdd=add,
        LinksToRemove=remove or [],
    )
    return await server.iserver.subscription_service.set_triggering(params, SESSION)


async def linked_pair(
    server: Server, name: str, trigger_mode: ua.MonitoringMode = MODE.Sampling
) -> tuple[Any, Any, ua.NodeId, ua.NodeId, int, int]:
    triggering_node, linked_node = await variable(server, f"{name}Trigger"), await variable(server, f"{name}Linked")
    sub, wire = await open_subscription(server)
    trigger, linked = await create_items(
        server,
        sub,
        item_request(triggering_node, mode=trigger_mode, queue=5, handle=1),
        item_request(linked_node, mode=MODE.Sampling, queue=5, handle=2),
    )
    await publish(sub, wire)
    return sub, wire, triggering_node, linked_node, trigger.MonitoredItemId, linked.MonitoredItemId


def handles(notifications: list[Any]) -> list[int]:
    return [n.ClientHandle for n in notifications]


async def test_srv19_a_notification_of_the_triggering_item_reports_the_queued_values_of_a_sampling_item(
    server: Server,
) -> None:
    """Part 4, 5.13.1.6 and 5.13.5: the linked item reports what it queued, once."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Reports")
    result = await set_triggering(server, sub, trigger, [linked])
    assert [code.value for code in result.AddResults] == [ua.StatusCodes.Good]
    await write(server, linked_node, 1)
    await write(server, linked_node, 2)
    assert await publish(sub, wire) == []
    await write(server, trigger_node, 7)
    notifications = await publish(sub, wire)
    assert handles(notifications) == [2, 2, 2]
    await write(server, linked_node, 3)
    assert await publish(sub, wire) == []


async def test_srv19_a_triggering_item_in_reporting_mode_is_reported_too(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(
        server, "ReportingTrigger", MODE.Reporting
    )
    await set_triggering(server, sub, trigger, [linked])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [1, 2, 2]


async def test_srv19_a_disabled_triggering_item_triggers_nothing(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "DisabledTrigger")
    await set_triggering(server, sub, trigger, [linked])
    await sub.monitored_item_srv.set_monitoring_mode(MODE.Disabled, [trigger])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert await publish(sub, wire) == []


async def test_srv19_a_reporting_linked_item_is_not_affected(server: Server) -> None:
    """Part 4, 5.13.1.6: it reports on its own."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "ReportingLinked")
    await sub.monitored_item_srv.set_monitoring_mode(MODE.Reporting, [linked])
    await publish(sub, wire)
    await set_triggering(server, sub, trigger, [linked])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [2]


async def test_srv19_the_trigger_does_not_follow_links_of_linked_items(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, _, trigger, linked = await linked_pair(server, "Chain")
    third_node = await variable(server, "ChainThird")
    [third] = await create_items(server, sub, item_request(third_node, mode=MODE.Sampling, queue=5, handle=3))
    await publish(sub, wire)
    await set_triggering(server, sub, trigger, [linked])
    await set_triggering(server, sub, linked, [third.MonitoredItemId])
    await write(server, third_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [2]


async def test_srv19_links_to_remove_are_processed_before_links_to_add(server: Server) -> None:
    """Part 4, 5.13.5.2."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Order")
    await set_triggering(server, sub, trigger, [linked])
    result = await set_triggering(server, sub, trigger, [linked], [linked])
    assert [code.value for code in result.RemoveResults] == [ua.StatusCodes.Good]
    assert [code.value for code in result.AddResults] == [ua.StatusCodes.Good]
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert handles(await publish(sub, wire)) == [2, 2]


async def test_srv19_removed_links_stop_triggering(server: Server) -> None:
    """Part 4, 5.13.5."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Removed")
    await set_triggering(server, sub, trigger, [linked])
    await set_triggering(server, sub, trigger, [], [linked])
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert await publish(sub, wire) == []


async def test_srv19_each_entry_has_its_own_result(server: Server) -> None:
    """Part 4, 5.13.5.2 and 5.13.5.3."""
    sub, _, _, _, trigger, linked = await linked_pair(server, "Results")
    result = await set_triggering(server, sub, trigger, [linked, 9999, trigger, linked], [8888])
    invalid = ua.StatusCodes.BadMonitoredItemIdInvalid
    assert [code.value for code in result.AddResults] == [ua.StatusCodes.Good, invalid, invalid, ua.StatusCodes.Good]
    assert [code.value for code in result.RemoveResults] == [invalid]


async def test_srv19_service_level_errors(server: Server) -> None:
    """Part 4, 5.13.5.3: unknown triggering item, nothing to do."""
    sub, _, _, _, trigger, linked = await linked_pair(server, "ServiceErrors")
    with pytest.raises(utils.ServiceError) as unknown:
        await set_triggering(server, sub, 9999, [linked])
    assert unknown.value.code == ua.StatusCodes.BadMonitoredItemIdInvalid
    with pytest.raises(utils.ServiceError) as nothing:
        await set_triggering(server, sub, trigger, [])
    assert nothing.value.code == ua.StatusCodes.BadNothingToDo
    params = ua.SetTriggeringParameters(SubscriptionId=123456, TriggeringItemId=trigger, LinksToAdd=[linked])
    with pytest.raises(utils.ServiceError) as no_subscription:
        await server.iserver.subscription_service.set_triggering(params, SESSION)
    assert no_subscription.value.code == ua.StatusCodes.BadSubscriptionIdInvalid


async def test_srv19_deleting_an_item_deletes_its_links(server: Server) -> None:
    """Part 4, 5.13.1.6."""
    sub, wire, trigger_node, linked_node, trigger, linked = await linked_pair(server, "Deleted")
    await set_triggering(server, sub, trigger, [linked])
    sub.monitored_item_srv.delete_monitored_items([linked])
    assert sub.monitored_item_srv._monitored_items[trigger].links == set()
    [again] = await create_items(server, sub, item_request(linked_node, mode=MODE.Sampling, queue=5, handle=5))
    await publish(sub, wire)
    await write(server, linked_node, 1)
    await write(server, trigger_node, 7)
    assert await publish(sub, wire) == []
    assert again.StatusCode.is_good()


async def test_srv19_set_triggering_is_served_over_the_wire() -> None:
    """Part 4, 5.13.5: the request reaches the service through the dispatch table."""
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await srv.start()
    probe = await SessionProbe.open(srv.endpoint.geturl())
    try:
        token = (await probe.create_session()).AuthenticationToken
        await probe.activate(token)
        nodes = [(await srv.nodes.objects.add_variable(2, f"Wire{n}", 0)).nodeid for n in range(2)]
        subscription = ua.CreateSubscriptionRequest()
        subscription.Parameters.RequestedPublishingInterval = 1000
        subscription.Parameters.RequestedLifetimeCount = 300
        subscription.Parameters.RequestedMaxKeepAliveCount = 100
        created = await probe.send(token, subscription, ua.CreateSubscriptionResponse)
        items = ua.CreateMonitoredItemsRequest()
        items.Parameters.SubscriptionId = created.Parameters.SubscriptionId
        items.Parameters.ItemsToCreate = [item_request(node, handle=n + 1) for n, node in enumerate(nodes)]
        monitored = await probe.send(token, items, ua.CreateMonitoredItemsResponse)
        first, second = (result.MonitoredItemId for result in monitored.Results)
        request = ua.SetTriggeringRequest()
        request.Parameters = ua.SetTriggeringParameters(
            SubscriptionId=created.Parameters.SubscriptionId, TriggeringItemId=first, LinksToAdd=[second]
        )
        response = await probe.send(token, request, ua.SetTriggeringResponse)
        assert [code.value for code in response.Parameters.AddResults] == [ua.StatusCodes.Good]
    finally:
        probe.close()
        await srv.stop()

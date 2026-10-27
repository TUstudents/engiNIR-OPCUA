"""Creation and modification of monitored items."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from enginir_opcua import Server, ua

from .monitoring import SLOW, create_items, item_request, make_server, modify_items, open_subscription


@pytest.fixture(scope="module")
async def server() -> AsyncIterator[Server]:
    srv = await make_server()
    yield srv


async def new_variable(server: Server, name: str, value: int = 1) -> ua.NodeId:
    node = await server.nodes.objects.add_variable(2, name, value)
    return node.nodeid


@pytest.mark.parametrize(
    "requested, revised", [(0, 1), (1, 1), (5, 5), (1000, 1000), (5000, 1000), (4_294_967_295, 1000)]
)
async def test_srv13_queue_size_of_a_data_item_is_revised(server: Server, requested: int, revised: int) -> None:
    """Part 4, 7.21: a data item's queue size 0 or 1 gives 1; the server limits the maximum."""
    nodeid = await new_variable(server, f"QueueRevision{requested}")
    sub, _ = await open_subscription(server)
    [result] = await create_items(server, sub, item_request(nodeid, queue=requested))
    assert result.StatusCode.is_good()
    assert result.RevisedQueueSize == revised


@pytest.mark.parametrize(
    "requested, revised",
    [(-1.0, SLOW), (0.0, 10.0), (1.0, 10.0), (250.0, 250.0), (7_200_000.0, 3_600_000.0), (float("nan"), SLOW)],
)
async def test_srv13_sampling_interval_is_revised(server: Server, requested: float, revised: float) -> None:
    """Part 4, 5.13.1.2 and 7.21: negative means the publishing interval, 0 the fastest, bounds apply."""
    nodeid = await new_variable(server, f"SamplingRevision{requested}")
    sub, _ = await open_subscription(server)
    [result] = await create_items(server, sub, item_request(nodeid, sampling=requested))
    assert result.RevisedSamplingInterval == revised


async def test_srv13_modify_revises_queue_size_and_sampling_interval(server: Server) -> None:
    """Part 4, 5.13.3: Modify revises the parameters like Create does."""
    nodeid = await new_variable(server, "ModifyRevision")
    sub, _ = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, queue=5, sampling=500))
    params = ua.MonitoringParameters(ClientHandle=2, SamplingInterval=0, QueueSize=50_000, DiscardOldest=True)
    [result] = modify_items(server, sub, (created.MonitoredItemId, params))
    assert result.StatusCode.is_good()
    assert result.RevisedQueueSize == 1000
    assert result.RevisedSamplingInterval == 10.0


async def test_srv13_modify_with_an_unknown_id_fails_only_that_item(server: Server) -> None:
    """Part 4, 5.13.3.3: errors are per item, Bad_MonitoredItemIdInvalid for an unknown id."""
    nodeid = await new_variable(server, "ModifyUnknown")
    sub, _ = await open_subscription(server)
    [created] = await create_items(server, sub, item_request(nodeid, queue=5))
    params = ua.MonitoringParameters(ClientHandle=2, SamplingInterval=100, QueueSize=7, DiscardOldest=True)
    unknown, known = modify_items(server, sub, (9999, params), (created.MonitoredItemId, params))
    assert unknown.StatusCode.value == ua.StatusCodes.BadMonitoredItemIdInvalid
    assert known.StatusCode.is_good()
    assert known.RevisedQueueSize == 7


async def test_srv13_an_unknown_node_fails_only_its_item(server: Server) -> None:
    """Part 4, 5.13.2.3: Bad_NodeIdUnknown is the status of the item, the others are created."""
    nodeid = await new_variable(server, "OneBadOneGood")
    sub, _ = await open_subscription(server)
    bad, good = await create_items(
        server, sub, item_request(ua.NodeId(424242, 2), handle=1), item_request(nodeid, handle=2)
    )
    assert bad.StatusCode.value == ua.StatusCodes.BadNodeIdUnknown
    assert good.StatusCode.is_good()

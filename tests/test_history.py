import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from enginir_opcua import ua
from enginir_opcua.common.node import Node

pytestmark = pytest.mark.asyncio


async def test_history_var_read_one(history_server):
    """
    no start and no end is not defined by spec, return reverse order
    Spec says that at least two parameters should be provided, so this one is out of spec
    """
    res = await history_server.var.read_raw_history(None, None, 1)
    assert 1 == len(res)
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_none(history_server):
    """no start and no end is not defined by spec, return reverse order"""
    res = await history_server.var.read_raw_history(None, None, 0)
    assert 20 == len(res)
    assert res[0].Value.Value == history_server.values[-1]
    assert res[-1].Value.Value == history_server.values[0]


async def test_history_var_read_last_3(history_server):
    """no start and no end is not defined by spec, return reverse order"""
    res = await history_server.var.read_raw_history(None, None, 3)
    assert 3 == len(res)
    assert res[-1].Value.Value == history_server.values[-3]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_all2(history_server):
    """no start and no end is not defined by spec, return reverse order"""
    res = await history_server.var.read_raw_history(None, None, 9999)
    assert 20 == len(res)
    assert res[-1].Value.Value == history_server.values[0]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_2_with_end(history_server):
    """only has end time, should return reverse order"""
    now = datetime.now(UTC)
    res = await history_server.var.read_raw_history(None, now, 2)
    assert 2 == len(res)
    assert res[-1].Value.Value == history_server.values[-2]


async def test_history_var_read_all(history_server):
    """both start and endtime, return from start to end"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.var.read_raw_history(old, now, 0)
    assert 20 == len(res)
    assert res[-1].Value.Value == history_server.values[-1]
    assert res[0].Value.Value == history_server.values[0]


async def test_history_var_read_5_in_timeframe(history_server):
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.var.read_raw_history(old, now, 5)
    assert 5 == len(res)
    assert res[-1].Value.Value == history_server.values[4]
    assert res[0].Value.Value == history_server.values[0]


async def test_history_var_read_5_in_timeframe_start_greater_than_end(history_server):
    """start time greater than end time, should return reverse order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)

    res = await history_server.var.read_raw_history(now, old, 5)
    assert 5 == len(res)
    assert res[-1].Value.Value == history_server.values[-5]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_6_with_start(history_server):
    """only start return original order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)
    res = await history_server.var.read_raw_history(old, None, 6)
    assert 6 == len(res)
    assert res[-1].Value.Value == history_server.values[5]
    assert res[0].Value.Value == history_server.values[0]


async def test_history_var_read_all_with_start(history_server):
    """only start return original order"""
    now = datetime.now(UTC)
    old = now - timedelta(days=6)
    res = await history_server.var.read_raw_history(old, None, 0)
    assert 20 == len(res)
    assert res[-1].Value.Value == history_server.values[-1]
    assert res[0].Value.Value == history_server.values[0]


async def test_history_var_read_all_with_end(history_server):
    """only end return reversed order"""
    end = datetime.now(UTC) + timedelta(days=6)
    res = await history_server.var.read_raw_history(None, end, 0)
    assert 20 == len(res)
    assert res[-1].Value.Value == history_server.values[0]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_3_with_end(history_server):
    """only end return reversed order"""
    end = datetime.now(UTC) + timedelta(days=6)
    res = await history_server.var.read_raw_history(None, end, 3)
    assert 3 == len(res)
    assert res[2].Value.Value == history_server.values[-3]
    assert res[0].Value.Value == history_server.values[-1]


async def test_history_var_read_repeated_continuation_point():
    """
    Some servers do not treat numvalues=0 as "as many as you can" and answer
    with no data plus the same continuation point over and over. read_raw_history
    must not loop forever on such a server.
    """

    class _StuckServerNode(Node):
        def __init__(self):
            self.calls = 0

        async def history_read(self, details, continuation_point=None):
            self.calls += 1
            if self.calls > 10:
                raise AssertionError("read_raw_history did not stop on a repeated continuation point")
            result = ua.HistoryReadResult()
            result.StatusCode = ua.StatusCode(ua.StatusCodes.Good)
            result.ContinuationPoint = b"\x00\x00\x01\x9d"
            result.HistoryData = ua.HistoryData()
            result.HistoryData.DataValues = []
            return result

    node = _StuckServerNode()
    res = await node.read_raw_history(numvalues=0)
    assert [] == res
    assert 2 == node.calls


async def test_srv54_history_keeps_every_value_written_within_one_publish_cycle():
    """Part 4, 7.21: the capture asks for a queue of its own, a queue of one would keep only the last value."""
    from enginir_opcua import Server

    srv = Server()
    await srv.init()
    var = await srv.nodes.objects.add_variable(2, "BurstVar", 0)
    await srv.historize_node_data_change(var, count=500)
    for value in range(1, 101):
        await var.write_value(value)
    await asyncio.sleep(0.3)
    values = await srv.iserver.history_manager.storage.read_node_history(var.nodeid, None, None, 0)
    assert len(values[0]) == 101
    await srv.iserver.history_manager._sub.delete()

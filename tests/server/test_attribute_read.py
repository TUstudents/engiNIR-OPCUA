from datetime import UTC, datetime, timedelta

import pytest

from enginir_opcua import ua
from enginir_opcua.ua.uaerrors import UaStatusCodeError
from tests.access_rig import AccessRig, make_access_rig, payload  # noqa: F401

READ = ua.AttributeIds.Value


def read_params(
    nodeid: ua.NodeId,
    attr: ua.AttributeIds = READ,
    index_range: str | None = None,
    timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both,
    max_age: float = 0,
) -> ua.ReadParameters:
    item = ua.ReadValueId(NodeId=nodeid, AttributeId=attr, IndexRange=index_range)
    return ua.ReadParameters(MaxAge=max_age, TimestampsToReturn=timestamps, NodesToRead=[item])


async def read_one(rig: AccessRig, params: ua.ReadParameters) -> ua.DataValue:
    return (await rig.user.uaclient.read(params))[0]


async def test_srv58_read_rejects_negative_max_age_and_invalid_timestamps(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.3."""
    node = await access_rig.add_variable("MaxAgeVar", 1, ua.VariantType.Int32)
    with pytest.raises(UaStatusCodeError) as error:
        await read_one(access_rig, read_params(node.nodeid, max_age=-1))
    assert error.value.code == ua.StatusCodes.BadMaxAgeInvalid
    with pytest.raises(UaStatusCodeError) as error:
        await read_one(access_rig, read_params(node.nodeid, timestamps=ua.TimestampsToReturn.Invalid))
    assert error.value.code == ua.StatusCodes.BadTimestampsToReturnInvalid
    assert payload(await read_one(access_rig, read_params(node.nodeid, max_age=3e12))) == 1


async def test_srv16_read_without_current_read_is_not_readable(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4; Part 3, 8.57."""
    node = await access_rig.add_variable("NoRead", 1, ua.VariantType.Int32, access=0, user_access=0)
    for client in (access_rig.user, access_rig.admin):
        dv = (await client.uaclient.read(read_params(node.nodeid)))[0]
        assert dv.StatusCode == ua.StatusCode(ua.StatusCodes.BadNotReadable)
        assert dv.Value is None or dv.Value.Value is None


async def test_srv16_user_access_level_denies_read(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4; Part 3, 8.57."""
    node = await access_rig.add_variable("UserNoRead", 1, ua.VariantType.Int32, user_access=0)
    for client in (access_rig.user, access_rig.admin):
        dv = (await client.uaclient.read(read_params(node.nodeid)))[0]
        assert dv.StatusCode == ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
    assert await node.read_value() == 1


async def test_srv16_other_attributes_need_no_access_level(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4."""
    node = await access_rig.add_variable("NoReadName", 1, ua.VariantType.Int32, access=0, user_access=0)
    dv = await read_one(access_rig, read_params(node.nodeid, ua.AttributeIds.BrowseName))
    assert dv.StatusCode is None or dv.StatusCode.is_good()
    assert payload(dv).Name == "NoReadName"


async def test_srv15_read_index_range(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4, 7.27."""
    node = await access_rig.add_variable("RangeArray", [1, 2, 3, 4], ua.VariantType.Int32)
    assert payload(await read_one(access_rig, read_params(node.nodeid, index_range="1:2"))) == [2, 3]
    assert payload(await read_one(access_rig, read_params(node.nodeid, index_range="2:9"))) == [3, 4]
    dv = await read_one(access_rig, read_params(node.nodeid, index_range="7"))
    assert dv.StatusCode == ua.StatusCode(ua.StatusCodes.BadIndexRangeNoData)
    dv = await read_one(access_rig, read_params(node.nodeid, index_range="2:1"))
    assert dv.StatusCode == ua.StatusCode(ua.StatusCodes.BadIndexRangeInvalid)
    scalar = await access_rig.add_variable("RangeScalar", 5, ua.VariantType.Int32)
    dv = await read_one(access_rig, read_params(scalar.nodeid, index_range="0"))
    assert dv.StatusCode == ua.StatusCode(ua.StatusCodes.BadIndexRangeNoData)


async def test_srv15_timestamps_to_return_source_server_both_neither(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4, 7.39."""
    node = await access_rig.add_variable("Stamps", 1, ua.VariantType.Int32)
    stamp = datetime.now(UTC) - timedelta(minutes=5)
    await node.write_attribute(READ, ua.DataValue(ua.Variant(1, ua.VariantType.Int32), SourceTimestamp=stamp))
    source = await read_one(access_rig, read_params(node.nodeid, timestamps=ua.TimestampsToReturn.Source))
    assert source.SourceTimestamp == stamp
    assert source.ServerTimestamp is None
    server = await read_one(access_rig, read_params(node.nodeid, timestamps=ua.TimestampsToReturn.Server))
    assert server.SourceTimestamp is None
    assert server.ServerTimestamp is not None
    both = await read_one(access_rig, read_params(node.nodeid, timestamps=ua.TimestampsToReturn.Both))
    assert both.SourceTimestamp == stamp
    assert both.ServerTimestamp is not None
    neither = await read_one(access_rig, read_params(node.nodeid, timestamps=ua.TimestampsToReturn.Neither))
    assert neither.SourceTimestamp is None
    assert neither.ServerTimestamp is None
    assert payload(neither) == 1


async def test_srv15_other_attributes_return_only_a_server_timestamp(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4."""
    node = await access_rig.add_variable("StampsName", 1, ua.VariantType.Int32)
    dv = await read_one(access_rig, read_params(node.nodeid, ua.AttributeIds.DisplayName))
    assert dv.SourceTimestamp is None
    assert dv.ServerTimestamp is not None
    dv = await read_one(
        access_rig, read_params(node.nodeid, ua.AttributeIds.DisplayName, timestamps=ua.TimestampsToReturn.Source)
    )
    assert dv.ServerTimestamp is None


async def test_srv15_data_encoding_is_ignored(access_rig: AccessRig) -> None:
    """Part 4, 7.28."""
    node = await access_rig.add_variable("Encoded", 7, ua.VariantType.Int32)
    item = ua.ReadValueId(NodeId=node.nodeid, AttributeId=READ, DataEncoding=ua.QualifiedName("Whatever", 0))
    dv = (await access_rig.user.uaclient.read(ua.ReadParameters(NodesToRead=[item])))[0]
    assert payload(dv) == 7


async def test_srv62_variable_without_value_reads_bad_no_value(access_rig: AccessRig) -> None:
    """Part 4, 7.11.5."""
    dv = await read_one(
        access_rig, read_params(ua.NodeId(ua.ObjectIds.Server_ServerCapabilities_MaxQueryContinuationPoints))
    )
    assert dv.StatusCode == ua.StatusCode(ua.StatusCodes.BadNoValue)
    assert dv.Value is None or dv.Value.Value is None


async def test_srv62_capability_variables_have_values(access_rig: AccessRig) -> None:
    """Part 5, 6.3.2."""
    queue = await read_one(
        access_rig, read_params(ua.NodeId(ua.ObjectIds.Server_ServerCapabilities_MaxMonitoredItemsQueueSize))
    )
    assert queue.StatusCode is None or queue.StatusCode.is_good()
    assert payload(queue) == access_rig.server.iserver.max_monitored_item_queue_size


async def test_srv68_value_callback_exception_fails_only_its_entry(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4."""
    good = await access_rig.add_variable("CallbackGood", 3, ua.VariantType.Int32)
    bad = await access_rig.add_variable("CallbackBad", 3, ua.VariantType.Int32)

    def broken(nodeid: ua.NodeId, attr: ua.AttributeIds) -> ua.DataValue:
        raise RuntimeError("secret detail")

    access_rig.server.iserver.set_attribute_value_callback(bad.nodeid, broken)
    params = ua.ReadParameters(
        TimestampsToReturn=ua.TimestampsToReturn.Both,
        NodesToRead=[ua.ReadValueId(NodeId=n.nodeid, AttributeId=READ) for n in (bad, good)],
    )
    results = await access_rig.user.uaclient.read(params)
    assert results[0].StatusCode == ua.StatusCode(ua.StatusCodes.BadInternalError)
    assert payload(results[1]) == 3


async def test_srv17_read_unknown_and_null_node_ids(access_rig: AccessRig) -> None:
    """Part 4, 5.11.2.4."""
    unknown = await read_one(access_rig, read_params(ua.NodeId("Nothing", access_rig.ns)))
    assert unknown.StatusCode == ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)
    null = await read_one(access_rig, read_params(ua.NodeId()))
    assert null.StatusCode == ua.StatusCode(ua.StatusCodes.BadNodeIdInvalid)
    invalid = await read_one(access_rig, read_params(ua.NodeId(ua.ObjectIds.Server), attr=ua.AttributeIds.Value))
    assert invalid.StatusCode == ua.StatusCode(ua.StatusCodes.BadAttributeIdInvalid)

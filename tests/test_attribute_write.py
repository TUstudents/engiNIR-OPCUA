from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from enginir_opcua import Client, ua
from enginir_opcua.server.address_space import NodeData

from .access_rig import AccessRig, make_access_rig, payload  # noqa: F401

VALUE = ua.AttributeIds.Value


def status(code: int) -> ua.StatusCode:
    return ua.StatusCode(code)


async def write_one(
    client: Client,
    nodeid: ua.NodeId,
    value: ua.DataValue,
    attr: ua.AttributeIds = VALUE,
    index_range: str | None = None,
) -> ua.StatusCode:
    item = ua.WriteValue(NodeId=nodeid, AttributeId=attr, Value=value, IndexRange=index_range)
    return (await client.uaclient.write(ua.WriteParameters(NodesToWrite=[item])))[0]


def dv(value: Any, vtype: ua.VariantType, **kwargs: Any) -> ua.DataValue:
    return ua.DataValue(ua.Variant(value, vtype), **kwargs)


async def stored(rig: AccessRig, nodeid: ua.NodeId) -> ua.DataValue:
    return rig.server.iserver.aspace.read_attribute_value(nodeid, VALUE)


async def test_srv16_admin_cannot_write_a_variable_without_current_write(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4; Part 3, 8.57."""
    node = await access_rig.add_variable("ReadOnly", 1, ua.VariantType.Int32)
    for client in (access_rig.admin, access_rig.user):
        result = await write_one(client, node.nodeid, dv(2, ua.VariantType.Int32))
        assert result == status(ua.StatusCodes.BadNotWritable)
    assert await node.read_value() == 1


async def test_srv16_user_access_level_without_write_is_user_access_denied(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4; Part 3, 8.57."""
    node = await access_rig.add_variable("UserReadOnly", 1, ua.VariantType.Int32, access=3, user_access=1)
    for client in (access_rig.admin, access_rig.user):
        result = await write_one(client, node.nodeid, dv(2, ua.VariantType.Int32))
        assert result == status(ua.StatusCodes.BadUserAccessDenied)


async def test_srv16_in_process_write_skips_access_bits_only(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4."""
    node = await access_rig.add_variable("InProcess", 1, ua.VariantType.Int32)
    await node.write_value(5, ua.VariantType.Int32)
    assert await node.read_value() == 5
    with pytest.raises(ua.UaStatusCodeError) as error:
        await node.write_value("text", ua.VariantType.String)
    assert error.value.code == ua.StatusCodes.BadTypeMismatch
    assert await node.read_value() == 5


async def test_srv16_write_mask_and_user_write_mask(access_rig: AccessRig) -> None:
    """Part 3, 5.2.7, 5.2.8; Part 4, 5.11.4.4."""
    node = await access_rig.add_variable("Masked", 1, ua.VariantType.Int32)
    name = ua.DataValue(ua.Variant(ua.LocalizedText("New"), ua.VariantType.LocalizedText))
    for client in (access_rig.admin, access_rig.user):
        assert await write_one(client, node.nodeid, name, ua.AttributeIds.DisplayName) == status(
            ua.StatusCodes.BadNotWritable
        )
    mask = 1 << ua.WriteMask.DisplayName
    await node.write_attribute(ua.AttributeIds.WriteMask, dv(mask, ua.VariantType.UInt32))
    await node.write_attribute(ua.AttributeIds.UserWriteMask, dv(0, ua.VariantType.UInt32))
    for client in (access_rig.admin, access_rig.user):
        assert await write_one(client, node.nodeid, name, ua.AttributeIds.DisplayName) == status(
            ua.StatusCodes.BadUserAccessDenied
        )
    await node.write_attribute(ua.AttributeIds.UserWriteMask, dv(mask, ua.VariantType.UInt32))
    assert await write_one(access_rig.user, node.nodeid, name, ua.AttributeIds.DisplayName) == status(0)
    assert (await node.read_display_name()).Text == "New"
    other = dv(ua.LocalizedText("Other"), ua.VariantType.LocalizedText)
    assert await write_one(access_rig.admin, node.nodeid, other, ua.AttributeIds.Description) == status(
        ua.StatusCodes.BadNotWritable
    )
    wrong_type = dv("text", ua.VariantType.String)
    assert await write_one(access_rig.admin, node.nodeid, wrong_type, ua.AttributeIds.DisplayName) == status(
        ua.StatusCodes.BadTypeMismatch
    )


async def test_srv16_node_id_and_node_class_are_never_writable(access_rig: AccessRig) -> None:
    """Part 3, 5.2.7; Part 4, 5.11.4.4."""
    node = await access_rig.add_variable("Identity", 1, ua.VariantType.Int32)
    everything = dv(0xFFFFFFFF, ua.VariantType.UInt32)
    await node.write_attribute(ua.AttributeIds.WriteMask, everything)
    await node.write_attribute(ua.AttributeIds.UserWriteMask, everything)
    new_id = dv(ua.NodeId("Other", access_rig.ns), ua.VariantType.NodeId)
    new_class = dv(ua.NodeClass.Object, ua.VariantType.Int32)
    for client in (access_rig.admin, access_rig.user):
        assert await write_one(client, node.nodeid, new_id, ua.AttributeIds.NodeId) == status(
            ua.StatusCodes.BadNotWritable
        )
        assert await write_one(client, node.nodeid, new_class, ua.AttributeIds.NodeClass) == status(
            ua.StatusCodes.BadNotWritable
        )


async def test_srv16_write_checks_value_rank_array_dimensions_and_subtypes(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.2; Part 3, 5.6.2."""
    scalar = await access_rig.add_variable("Scalar", 1, ua.VariantType.Int32, writable=True)
    array = await access_rig.add_variable("Array", [1, 2, 3], ua.VariantType.Int32, writable=True)
    user = access_rig.user
    assert await write_one(user, scalar.nodeid, dv([1, 2], ua.VariantType.Int32)) == status(
        ua.StatusCodes.BadTypeMismatch
    )
    assert await write_one(user, array.nodeid, dv(7, ua.VariantType.Int32)) == status(ua.StatusCodes.BadTypeMismatch)
    assert await write_one(user, array.nodeid, dv([4, 5], ua.VariantType.Int32)) == status(0)
    assert await write_one(user, scalar.nodeid, dv(1.5, ua.VariantType.Double)) == status(
        ua.StatusCodes.BadTypeMismatch
    )
    await array.write_attribute(ua.AttributeIds.ArrayDimensions, dv([2], ua.VariantType.UInt32))
    assert await write_one(user, array.nodeid, dv([1, 2, 3], ua.VariantType.Int32)) == status(
        ua.StatusCodes.BadTypeMismatch
    )
    assert await write_one(user, array.nodeid, dv([1, 2], ua.VariantType.Int32)) == status(0)

    number = await access_rig.add_variable("Number", 1, ua.VariantType.Int32, writable=True)
    await number.write_attribute(ua.AttributeIds.DataType, dv(ua.NodeId(ua.ObjectIds.Number), ua.VariantType.NodeId))
    assert await write_one(user, number.nodeid, dv(2.5, ua.VariantType.Double)) == status(0)
    assert await write_one(user, number.nodeid, dv(3, ua.VariantType.UInt16)) == status(0)
    assert await write_one(user, number.nodeid, dv("x", ua.VariantType.String)) == status(
        ua.StatusCodes.BadTypeMismatch
    )

    duration = await access_rig.add_variable("Duration", 1.0, ua.VariantType.Double, writable=True)
    await duration.write_attribute(
        ua.AttributeIds.DataType, dv(ua.NodeId(ua.ObjectIds.Duration), ua.VariantType.NodeId)
    )
    assert await write_one(user, duration.nodeid, dv(2.0, ua.VariantType.Double)) == status(0)
    assert await write_one(user, duration.nodeid, dv(2, ua.VariantType.Int32)) == status(ua.StatusCodes.BadTypeMismatch)

    enum = await access_rig.add_variable("Enum", 1, ua.VariantType.Int32, writable=True)
    await enum.write_attribute(ua.AttributeIds.DataType, dv(ua.NodeId(ua.ObjectIds.NodeClass), ua.VariantType.NodeId))
    assert await write_one(user, enum.nodeid, dv(4, ua.VariantType.Int32)) == status(0)
    assert await write_one(user, enum.nodeid, dv(4, ua.VariantType.Int16)) == status(ua.StatusCodes.BadTypeMismatch)


async def test_srv16_null_value_needs_base_data_type_or_allow_nulls(access_rig: AccessRig) -> None:
    """Part 6, 5.1.2; design decision on null writes."""
    typed = await access_rig.add_variable("Typed", 1, ua.VariantType.Int32, writable=True)
    assert await write_one(access_rig.user, typed.nodeid, dv(None, ua.VariantType.Null)) == status(
        ua.StatusCodes.BadTypeMismatch
    )
    anything = await access_rig.add_variable("Anything", 1, ua.VariantType.Int32, writable=True)
    await anything.write_attribute(
        ua.AttributeIds.DataType, dv(ua.NodeId(ua.ObjectIds.BaseDataType), ua.VariantType.NodeId)
    )
    assert await write_one(access_rig.user, anything.nodeid, dv(None, ua.VariantType.Null)) == status(0)


async def test_com13_array_dimensions_rejects_scalar(access_rig: AccessRig) -> None:
    """Part 3, 5.6.2: ArrayDimensions is an array of UInt32."""
    node = await access_rig.add_variable("Dims", [1, 2, 3], ua.VariantType.Int32)
    everything = dv(0xFFFFFFFF, ua.VariantType.UInt32)
    await node.write_attribute(ua.AttributeIds.WriteMask, everything)
    await node.write_attribute(ua.AttributeIds.UserWriteMask, everything)
    scalar = dv(3, ua.VariantType.UInt32)
    assert await write_one(access_rig.user, node.nodeid, scalar, ua.AttributeIds.ArrayDimensions) == status(
        ua.StatusCodes.BadTypeMismatch
    )
    array = dv([3], ua.VariantType.UInt32)
    assert await write_one(access_rig.user, node.nodeid, array, ua.AttributeIds.ArrayDimensions) == status(0)


async def test_srv55_status_and_timestamp_writes_need_the_access_bits(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.2; Part 3, 8.57."""
    node = await access_rig.add_variable("Bits", 1, ua.VariantType.Int32, writable=True)
    stamp = datetime.now(UTC) - timedelta(hours=1)
    bad = dv(1, ua.VariantType.Int32, StatusCode=status(ua.StatusCodes.BadSensorFailure))
    stamped = dv(2, ua.VariantType.Int32, SourceTimestamp=stamp)
    server_stamped = dv(2, ua.VariantType.Int32, ServerTimestamp=stamp)
    for client in (access_rig.user, access_rig.admin):
        for value in (bad, stamped, server_stamped):
            assert await write_one(client, node.nodeid, value) == status(ua.StatusCodes.BadWriteNotSupported)
    assert payload(await stored(access_rig, node.nodeid)) == 1
    await node.set_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.StatusWrite)
    await node.set_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.StatusWrite)
    assert await write_one(access_rig.user, node.nodeid, bad) == status(0)
    result = await stored(access_rig, node.nodeid)
    assert result.StatusCode == status(ua.StatusCodes.BadSensorFailure)
    assert result.Value is not None
    assert result.Value.VariantType == ua.VariantType.Null
    await node.set_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.TimestampWrite)
    await node.set_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.TimestampWrite)
    assert await write_one(access_rig.user, node.nodeid, stamped) == status(0)
    assert (await stored(access_rig, node.nodeid)).SourceTimestamp == stamp


async def test_srv55_source_timestamp_is_set_when_missing(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.2."""
    node = await access_rig.add_variable("Stamped", 1, ua.VariantType.Int32, writable=True)
    before = datetime.now(UTC)
    assert await write_one(access_rig.user, node.nodeid, dv(3, ua.VariantType.Int32)) == status(0)
    result = await stored(access_rig, node.nodeid)
    assert result.SourceTimestamp is not None
    assert result.SourceTimestamp >= before
    assert result.ServerTimestamp is not None


async def test_srv65_session_write_to_callback_attribute_is_not_writable(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4."""
    node = await access_rig.add_variable("Callback", 1, ua.VariantType.Int32, writable=True)

    def callback(nodeid: ua.NodeId, attr: ua.AttributeIds) -> ua.DataValue:
        return dv(9, ua.VariantType.Int32)

    access_rig.server.iserver.set_attribute_value_callback(node.nodeid, callback)
    for client in (access_rig.admin, access_rig.user):
        assert await write_one(client, node.nodeid, dv(2, ua.VariantType.Int32)) == status(
            ua.StatusCodes.BadNotWritable
        )
    assert await node.read_value() == 9


async def test_srv16_setter_status_is_the_result_and_subscribers_are_not_told(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4."""
    node = await access_rig.add_variable("Setter", 1, ua.VariantType.Int32, writable=True)
    told: list[ua.DataValue] = []

    async def subscriber(handle: int, value: ua.DataValue) -> None:
        told.append(value)

    def setter(data: NodeData, attr: ua.AttributeIds, value: ua.DataValue) -> ua.StatusCode:
        if payload(value) > 100:
            return status(ua.StatusCodes.BadOutOfRange)
        data.attributes[attr].value = value
        return status(0)

    aspace = access_rig.server.iserver.aspace
    aspace.add_datachange_callback(node.nodeid, VALUE, subscriber)
    aspace.set_attribute_value_setter(node.nodeid, VALUE, setter)
    assert await write_one(access_rig.user, node.nodeid, dv(101, ua.VariantType.Int32)) == status(
        ua.StatusCodes.BadOutOfRange
    )
    assert told == []
    assert payload(await stored(access_rig, node.nodeid)) == 1
    assert await write_one(access_rig.user, node.nodeid, dv(7, ua.VariantType.Int32)) == status(0)
    assert [payload(t) for t in told] == [7]


async def test_srv68_setter_and_callback_errors_fail_only_their_entry(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4."""
    broken = await access_rig.add_variable("BrokenSetter", 1, ua.VariantType.Int32, writable=True)
    raising = await access_rig.add_variable("RaisingSubscriber", 1, ua.VariantType.Int32, writable=True)
    fine = await access_rig.add_variable("FineVariable", 1, ua.VariantType.Int32, writable=True)

    def setter(data: NodeData, attr: ua.AttributeIds, value: ua.DataValue) -> None:
        raise RuntimeError("secret detail")

    async def subscriber(handle: int, value: ua.DataValue) -> None:
        raise RuntimeError("subscriber failed")

    aspace = access_rig.server.iserver.aspace
    aspace.set_attribute_value_setter(broken.nodeid, VALUE, setter)
    aspace.add_datachange_callback(raising.nodeid, VALUE, subscriber)
    items = [
        ua.WriteValue(NodeId=n.nodeid, AttributeId=VALUE, Value=dv(5, ua.VariantType.Int32))
        for n in (broken, raising, fine)
    ]
    results = await access_rig.user.uaclient.write(ua.WriteParameters(NodesToWrite=items))
    assert results == [status(ua.StatusCodes.BadInternalError), status(0), status(0)]
    assert payload(await stored(access_rig, fine.nodeid)) == 5


async def test_srv15_write_with_index_range_changes_only_the_range(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4, 7.27."""
    node = await access_rig.add_variable("RangeWrite", [1.0, 2.0, 3.0, 4.0], ua.VariantType.Double, writable=True)
    assert await write_one(access_rig.user, node.nodeid, dv([9.0], ua.VariantType.Double), index_range="1") == status(0)
    assert payload(await stored(access_rig, node.nodeid)) == [1.0, 9.0, 3.0, 4.0]
    result = await write_one(access_rig.user, node.nodeid, dv([7.0, 8.0], ua.VariantType.Double), index_range="2:3")
    assert result == status(0)
    assert payload(await stored(access_rig, node.nodeid)) == [1.0, 9.0, 7.0, 8.0]
    text = await access_rig.add_variable("RangeText", "TestString", ua.VariantType.String, writable=True)
    assert await write_one(
        access_rig.user, text.nodeid, dv("Rest", ua.VariantType.String), index_range="0:3"
    ) == status(0)
    assert payload(await stored(access_rig, text.nodeid)) == "RestString"


async def test_srv15_write_range_mismatch_is_data_mismatch(access_rig: AccessRig) -> None:
    """Part 4, 7.27."""
    node = await access_rig.add_variable("RangeMismatch", [1, 2, 3, 4], ua.VariantType.Int32, writable=True)
    result = await write_one(access_rig.user, node.nodeid, dv([1], ua.VariantType.Int32), index_range="1:2")
    assert result == status(ua.StatusCodes.BadIndexRangeDataMismatch)
    result = await write_one(access_rig.user, node.nodeid, dv([1, 2], ua.VariantType.Int32), index_range="2:1")
    assert result == status(ua.StatusCodes.BadIndexRangeInvalid)
    assert payload(await stored(access_rig, node.nodeid)) == [1, 2, 3, 4]


async def test_srv15_write_range_out_of_bounds_is_no_data(access_rig: AccessRig) -> None:
    """Part 4, 7.27."""
    node = await access_rig.add_variable("RangeOut", [1, 2, 3, 4], ua.VariantType.Int32, writable=True)
    result = await write_one(access_rig.user, node.nodeid, dv([1, 2], ua.VariantType.Int32), index_range="3:4")
    assert result == status(ua.StatusCodes.BadIndexRangeNoData)
    scalar = await access_rig.add_variable("RangeScalarWrite", 1, ua.VariantType.Int32, writable=True)
    result = await write_one(access_rig.user, scalar.nodeid, dv([1], ua.VariantType.Int32), index_range="0")
    assert result == status(ua.StatusCodes.BadIndexRangeNoData)


async def test_srv17_write_unknown_and_null_node_ids(access_rig: AccessRig) -> None:
    """Part 4, 5.11.4.4."""
    unknown = await write_one(access_rig.user, ua.NodeId("Nothing", access_rig.ns), dv(1, ua.VariantType.Int32))
    assert unknown == status(ua.StatusCodes.BadNodeIdUnknown)
    null = await write_one(access_rig.user, ua.NodeId(), dv(1, ua.VariantType.Int32))
    assert null == status(ua.StatusCodes.BadNodeIdInvalid)
    wrong = await write_one(
        access_rig.user, ua.NodeId(ua.ObjectIds.Server), dv(1, ua.VariantType.Int32), attr=ua.AttributeIds.Value
    )
    assert wrong == status(ua.StatusCodes.BadAttributeIdInvalid)

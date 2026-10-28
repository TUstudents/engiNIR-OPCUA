import struct
from datetime import UTC
from typing import Any

import pytest

from enginir_opcua.common.utils import Buffer
from enginir_opcua.pubsub import uadp
from enginir_opcua.ua import FieldMetaData, UaError, Variant, VariantType
from enginir_opcua.ua.uatypes import Byte, DataValue, DateTime, Int32, StatusCode, String, UInt16, UInt32, UInt64


def _network(payload: list, publisher_id=UInt16(1), writer_ids: list | None = None, **kwargs) -> bytes:
    msg = uadp.UadpNetworkMessage(
        uadp.UadpHeader(publisher_id),
        DataSetPayloadHeader=writer_ids if writer_ids is not None else [UInt16(5)],
        Payload=payload,
        **kwargs,
    )
    return msg.to_binary()


def _variant_message(value: int = 1, **header) -> uadp.UadpDataSetVariant:
    return uadp.UadpDataSetVariant(uadp.UadpDataSetMessageHeader(**header), [Variant(Int32(value))])


def _decode(data: bytes) -> uadp.UadpNetworkMessage:
    return uadp.UadpNetworkMessage.from_binary(Buffer(data))


def _payload(message: uadp.UadpNetworkMessage) -> list[Any]:
    assert isinstance(message.Payload, list)
    return message.Payload


def _skip_reason(data: bytes) -> str:
    result = uadp.decode_network_message(Buffer(data))
    assert isinstance(result, uadp.UadpSkip)
    return result.reason


def test_pub2_uint64_publisher_id_uses_type_bits_011() -> None:
    data = uadp.UadpNetworkMessage(uadp.UadpHeader(UInt64(0x0102030405060708)), Payload=[]).to_binary()
    assert data[0] & 0x80
    assert data[1] & 0b111 == 0b011
    message = _decode(data)
    assert message.Header.PublisherId == 0x0102030405060708
    assert isinstance(message.Header.PublisherId, UInt64)


@pytest.mark.parametrize("type_bits", [0b101, 0b110, 0b111])
def test_pub2_reserved_publisher_id_types_are_skipped(type_bits: int) -> None:
    data = bytearray(uadp.UadpNetworkMessage(uadp.UadpHeader(UInt16(1)), Payload=[]).to_binary())
    data[1] = (data[1] & ~0b111) | type_bits
    assert "PublisherId" in _skip_reason(bytes(data))


def test_pub2_unknown_uadp_version_is_skipped() -> None:
    data = bytearray(_network([_variant_message()]))
    data[0] = (data[0] & 0xF0) | 2
    assert "version" in _skip_reason(bytes(data))


def test_pub2_reserved_bits_of_extended_flags_2_are_skipped() -> None:
    data = bytearray(_network([_variant_message()], PromotedFields=[Variant(Int32(1))]))
    assert data[1] & 0x80
    data[2] |= 0b01000000
    assert "ExtendedFlags2" in _skip_reason(bytes(data))


def test_pub2_reserved_network_message_type_is_skipped() -> None:
    data = bytearray(_network([_variant_message()], PromotedFields=[Variant(Int32(1))]))
    data[2] |= 0b00001100
    assert "NetworkMessage type" in _skip_reason(bytes(data))


def test_pub2_reserved_group_flags_are_skipped() -> None:
    message = uadp.UadpNetworkMessage(
        uadp.UadpHeader(UInt16(1)), uadp.UadpGroupHeader(UInt16(2)), [UInt16(5)], Payload=[_variant_message()]
    )
    data = bytearray(message.to_binary())
    group_flags_at = 2 + 2
    data[group_flags_at] |= 0b00010000
    assert "GroupFlags" in _skip_reason(bytes(data))


def test_pub2_valid_flag_round_trips() -> None:
    message = _decode(_network([_variant_message(Valid=False)]))
    assert _payload(message)[0].Header.Valid is False
    message = _decode(_network([_variant_message(Valid=True)]))
    assert _payload(message)[0].Header.Valid is True


def test_pub2_promoted_fields_size_is_the_byte_length() -> None:
    fields = [Variant(UInt16(1)), Variant(UInt16(2))]
    data = _network([_variant_message()], PromotedFields=fields)
    encoded_fields = b"".join(uadp.pack_uatype(VariantType.Variant, f) for f in fields)
    size_at = data.index(encoded_fields) - 2
    assert struct.unpack_from("<H", data, size_at)[0] == len(encoded_fields)
    assert _decode(data).PromotedFields == fields


def test_pub2_event_dataset_message_round_trips() -> None:
    event = uadp.UadpDataSetEvent(
        uadp.UadpDataSetMessageHeader(SequenceNo=UInt16(3)), [Variant("a"), Variant(Int32(2))]
    )
    message = _decode(_network([event]))
    assert isinstance(_payload(message)[0], uadp.UadpDataSetEvent)
    assert _payload(message)[0].Data == event.Data


def test_pub2_reserved_dataset_encoding_and_type_are_skipped() -> None:
    data = bytearray(_network([_variant_message()]))
    payload_at = len(data) - len(_variant_message().message_to_binary())
    reserved_encoding = bytearray(data)
    reserved_encoding[payload_at] |= 0b110
    result = _decode(bytes(reserved_encoding))
    assert isinstance(_payload(result)[0], uadp.UadpDataSetSkipped)
    reserved_type = bytearray(data)
    reserved_type[payload_at] |= 0x80
    reserved_type[payload_at + 1 : payload_at + 1] = bytes([0b0111])
    result = _decode(bytes(reserved_type))
    assert isinstance(_payload(result)[0], uadp.UadpDataSetSkipped)


def test_pub2_picoseconds_of_10000_or_more_are_read_as_9999() -> None:
    header = uadp.UadpDataSetMessageHeader(Timestamp=DateTime.now(UTC), PicoSeconds=UInt16(12000))
    message = _decode(_network([uadp.UadpDataSetVariant(header, [Variant(Int32(1))])]))
    assert _payload(message)[0].Header.PicoSeconds == 9999


def test_pub10_publisher_id_type_follows_the_variant_type() -> None:
    cases = [
        (Variant(5, VariantType.Byte), 0, Byte),
        (Variant(5, VariantType.UInt16), 1, UInt16),
        (Variant(70000, VariantType.UInt32), 2, UInt32),
        (Variant(5, VariantType.UInt64), 3, UInt64),
        (Variant("pub", VariantType.String), 4, String),
    ]
    for variant, type_bits, cls in cases:
        publisher_id = uadp.publisher_id_from_variant(variant)
        data = uadp.UadpNetworkMessage(uadp.UadpHeader(publisher_id), Payload=[]).to_binary()
        assert (data[1] & 0b111 if data[0] & 0x80 else 0) == type_bits
        decoded = _decode(data).Header.PublisherId
        assert isinstance(decoded, cls)
        assert decoded == variant.Value


def test_pub10_publisher_id_without_a_type_is_refused() -> None:
    with pytest.raises(UaError, match="PublisherId"):
        uadp.UadpNetworkMessage(uadp.UadpHeader(5), Payload=[]).to_binary()


def test_pub10_publisher_id_matching_needs_equal_types() -> None:
    assert uadp.publisher_id_matches(Variant(5, VariantType.UInt16), UInt16(5))
    assert not uadp.publisher_id_matches(Variant(5, VariantType.UInt16), UInt32(5))
    assert not uadp.publisher_id_matches(Variant(5, VariantType.UInt16), None)
    assert uadp.publisher_id_matches(Variant(), UInt16(5))
    assert uadp.publisher_id_matches(Variant(), None)


def test_pub11_heartbeat_key_frame_decodes() -> None:
    heartbeat = uadp.UadpDataSetHeartbeat(uadp.UadpDataSetMessageHeader(SequenceNo=UInt16(3)))
    message = _decode(_network([heartbeat]))
    assert isinstance(_payload(message)[0], uadp.UadpDataSetHeartbeat)
    assert _payload(message)[0].Header.SequenceNo == 3


def test_pub12_padding_does_not_shift_the_next_dataset_message() -> None:
    first = _variant_message(1).message_to_binary() + bytes(3)
    second = _variant_message(2).message_to_binary()
    head = uadp.UadpNetworkMessage(uadp.UadpHeader(UInt16(1)), DataSetPayloadHeader=[UInt16(5), UInt16(6)], Payload=[])
    data = head.to_binary() + struct.pack("<HH", len(first), len(second)) + first + second
    message = _decode(data)
    assert [m.Data for m in _payload(message)] == [[Variant(Int32(1))], [Variant(Int32(2))]]


def test_pub12_dataset_message_longer_than_its_size_does_not_spill_over() -> None:
    first = _variant_message(1).message_to_binary()
    second = _variant_message(2).message_to_binary()
    head = uadp.UadpNetworkMessage(uadp.UadpHeader(UInt16(1)), DataSetPayloadHeader=[UInt16(5), UInt16(6)], Payload=[])
    data = head.to_binary() + struct.pack("<HH", len(first) - 2, len(second)) + first + second
    with pytest.raises(UaError):
        _decode(data)


def test_pub14_chunk_message_layout() -> None:
    chunk = uadp.UadpChunk(UInt16(7), UInt16(2), UInt32(10), UInt32(30), b"abcd")
    message = uadp.UadpNetworkMessage(uadp.UadpHeader(UInt16(1)), Payload=chunk)
    data = message.to_binary()
    assert data.endswith(struct.pack("<HHIIi", 7, 2, 10, 30, 4) + b"abcd")
    assert _decode(data).Payload == chunk


def test_pub15_discovery_probe_and_announcement_layout() -> None:
    probe = uadp.UadpNetworkMessage(uadp.UadpHeader(UInt16(1)), Payload=uadp.UadpDiscoveryProbe(Byte(1), b"\x01\x02"))
    data = probe.to_binary()
    assert data[-3:] == b"\x01\x01\x02"
    assert _decode(data).Payload == uadp.UadpDiscoveryProbe(Byte(1), b"\x01\x02")
    announcement = uadp.UadpNetworkMessage(
        uadp.UadpHeader(UInt16(1)), Payload=uadp.UadpDiscoveryAnnouncement(Byte(2), UInt16(9), b"xy")
    )
    data = announcement.to_binary()
    assert data[-5:] == b"\x02\x09\x00xy"
    assert _decode(data).Payload == uadp.UadpDiscoveryAnnouncement(Byte(2), UInt16(9), b"xy")


def _field(name: str, vtype: VariantType, **kwargs) -> FieldMetaData:
    return FieldMetaData(Name=name, BuiltInType=Byte(vtype.value), ValueRank=kwargs.pop("ValueRank", -1), **kwargs)


def test_pub26_raw_strings_are_padded_to_max_string_length() -> None:
    fields = [_field("s", VariantType.String, MaxStringLength=UInt32(6)), _field("i", VariantType.Int32)]
    encoded = uadp.raw_field_to_binary(fields[0], Variant("ab")) + uadp.raw_field_to_binary(
        fields[1], Variant(Int32(7))
    )
    assert len(encoded) == 4 + 6 + 4
    values = uadp.raw_fields_from_binary(Buffer(encoded), fields)
    assert [v.Value for v in values] == ["ab", 7]


def test_pub26_raw_fixed_arrays_are_padded_to_array_dimensions() -> None:
    meta = _field("a", VariantType.Int16, ValueRank=1, ArrayDimensions=[UInt32(4)])
    encoded = uadp.raw_field_to_binary(meta, Variant([1, 2], VariantType.Int16, is_array=True))
    assert len(encoded) == 4 + 4 * 2
    values = uadp.raw_fields_from_binary(Buffer(encoded + b"tail"), [meta])
    assert values[0].Value == [1, 2]


def test_pub26_raw_refuses_fields_it_cannot_encode() -> None:
    forbidden = [
        _field("n", VariantType.NodeId),
        _field("t", VariantType.LocalizedText),
        _field("s", VariantType.String),
        _field("x", VariantType.Int32, ValueRank=2),
        _field("a", VariantType.Int32, ValueRank=1),
    ]
    for meta in forbidden:
        assert uadp.raw_layout_error(meta) is not None


def test_pub26_datavalue_with_status_round_trips() -> None:
    value = DataValue(Variant(Int32(1)), StatusCode(0x80000000))
    message = _decode(_network([uadp.UadpDataSetDataValue(uadp.UadpDataSetMessageHeader(), [value])]))
    assert _payload(message)[0].Data[0].StatusCode == value.StatusCode

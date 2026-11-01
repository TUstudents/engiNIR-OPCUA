import struct
from datetime import UTC, datetime, timedelta, timezone

import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.common.xmlparser import xs_datetime, xs_datetime_text
from enginir_opcua.ua.ua_binary import Primitives, nodeid_to_binary, struct_from_binary, struct_to_binary

MIN = datetime.min.replace(tzinfo=UTC)
MAX = datetime.max.replace(tzinfo=UTC)
EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
LATEST = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
MOMENT = datetime(2026, 11, 1, 12, 30, 15, 123456, tzinfo=UTC)
MOMENT_TICKS = 134380098151234560


def ticks(value: int) -> bytes:
    return struct.pack("<q", value)


def test_min_and_max_value_are_the_platform_limits() -> None:
    """Part 6, 5.1.4: DateTime.MinValue and MaxValue are the earliest and latest times of the platform."""
    assert ua.DATETIME_MIN_VALUE == MIN
    assert ua.DATETIME_MAX_VALUE == MAX


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        (MIN, 0),
        (datetime(1000, 6, 1, tzinfo=UTC), 0),
        (EPOCH, 0),
        (EPOCH + timedelta(microseconds=1), 10),
        (MOMENT, MOMENT_TICKS),
        (LATEST - timedelta(microseconds=1), 2650467743989999990),
        (LATEST, ua.MAX_INT64),
        (MAX, ua.MAX_INT64),
    ],
)
def test_encoder_clamps_to_zero_and_int64_max(moment: datetime, expected: int) -> None:
    """Part 6, 5.2.2.5, rules 1 to 6."""
    assert ua.datetime_to_ticks(moment) == expected


def test_encoder_converts_to_utc_and_takes_a_naive_value_as_utc() -> None:
    """Part 6, 5.1.4: DateTime values are encoded as UTC."""
    vienna = MOMENT.astimezone(timezone(timedelta(hours=1)))
    assert ua.datetime_to_ticks(vienna) == MOMENT_TICKS
    assert ua.datetime_to_ticks(MOMENT.replace(tzinfo=None)) == MOMENT_TICKS


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (-1, MIN),
        (0, MIN),
        (10, EPOCH + timedelta(microseconds=1)),
        (MOMENT_TICKS, MOMENT),
        (MOMENT_TICKS + 7, MOMENT),
        (ua.datetime_to_ticks(LATEST - timedelta(microseconds=1)), LATEST - timedelta(microseconds=1)),
        (2650467743990000000, MAX),
        (ua.MAX_INT64, MAX),
    ],
)
def test_decoder_maps_zero_and_int64_max_to_the_platform_limits(value: int, expected: datetime) -> None:
    """Part 6, 5.2.2.5, rules 7 to 12; the 100 ns digit is truncated."""
    assert ua.ticks_to_datetime(value) == expected
    assert Primitives.DateTime.unpack(Buffer(ticks(value))) == expected


def test_min_value_round_trips_through_the_binary_encoding() -> None:
    """Part 6, 5.2.2.5: MinValue is written as 0 and read back as MinValue; 1601-01-01 is read back as MinValue too."""
    assert Primitives.DateTime.pack(MIN) == ticks(0)
    assert Primitives.DateTime.pack(MAX) == ticks(ua.MAX_INT64)
    assert Primitives.DateTime.unpack(Buffer(Primitives.DateTime.pack(EPOCH))) == MIN


@pytest.mark.parametrize(
    ("moment", "null"),
    [
        (None, True),
        (MIN, True),
        (EPOCH, True),
        (EPOCH.astimezone(timezone(timedelta(hours=2))), True),
        (datetime(1601, 1, 1), True),
        (EPOCH + timedelta(microseconds=1), False),
        (MOMENT, False),
        (MAX, False),
    ],
)
def test_null_is_every_value_that_encodes_as_zero(moment: datetime | None, null: bool) -> None:
    """Part 6, 5.1.2: the default value of a nullable type is equivalent to null."""
    assert ua.is_null_datetime(moment) is null


def test_default_value_of_datetime_is_min_value() -> None:
    """Part 6, 5.1.2, Table 1: the default DateTime is DateTime.MinValue."""
    assert ua.get_default_value(ua.VariantType.DateTime) == MIN


def test_ua58_generated_datetime_fields_default_to_min_value() -> None:
    """Part 6, 5.1.2, Table 1: a structure field of type DateTime starts as DateTime.MinValue, not as the clock."""
    details = ua.ReadEventDetails()
    assert details.StartTime == details.EndTime == MIN
    assert ua.ReadRawModifiedDetails().StartTime == MIN
    assert ua.ViewDescription().Timestamp == MIN
    assert ua.BuildInfo().BuildDate == MIN
    assert ua.RequestHeader() == ua.RequestHeader()
    assert struct_to_binary(ua.ViewDescription()) == nodeid_to_binary(ua.NodeId()) + ticks(0) + b"\x00" * 4


def data_value(mask: int, *fields: bytes) -> bytes:
    return bytes([mask]) + b"".join(fields)


def test_data_value_puts_source_picoseconds_before_the_server_timestamp() -> None:
    """Part 6, 5.2.2.17, Table 27: SourceTimestamp, SourcePicoseconds, ServerTimestamp, ServerPicoseconds."""
    value = ua.DataValue(SourceTimestamp=MOMENT, SourcePicoseconds=1234, ServerTimestamp=MOMENT, ServerPicoseconds=4321)
    expected = data_value(
        0x3C, ticks(MOMENT_TICKS), struct.pack("<H", 1234), ticks(MOMENT_TICKS), struct.pack("<H", 4321)
    )
    assert struct_to_binary(value) == expected
    assert struct_from_binary(ua.DataValue, Buffer(expected)) == value


def test_data_value_keeps_the_100_ns_digit_in_the_picoseconds() -> None:
    """Part 6, 5.1.4: a platform without 100 ns resolution keeps the full precision in its Picoseconds."""
    wire = data_value(0x14, ticks(MOMENT_TICKS + 7), struct.pack("<H", 1234))
    decoded = struct_from_binary(ua.DataValue, Buffer(wire))
    assert decoded.SourceTimestamp == MOMENT
    assert decoded.SourcePicoseconds == 71234
    assert struct_to_binary(decoded) == wire
    digit_only = data_value(0x04, ticks(MOMENT_TICKS + 3))
    assert struct_from_binary(ua.DataValue, Buffer(digit_only)).SourcePicoseconds == 30000
    assert struct_to_binary(struct_from_binary(ua.DataValue, Buffer(digit_only))) == digit_only


def test_data_value_decoder_reads_picoseconds_of_10000_or_more_as_9999() -> None:
    """Part 6, 5.2.2.17: values greater than or equal to 10 000 are treated as 9999."""
    wire = data_value(0x14, ticks(MOMENT_TICKS), struct.pack("<H", 20000))
    assert struct_from_binary(ua.DataValue, Buffer(wire)).SourcePicoseconds == 9999


def test_data_value_ignores_picoseconds_without_their_timestamp() -> None:
    """Part 6, 5.2.2.17: if the timestamp is missing the Picoseconds are ignored."""
    wire = data_value(0x20, struct.pack("<H", 5))
    decoded = struct_from_binary(ua.DataValue, Buffer(wire))
    assert decoded.ServerTimestamp is None
    assert decoded.ServerPicoseconds is None
    assert struct_to_binary(ua.DataValue(ServerPicoseconds=5)) == b"\x00"


def test_data_value_leaves_out_null_value_good_status_and_min_value_timestamps() -> None:
    """Part 6, 5.2.2.17: the mask bits are false for a null Value, a Good StatusCode and DateTime.MinValue."""
    assert struct_to_binary(ua.DataValue()) == b"\x00"
    assert struct_to_binary(ua.DataValue(SourceTimestamp=MIN, SourcePicoseconds=5, ServerTimestamp=EPOCH)) == b"\x00"
    decoded = struct_from_binary(ua.DataValue, Buffer(b"\x00"))
    assert decoded.StatusCode == ua.StatusCode()
    assert decoded.Value == ua.Variant()
    assert decoded.SourceTimestamp is None


def test_data_value_sets_picoseconds_of_min_and_max_value_to_zero() -> None:
    """Part 6, 5.1.4: the Picoseconds are 0 when the DateTime is MinValue or MaxValue."""
    wire = data_value(0x14, ticks(ua.MAX_INT64), struct.pack("<H", 77))
    decoded = struct_from_binary(ua.DataValue, Buffer(wire))
    assert decoded.SourceTimestamp == MAX
    assert decoded.SourcePicoseconds is None
    assert struct_to_binary(ua.DataValue(SourceTimestamp=MAX, SourcePicoseconds=77)) == data_value(
        0x04, ticks(ua.MAX_INT64)
    )


def test_data_value_encoder_refuses_picoseconds_outside_one_microsecond() -> None:
    """The Picoseconds of a DataValue count 10 ps below the microsecond, so they lie between 0 and 99 999."""
    with pytest.raises(ua.UaError):
        struct_to_binary(ua.DataValue(SourceTimestamp=MOMENT, SourcePicoseconds=100_000))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0001-01-01T00:00:00Z", MIN),
        ("9999-12-31T23:59:59Z", MAX),
        ("10000-01-01T00:00:00Z", MAX),
        ("-0044-03-15T12:00:00Z", MIN),
        ("2002-10-10T00:00:00+05:00", datetime(2002, 10, 9, 19, tzinfo=UTC)),
        ("2026-11-01T12:30:15.123456Z", MOMENT),
    ],
)
def test_xml_decoder_converts_to_utc_and_clamps_out_of_range_values(text: str, expected: datetime) -> None:
    """Part 6, 5.3.1.6: out of range values become the earliest or latest time without an error."""
    parsed = xs_datetime(text)
    assert parsed == expected
    assert parsed.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    ("moment", "text"),
    [
        (MIN, "0001-01-01T00:00:00Z"),
        (EPOCH, "0001-01-01T00:00:00Z"),
        (MAX, "9999-12-31T23:59:59Z"),
        (LATEST, "9999-12-31T23:59:59Z"),
        (MOMENT, "2026-11-01T12:30:15.123456Z"),
        (MOMENT.replace(microsecond=0).astimezone(timezone(timedelta(hours=5))), "2026-11-01T12:30:15Z"),
        (MOMENT.replace(tzinfo=None), "2026-11-01T12:30:15.123456Z"),
    ],
)
def test_xml_encoder_writes_utc_and_the_special_values(moment: datetime, text: str) -> None:
    """Part 6, 5.3.1.6: UTC xs:dateTime; MinValue is 0001-01-01T00:00:00Z and MaxValue 9999-12-31T23:59:59Z."""
    assert xs_datetime_text(moment) == text

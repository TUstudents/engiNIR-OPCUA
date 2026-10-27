import pytest

from enginir_opcua import ua
from enginir_opcua.ua.numeric_range import IndexRange
from enginir_opcua.ua.uaerrors import BadIndexRangeDataMismatch, BadIndexRangeInvalid, BadIndexRangeNoData


def parse(text: str) -> IndexRange:
    result = IndexRange.parse(text)
    assert result is not None
    return result


def ints(values: list, dimensions: list[int] | None = None) -> ua.Variant:
    return ua.Variant(values, ua.VariantType.Int32, Dimensions=dimensions, is_array=True)


def strings(values: list) -> ua.Variant:
    return ua.Variant(values, ua.VariantType.String, is_array=True)


@pytest.mark.parametrize("text", ["1", "0", "1:3", "1:2,0:1", "1,1", "4294967295", "0:4294967295"])
def test_srv15_numeric_range_accepts_valid_syntax(text: str) -> None:
    """Part 4, 7.27, A.3."""
    assert str(parse(text)) == text


@pytest.mark.parametrize(
    "text",
    [
        "5:5",
        "7:5",
        "+1",
        " 1",
        "1 ",
        "1:2:3",
        "4294967296",
        "-1",
        "a",
        "1,",
        ",1",
        "1:",
        ":1",
        "1;2",
        "٣",
        ",".join("1" * 33),
    ],
)
def test_srv15_numeric_range_rejects_invalid_syntax(text: str) -> None:
    """Part 4, 7.27, A.3."""
    with pytest.raises(BadIndexRangeInvalid):
        IndexRange.parse(text)


@pytest.mark.parametrize("text", [None, ""])
def test_srv15_null_or_empty_range_is_not_used(text: str | None) -> None:
    """Part 4, 7.27."""
    assert IndexRange.parse(text) is None


def test_srv15_numeric_range_select_examples_of_table_166() -> None:
    """Part 4, 7.27, Table 166."""
    value = ints([2, 33, 12, 0, 99])
    assert parse("0:2").select(value).Value == [2, 33, 12]
    assert parse("3:7").select(value).Value == [0, 99]
    with pytest.raises(BadIndexRangeNoData):
        parse("7:9").select(value)
    names = strings(["TestString", "Test", "String"])
    assert parse("0:1,7:9").select(names).Value == ["ing", None]
    with pytest.raises(BadIndexRangeNoData):
        parse("0:1,10:15").select(names)


def test_srv15_single_index_selects_an_array_of_one() -> None:
    """Part 4, 7.27."""
    selected = parse("1").select(ints([5, 6, 7]))
    assert selected.Value == [6]
    assert selected.is_array


def test_srv15_matrix_and_substring_select() -> None:
    """Part 4, 7.27; Part 6, 5.2.2.16."""
    matrix = ints([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]], [4, 4])
    block = parse("1:2,0:1").select(matrix)
    assert block.Value == [[5, 6], [9, 10]]
    assert block.Dimensions == [2, 2]
    assert parse("1,1").select(matrix).Value == [[6]]
    with pytest.raises(BadIndexRangeNoData):
        parse("1").select(matrix)
    with pytest.raises(BadIndexRangeNoData):
        parse("4,0").select(matrix)
    text = ua.Variant("TestString", ua.VariantType.String)
    assert parse("4:6").select(text) == ua.Variant("Str", ua.VariantType.String)
    assert parse("8:20").select(text).Value == "ng"
    with pytest.raises(BadIndexRangeNoData):
        parse("10:12").select(text)
    raw = ua.Variant(b"\x01\x02\x03\x04", ua.VariantType.ByteString)
    assert parse("1:2").select(raw).Value == b"\x02\x03"


def test_srv15_string_indexes_count_characters_and_byte_string_indexes_count_bytes() -> None:
    """Design: the unit of a String index is a character."""
    text = ua.Variant("aä€", ua.VariantType.String)
    assert parse("1:2").select(text).Value == "ä€"
    raw = ua.Variant("ä".encode(), ua.VariantType.ByteString)
    assert parse("0").select(raw).Value == b"\xc3"


def test_srv15_range_on_a_scalar_or_with_wrong_dimension_count_is_no_data() -> None:
    """Part 4, 7.27."""
    with pytest.raises(BadIndexRangeNoData):
        parse("0").select(ua.Variant(5, ua.VariantType.Int32))
    with pytest.raises(BadIndexRangeNoData):
        parse("0,0").select(ints([1, 2]))
    with pytest.raises(BadIndexRangeNoData):
        parse("0").select(ua.Variant(None, ua.VariantType.Null))


def test_srv15_select_returns_a_copy() -> None:
    """Part 4, 7.27."""
    source = ints([1, 2, 3])
    selected = parse("0:1").select(source)
    selected.Value[0] = 99
    assert source.Value == [1, 2, 3]


def test_srv15_compose_changes_only_the_range() -> None:
    """Part 4, 7.27, 5.11.4.4."""
    current = ints([1, 2, 3, 4])
    composed = parse("1:2").compose(current, ints([20, 30]))
    assert composed.Value == [1, 20, 30, 4]
    assert current.Value == [1, 2, 3, 4]
    matrix = ints([[1, 2], [3, 4]], [2, 2])
    composed = parse("1,0").compose(matrix, ints([[9]], [1, 1]))
    assert composed.Value == [[1, 2], [9, 4]]
    assert composed.Dimensions == [2, 2]


def test_srv15_compose_substrings() -> None:
    """Part 4, 7.27."""
    current = ua.Variant("TestString", ua.VariantType.String)
    assert parse("0:3").compose(current, ua.Variant("Rest", ua.VariantType.String)).Value == "RestString"
    names = strings(["abc", "def"])
    composed = parse("0:1,1:2").compose(names, strings(["XY", "ZW"]))
    assert composed.Value == ["aXY", "dZW"]
    composed = parse("1").compose(names, strings(["new"]))
    assert composed.Value == ["abc", "new"]
    raw = ua.Variant(b"\x01\x02\x03", ua.VariantType.ByteString)
    assert parse("1").compose(raw, ua.Variant(b"\xff", ua.VariantType.ByteString)).Value == b"\x01\xff\x03"


def test_srv15_compose_size_or_type_mismatch_is_data_mismatch() -> None:
    """Part 4, 7.27: the size of the written array shall match the range."""
    current = ints([1, 2, 3, 4])
    with pytest.raises(BadIndexRangeDataMismatch):
        parse("1:2").compose(current, ints([1]))
    with pytest.raises(BadIndexRangeDataMismatch):
        parse("1:2").compose(current, ua.Variant([1.0, 2.0], ua.VariantType.Double))
    with pytest.raises(BadIndexRangeDataMismatch):
        parse("1").compose(current, ua.Variant(5, ua.VariantType.Int32))
    with pytest.raises(BadIndexRangeDataMismatch):
        parse("0:3").compose(ua.Variant("abcd", ua.VariantType.String), ua.Variant("ab", ua.VariantType.String))


def test_srv15_compose_outside_the_current_value_is_no_data() -> None:
    """Part 4, 7.27."""
    current = ints([1, 2, 3, 4])
    with pytest.raises(BadIndexRangeNoData):
        parse("3:4").compose(current, ints([1, 2]))
    with pytest.raises(BadIndexRangeNoData):
        parse("0").compose(ua.Variant(None, ua.VariantType.Null), ints([1]))
    with pytest.raises(BadIndexRangeNoData):
        parse("2:5").compose(ua.Variant("abc", ua.VariantType.String), ua.Variant("abcd", ua.VariantType.String))


def test_srv15_fits_detects_a_range_that_can_never_hold_data() -> None:
    """Part 4, 7.27."""
    assert parse("0:2").fits([5])
    assert not parse("5:6").fits([5])
    assert parse("5:6").fits([0])
    assert not parse("0,0,0").fits([5])

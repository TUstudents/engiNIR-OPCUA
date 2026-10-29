import time
from datetime import datetime

import pytest
from dateutil.tz import tzutc

from enginir_opcua import ua
from enginir_opcua.common.ua_utils import string_to_val, val_to_string
from enginir_opcua.ua.ua_binary import (
    struct_from_binary,
    struct_to_binary,
)


@pytest.fixture
def utc_local_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.mark.parametrize("text", ["2026-05-01T00:00:00Z", "2026-05-01T02:00:00+02:00"])
def test_datetime_string_is_utc_independent_of_local_zone(utc_local_zone: None, text: str) -> None:
    """Part 6, 5.3.1.6: DateTime text is UTC or carries an offset; the result is UTC whatever the host's zone."""
    value = string_to_val(text, ua.VariantType.DateTime)
    assert value == datetime(2026, 5, 1, tzinfo=tzutc())
    assert isinstance(value.tzinfo, tzutc)


def test_datetime_string_without_offset_stays_naive() -> None:
    assert string_to_val("2026-05-01T00:00:00", ua.VariantType.DateTime) == datetime(2026, 5, 1)


def test_string_to_variant_int():
    s_arr_uint = "[1, 2, 3, 4]"
    arr_uint = [1, 2, 3, 4]
    assert arr_uint == string_to_val(s_arr_uint, ua.VariantType.UInt32)
    assert arr_uint == string_to_val(s_arr_uint, ua.VariantType.UInt16)
    assert s_arr_uint == val_to_string(arr_uint)


def test_string_to_variant_float():
    s_arr_float = "[1.1, 2.1, 3, 4.0]"
    arr_float = [1.1, 2.1, 3, 4.0]
    s_float = "1.9"
    assert 1.9 == string_to_val(s_float, ua.VariantType.Float)
    assert s_arr_float == val_to_string(arr_float)


def test_string_to_variant_datetime_string():
    s_arr_datetime = "[2014-05-6, 2016-10-3]"
    arr_string = ["2014-05-6", "2016-10-3"]
    arr_datetime = [datetime(2014, 5, 6), datetime(2016, 10, 3)]
    assert s_arr_datetime == val_to_string(arr_string)
    assert arr_string == string_to_val(s_arr_datetime, ua.VariantType.String)
    assert arr_datetime == string_to_val(s_arr_datetime, ua.VariantType.DateTime)


def test_string_not_an_array():
    s_not_an_array = "[this] is not an array"
    assert s_not_an_array == string_to_val(s_not_an_array, ua.VariantType.String)


def test_string_to_variant_nodeid():
    s_arr_nodeid = "[ns=2;i=56, i=45]"
    arr_nodeid = [ua.NodeId.from_string("ns=2;i=56"), ua.NodeId.from_string("i=45")]
    assert arr_nodeid == string_to_val(s_arr_nodeid, ua.VariantType.NodeId)


def test_string_to_variant_status_code():
    s_statuscode = "Good"
    statuscode = ua.StatusCode(ua.StatusCodes.Good)
    s_statuscode2 = "Uncertain"
    statuscode2 = ua.StatusCode(ua.StatusCodes.Uncertain)
    assert statuscode == string_to_val(s_statuscode, ua.VariantType.StatusCode)
    assert statuscode2 == string_to_val(s_statuscode2, ua.VariantType.StatusCode)


def test_string_to_variant_qname():
    string = "2:name"
    obj = ua.QualifiedName("name", 2)
    assert obj == string_to_val(string, ua.VariantType.QualifiedName)
    assert string == val_to_string(obj)


def test_string_to_variant_localized_text():
    string = "_This is my nøåæ"
    obj = ua.LocalizedText(string)
    string_repr = f"LocalizedText(Locale=None, Text='{string}')"
    assert obj == string_to_val(string, ua.VariantType.LocalizedText)
    assert string_repr == val_to_string(obj)


def test_string_to_variant_localized_text_with_locale():
    locale = "cs-CZ"
    string = "Moje jméno"
    string_repr = f"LocalizedText(Locale='{locale}', Text='{string}')"
    obj = ua.LocalizedText(string, locale)
    assert obj == string_to_val(string_repr, ua.VariantType.LocalizedText)
    assert string_repr == val_to_string(obj)


def test_string_to_variant_localized_text_with_none1():
    locale = "en-US"
    string = ""
    string_repr = f"LocalizedText(Locale='{locale}', Text='{string}')"
    obj = ua.LocalizedText(string, locale)
    obj2 = ua.LocalizedText(string)
    assert obj == string_to_val(string_repr, ua.VariantType.LocalizedText)
    assert obj2 == string_to_val(string, ua.VariantType.LocalizedText)


def test_string_to_variant_localized_text_with_none2():
    locale = None
    string = "my name is ..."
    string_repr = f"LocalizedText(Locale={locale!r}, Text={string!r})"
    obj = ua.LocalizedText(string, locale)
    assert obj == string_to_val(string_repr, ua.VariantType.LocalizedText)
    assert obj == string_to_val(string, ua.VariantType.LocalizedText)


def test_string_to_val_xml_element():
    string = "<p> titi toto </p>"
    obj = ua.XmlElement(string)
    assert obj == string_to_val(string, ua.VariantType.XmlElement)
    assert string == val_to_string(obj)
    b = struct_to_binary(obj)
    obj2 = struct_from_binary(ua.XmlElement, ua.utils.Buffer(b))
    assert obj == obj2

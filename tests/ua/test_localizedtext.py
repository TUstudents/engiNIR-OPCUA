import pytest

from enginir_opcua import ua
from enginir_opcua.ua.ua_binary import (
    struct_from_binary,
    struct_to_binary,
)


@pytest.mark.parametrize(
    ("text", "locale"),
    [
        ("hello", "en"),
        ("hello", None),
        (None, "en"),
        (None, None),
        ("None", None),
        (None, "None"),
        ("it's", "en"),
        ('say "hi"', None),
        ("a', Text='b", "en"),
        ("", ""),
        ("line\nbreak", "de"),
        ("水", "zh"),
    ],
)
def test_ua54_string_round_trip_null_fields_and_quotes(text: str | None, locale: str | None) -> None:
    """Part 6, 5.2.2.14: both fields are optional and must survive the library string form."""
    original = ua.LocalizedText(text, locale)
    again = ua.LocalizedText.from_string(original.to_string())
    assert (again.Text, again.Locale) == (text, locale)


def test_ua54_plain_string_becomes_text() -> None:
    parsed = ua.LocalizedText.from_string("just text")
    assert (parsed.Text, parsed.Locale) == ("just text", None)
    parsed = ua.LocalizedText.from_string("LocalizedText(Locale=1+1, Text=2)")
    assert parsed.Locale is None
    assert parsed.Text == "LocalizedText(Locale=1+1, Text=2)"


def test_localizedtext_rejects_non_text() -> None:
    with pytest.raises(ValueError):
        ua.LocalizedText(5)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ua.LocalizedText("x", 5)  # type: ignore[arg-type]


def test_text():
    t1 = ua.LocalizedText("Root")
    t2 = ua.LocalizedText("Root")
    t3 = ua.LocalizedText("root")
    assert t1 == t2
    assert t1 != t3
    t4 = struct_from_binary(ua.LocalizedText, ua.utils.Buffer(struct_to_binary(t1)))
    assert t1 == t4


def test_text_simple():
    t = ua.LocalizedText("Root")
    b = struct_to_binary(t)
    buf = ua.utils.Buffer(b)
    print("BUFFER", buf)
    t2 = struct_from_binary(ua.LocalizedText, buf)
    assert t == t2


def test_text_with_locale():
    t0 = ua.LocalizedText("Root")
    t1 = ua.LocalizedText("Root", "de-AT")
    t2 = ua.LocalizedText("Root", "de-AT")
    t3 = ua.LocalizedText("Root", "de-DE")
    t4 = ua.LocalizedText(Locale="de-DE")
    t5 = ua.LocalizedText(Locale="de-DE")
    assert t0 != t1
    assert t1 == t2
    assert t1 != t3
    assert t3 != t4
    assert t4 == t5
    t6 = struct_from_binary(ua.LocalizedText, ua.utils.Buffer(struct_to_binary(t1)))
    assert t1 == t6

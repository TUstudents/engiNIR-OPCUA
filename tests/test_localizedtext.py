import pytest

from enginir_opcua import ua


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

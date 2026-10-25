import time
from datetime import datetime

import pytest
from dateutil.tz import tzutc

from enginir_opcua import ua
from enginir_opcua.common.ua_utils import string_to_val


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

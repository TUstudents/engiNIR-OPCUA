import dataclasses
import uuid
from datetime import UTC, datetime

import pytest

from enginir_opcua import ua


def test_ua28_defaults_are_deterministic_and_null_values() -> None:
    """Part 6, 5.1.2, Table 1: DateTime.MinValue (5.1.4) and an all-zero Guid are the defaults."""
    assert ua.get_default_value(ua.VariantType.DateTime) == datetime(1601, 1, 1, tzinfo=UTC)
    assert ua.get_default_value(ua.VariantType.DateTime) == ua.get_default_value(ua.VariantType.DateTime)
    assert ua.get_default_value(ua.VariantType.Guid) == uuid.UUID(int=0)
    assert ua.get_default_value(ua.VariantType.ByteString) == b""


@pytest.mark.parametrize("vtype", list(ua.VariantType))
def test_default_value_every_variant_type(vtype: ua.VariantType) -> None:
    """Part 6, 5.1.2, Table 1: every built-in type has a default, and it is the same on every call."""
    assert ua.get_default_value(vtype) == ua.get_default_value(vtype)


def test_ua28_diagnostic_info_default_has_no_fields() -> None:
    """Part 6, 5.1.2, Table 1: DiagnosticInfo default is no fields specified."""
    assert ua.get_default_value(ua.VariantType.DiagnosticInfo) == ua.DiagnosticInfo()


def test_default_value_outside_table1_raises() -> None:
    with pytest.raises(RuntimeError):
        ua.get_default_value(ua.VariantTypeCustom(40))  # type: ignore[arg-type]


def _boolean_fields() -> list[tuple[str, str]]:
    result = []
    for name, cls in vars(ua).items():
        if not (
            isinstance(cls, type)
            and cls.__module__ == "enginir_opcua.ua.uaprotocol_auto"
            and dataclasses.is_dataclass(cls)
        ):
            continue
        for field in dataclasses.fields(cls):
            if field.type.strip("'") == "ua.Boolean" and field.default is not dataclasses.MISSING:
                result.append((name, field.name))
    return result


def test_ua_58_boolean_fields_default_to_false() -> None:
    offenders = [
        f"{cls}.{field}"
        for cls, field in _boolean_fields()
        if getattr(ua, cls).__dataclass_fields__[field].default is not False
    ]
    assert offenders == []


def test_ua_58_read_raw_modified_details_defaults() -> None:
    details = ua.ReadRawModifiedDetails()
    assert details.IsReadModified is False
    assert details.ReturnBounds is False


@pytest.mark.parametrize("cls_name,field", _boolean_fields())
def test_ua_58_each_boolean_field(cls_name: str, field: str) -> None:
    assert getattr(getattr(ua, cls_name)(), field) is False

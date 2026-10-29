import dataclasses

import pytest

from enginir_opcua import ua


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

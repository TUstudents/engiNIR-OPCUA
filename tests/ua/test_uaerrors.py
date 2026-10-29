import pytest

import enginir_opcua.ua.uaerrors as uaerrors
from enginir_opcua.ua.uaerrors import UaStatusCodeError

status_code_bad_internal = 0x80020000
status_code_unknown = "Definitely Not A Status Code"


@pytest.fixture()
def errors():
    return {
        "direct": uaerrors.BadInternalError(),
        "indirect": UaStatusCodeError(status_code_bad_internal),
        "unknown": UaStatusCodeError(status_code_unknown),
    }


def test_subclass_selection(errors):
    assert type(errors["direct"]) is uaerrors.BadInternalError
    assert type(errors["indirect"]) is uaerrors.BadInternalError
    assert type(errors["unknown"]) is UaStatusCodeError


def test_code(errors):
    assert errors["direct"].code == status_code_bad_internal
    assert errors["indirect"].code == status_code_bad_internal
    assert errors["unknown"].code == status_code_unknown


def test_string_repr(errors):
    assert "BadInternal" in str(errors["direct"])
    assert "BadInternal" in str(errors["indirect"])


def test_ua2_only_integer_keys_registered() -> None:
    assert all(isinstance(key, int) for key in UaStatusCodeError._subclasses)


def test_ua4_status_code_errors_codes() -> None:
    error = uaerrors.UaStatusCodeErrors([0, status_code_bad_internal, 0x80010000])
    assert error.codes == [0, status_code_bad_internal, 0x80010000]
    assert error.code == status_code_bad_internal
    assert uaerrors.UaStatusCodeErrors([0, 0]).code is None
    assert "BadInternalError" in str(error)


def test_com_78_detail_keyword_is_accepted() -> None:
    error = UaStatusCodeError(0x80010000, detail="why")
    assert isinstance(error, uaerrors.BadUnexpectedError)
    assert error.detail == "why"
    assert "why" in str(error)
    assert uaerrors.BadInternalError(detail="x").detail == "x"

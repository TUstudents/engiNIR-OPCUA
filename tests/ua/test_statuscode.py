import io

import pytest

from enginir_opcua import ua
from enginir_opcua.ua import uaerrors
from enginir_opcua.ua.status_codes import StatusCodes
from enginir_opcua.ua.ua_binary import (
    struct_from_binary,
    struct_to_binary,
)

BAD_NODEID_UNKNOWN = StatusCodes.BadNodeIdUnknown
WITH_INFO_BITS = BAD_NODEID_UNKNOWN | 0x0400


def test_severity_bits_part4_7_38_1() -> None:
    """Part 4, 7.38.1: severity is bits 30 and 31; 0b11 is reserved and treated as Bad."""
    assert ua.StatusCode(0x00000000).is_good()
    assert ua.StatusCode(0x00000400).is_good()
    assert ua.StatusCode(0x40000000).is_uncertain()
    assert ua.StatusCode(0x80000000).is_bad()
    assert ua.StatusCode(0xC0000000).is_bad()


def test_check_raises_unless_good() -> None:
    """Part 4, 7.38.1: only the severity decides; Uncertain raises."""
    ua.StatusCode(0x00000400).check()
    with pytest.raises(uaerrors.UaStatusCodeError):
        ua.StatusCode(0x40000000).check()
    with pytest.raises(uaerrors.UaStatusCodeError):
        ua.StatusCode(BAD_NODEID_UNKNOWN).check()


def test_ua1_info_bits_map_to_subclass() -> None:
    """Part 4, 7.38.1: the top 16 bits identify the condition, the low 16 bits are flags."""
    with pytest.raises(uaerrors.BadNodeIdUnknown):
        ua.StatusCode(WITH_INFO_BITS).check()
    assert type(uaerrors.UaStatusCodeError(WITH_INFO_BITS)) is uaerrors.BadNodeIdUnknown


def test_ua1_code_keeps_info_bits() -> None:
    """Part 4, 7.38.1: the received 32-bit value, flags included, stays available."""
    assert uaerrors.UaStatusCodeError(WITH_INFO_BITS).code == WITH_INFO_BITS
    assert uaerrors.BadNodeIdUnknown(WITH_INFO_BITS).code == WITH_INFO_BITS
    assert uaerrors.BadNodeIdUnknown().code == BAD_NODEID_UNKNOWN
    assert uaerrors.UaStatusCodeError(BAD_NODEID_UNKNOWN).code == BAD_NODEID_UNKNOWN


def test_ua1_str_uses_masked_code() -> None:
    """Part 4, 7.38.1: name and description come from the top 16 bits."""
    assert "BadNodeIdUnknown" in str(uaerrors.UaStatusCodeError(WITH_INFO_BITS))


def test_ua11_name_and_doc_ignore_info_bits() -> None:
    """Part 4, 7.38.1: flag bits do not change the name or the description."""
    code = ua.StatusCode(WITH_INFO_BITS)
    plain = ua.StatusCode(BAD_NODEID_UNKNOWN)
    assert code.name == "BadNodeIdUnknown"
    assert code.doc == plain.doc


def test_ua11_unknown_masked_value_falls_back_to_severity() -> None:
    """Part 4, 7.38.1: an unlisted value is named by its severity."""
    assert ua.StatusCode(0x80FF0123).name == "Bad"
    assert ua.StatusCode(0x40FF0123).name == "Uncertain"
    assert ua.StatusCode(0x00FF0123).name == "Good"


def test_status_code_unknown_name_raises_ua_error() -> None:
    with pytest.raises(ua.UaError):
        ua.StatusCode("Definitely Not A Status Code")


def test_ua1_class_level_code_is_the_class_constant() -> None:
    """Part 4, 7.38.1: the exception class still exposes its own code."""
    assert uaerrors.BadNodeIdUnknown.code == BAD_NODEID_UNKNOWN


def test_status_code_severity():
    good_statuscodes = (ua.StatusCodes.Good, ua.StatusCodes.GoodLocalOverride)
    bad_statuscodes = (ua.StatusCodes.Bad, ua.StatusCodes.BadConditionDisabled)
    uncertain_statuscodes = (ua.StatusCodes.Uncertain, ua.StatusCodes.UncertainSimulatedValue)

    for good_statuscode in good_statuscodes:
        statuscode = ua.StatusCode(good_statuscode)
        assert statuscode.is_good()
        assert not statuscode.is_bad()
        assert not statuscode.is_uncertain()

    for bad_statuscode in bad_statuscodes:
        statuscode = ua.StatusCode(bad_statuscode)
        assert not statuscode.is_good()
        assert statuscode.is_bad()
        assert not statuscode.is_uncertain()

    for uncertain_statuscode in uncertain_statuscodes:
        statuscode = ua.StatusCode(uncertain_statuscode)
        assert not statuscode.is_good()
        assert not statuscode.is_bad()
        assert statuscode.is_uncertain()


def test_status_code_to_string():
    # serialize a status code and deserialize it, name and doc resolution should work just fine
    statuscode = ua.StatusCode(ua.StatusCodes.BadNotConnected)
    statuscode2 = struct_from_binary(
        ua.StatusCode, io.BytesIO(struct_to_binary(ua.StatusCode(ua.StatusCodes.BadNotConnected)))
    )

    assert statuscode == statuscode2
    assert statuscode.value == statuscode2.value

    # properties that are not serialized should still translate properly
    assert statuscode.name == statuscode2.name
    assert statuscode.doc == statuscode2.doc

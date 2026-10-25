import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import diagnosticinfo_to_binary, from_binary, struct_to_binary, variant_from_binary
from enginir_opcua.ua.uaerrors import UaError


def _nested(levels: int) -> ua.DiagnosticInfo:
    info = ua.DiagnosticInfo(SymbolicId=1)
    for _ in range(levels - 1):
        info = ua.DiagnosticInfo(SymbolicId=1, InnerDiagnosticInfo=info)
    return info


def _nested_bytes(levels: int) -> bytes:
    return bytes.fromhex("41 01000000") * (levels - 1) + bytes.fromhex("01 01000000")


def test_ua24_empty_diagnostic_info_is_one_zero_byte() -> None:
    """Part 6, 5.2.2.12: the encoding mask is the only field when nothing is present."""
    assert struct_to_binary(ua.DiagnosticInfo()) == b"\x00"
    assert from_binary(ua.DiagnosticInfo, Buffer(b"\x00")) == ua.DiagnosticInfo()


def test_ua24_diagnostic_info_locale_uses_mask_bit_0x08() -> None:
    """Part 6, 5.2.2.12: Locale is mask bit 0x08."""
    assert struct_to_binary(ua.DiagnosticInfo(Locale=2)) == bytes.fromhex("08 02000000")


def test_ua24_diagnostic_info_localized_text_uses_mask_bit_0x04() -> None:
    """Part 6, 5.2.2.12: LocalizedText is mask bit 0x04."""
    assert struct_to_binary(ua.DiagnosticInfo(LocalizedText=3)) == bytes.fromhex("04 03000000")


def test_ua24_diagnostic_info_symbolic_id_and_namespace_bits() -> None:
    """Part 6, 5.2.2.12: SymbolicId is mask bit 0x01 and the namespace is 0x02."""
    assert struct_to_binary(ua.DiagnosticInfo(SymbolicId=1)) == bytes.fromhex("01 01000000")
    assert struct_to_binary(ua.DiagnosticInfo(NamespaceUri=2)) == bytes.fromhex("02 02000000")


def test_ua24_diagnostic_info_stream_order_is_field_table_order() -> None:
    """Part 6, 5.2.2.12: the stream follows the field table, with Locale before LocalizedText."""
    info = ua.DiagnosticInfo(
        SymbolicId=1,
        NamespaceUri=2,
        Locale=3,
        LocalizedText=4,
        AdditionalInfo="x",
        InnerStatusCode=ua.StatusCode(0x80010000),
    )
    expected = bytes.fromhex("3f 01000000 02000000 03000000 04000000 01000000 78 00000180")
    assert struct_to_binary(info) == expected
    assert from_binary(ua.DiagnosticInfo, Buffer(expected)) == info


def test_ua24_diagnostic_info_decodes_each_mask_bit() -> None:
    """Part 6, 5.2.2.12: the mask bits select the fields."""
    info = from_binary(ua.DiagnosticInfo, Buffer(bytes.fromhex("0c 05000000 06000000")))
    assert info.Locale == 5
    assert info.LocalizedText == 6
    assert info.SymbolicId is None


def test_ua24_inner_diagnostic_info_is_written_inline() -> None:
    """Part 6, 5.2.2.12: InnerDiagnosticInfo is a DiagnosticInfo, not an ExtensionObject."""
    info = ua.DiagnosticInfo(SymbolicId=1, InnerDiagnosticInfo=ua.DiagnosticInfo(SymbolicId=2))
    expected = bytes.fromhex("41 01000000 01 02000000")
    assert struct_to_binary(info) == expected
    decoded = from_binary(ua.DiagnosticInfo, Buffer(expected))
    assert decoded == info
    assert isinstance(decoded.InnerDiagnosticInfo, ua.DiagnosticInfo)


def test_ua24_diagnostic_info_reserved_mask_bit_raises() -> None:
    """Part 6, 5.2.2.12: only seven mask bits are defined."""
    with pytest.raises(ua.UaError):
        from_binary(ua.DiagnosticInfo, Buffer(bytes.fromhex("80")))


def test_ua24_diagnostic_info_nesting_limit_is_10_on_decode() -> None:
    """Part 6, 5.2.2.12: decoders are not expected to support more than 10 levels."""
    assert from_binary(ua.DiagnosticInfo, Buffer(_nested_bytes(10))) == _nested(10)
    with pytest.raises(ua.UaError):
        from_binary(ua.DiagnosticInfo, Buffer(_nested_bytes(11)))
    with pytest.raises(ua.UaError):
        from_binary(ua.DiagnosticInfo, Buffer(_nested_bytes(100_000)))


def test_ua24_diagnostic_info_nesting_limit_is_10_on_encode() -> None:
    """Part 6, 5.2.2.12: decoders are not expected to support more than 10 levels."""
    assert struct_to_binary(_nested(10)) == _nested_bytes(10)
    with pytest.raises(ua.UaError):
        struct_to_binary(_nested(11))


def test_ua24_diagnostic_info_inside_a_structure() -> None:
    """Part 6, 5.2.2.12: DiagnosticInfo is encoded inline wherever it is used."""
    header = ua.ResponseHeader(ServiceDiagnostics=ua.DiagnosticInfo(Locale=2, AdditionalInfo="a"))
    assert from_binary(ua.ResponseHeader, Buffer(struct_to_binary(header))) == header


def test_ua24_diagnostic_info_inside_a_variant_is_rejected() -> None:
    """Part 6, 5.1.9: a Variant can't hold a DiagnosticInfo, so a peer's Variant of type 25 fails to decode."""
    info = ua.DiagnosticInfo(LocalizedText=1, InnerDiagnosticInfo=ua.DiagnosticInfo(Locale=2))
    with pytest.raises(UaError):
        variant_from_binary(Buffer(bytes([ua.VariantType.DiagnosticInfo.value]) + diagnosticinfo_to_binary(info)))

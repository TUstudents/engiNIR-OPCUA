import base64
import uuid

import pytest

from enginir_opcua import ua
from enginir_opcua.ua.uaerrors import UaStringParsingError

WIDGETS = "http://widgets.com/schemas/hello"
ACME = "tag:acme.com,2023:schemas:data#off;"
ACME_ENCODED = "tag:acme.com,2023:schemas:data#off%3B"
GUID = "09087e75-8e5e-499b-954f-f2a9603db28a"
OPAQUE = "M/RbKBsRVkePCePcx24oRA=="


def test_ua12_spec_examples_part6_5_1_12() -> None:
    """Part 6, 5.1.12, Tables 5 and 6: the example strings read back and are written unchanged."""
    examples = [
        "i=13",
        "ns=10;i=12345",
        f"nsu={WIDGETS};s=水 World",
        f"g={GUID}",
        f"nsu={ACME_ENCODED};b={OPAQUE}",
        f"svr=1;nsu={WIDGETS};s=水 World",
    ]
    for text in examples:
        assert ua.NodeId.from_string(text).to_string() == text


def test_ua12_parse_svr_and_nsu() -> None:
    """Part 6, 5.1.12, Table 6; 5.2.2.10: the server index and the URI replace the namespace index."""
    parsed = ua.NodeId.from_string(f"svr=1;nsu={WIDGETS};s=hello")
    assert isinstance(parsed, ua.ExpandedNodeId)
    assert (parsed.ServerIndex, parsed.NamespaceUri, parsed.NamespaceIndex) == (1, WIDGETS, 0)
    assert parsed.Identifier == "hello"
    parsed = ua.NodeId.from_string(f"nsu={ACME_ENCODED};i=5")
    assert isinstance(parsed, ua.ExpandedNodeId)
    assert parsed.NamespaceUri == ACME


def test_ua12_to_string_order_server_namespace_identifier() -> None:
    """Part 6, 5.1.12, Table 6: svr first, then ns or nsu, identifier last; never ns and nsu together."""
    assert ua.ExpandedNodeId(5, 2, ServerIndex=3).to_string() == "svr=3;ns=2;i=5"
    assert ua.ExpandedNodeId(5, 2, NamespaceUri="urn:x", ServerIndex=3).to_string() == "svr=3;nsu=urn:x;i=5"
    assert ua.ExpandedNodeId(5, 2, NamespaceUri="urn:x").to_string() == "nsu=urn:x;i=5"
    assert ua.ExpandedNodeId(5, 2).to_string() == "ns=2;i=5"


def test_ua12_opc_ua_namespace_uri_uses_bare_identifier() -> None:
    """Part 6, 5.1.12, Table 5: the OPC UA namespace URI is not written."""
    node = ua.ExpandedNodeId(2253, NamespaceUri="http://opcfoundation.org/UA/")
    assert node.to_string() == "i=2253"


def test_ua12_uri_percent_encoding_semicolon() -> None:
    """Part 6, 5.1.12: a semicolon in the URI is percent-encoded."""
    node = ua.ExpandedNodeId("x", NamespaceUri="urn:a;b%c")
    assert node.to_string() == "nsu=urn:a%3Bb%25c;s=x"
    assert ua.NodeId.from_string(node.to_string()) == node


def test_ua13_server_index_zero_with_nsu() -> None:
    """Part 6, 5.2.2.10: ServerIndex is 0 when only the URI is given."""
    parsed = ua.NodeId.from_string("nsu=urn:x;i=5")
    assert isinstance(parsed, ua.ExpandedNodeId)
    assert parsed.ServerIndex == 0


def test_legacy_srv_prefix_accepted_trailing_form_rejected() -> None:
    """Part 6, 5.1.12: `srv=` is a legacy spelling of `svr=` in prefix position only."""
    parsed = ua.NodeId.from_string("srv=2;ns=1;i=5")
    assert isinstance(parsed, ua.ExpandedNodeId)
    assert parsed.ServerIndex == 2
    trailing = ua.NodeId.from_string("s=abc;srv=2;nsu=urn:x")
    assert not isinstance(trailing, ua.ExpandedNodeId)
    assert trailing.Identifier == "abc;srv=2;nsu=urn:x"


def test_svu_rejected_with_parsing_error() -> None:
    """Part 6, 5.1.12, Table 6: the class has no field for a server URI."""
    with pytest.raises(UaStringParsingError):
        ua.NodeId.from_string("svu=http://smith.com/east/factory;i=5")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "ns=2",
        "i=5;ns=3",
        "x=1;i=5",
        "ns=a;i=5",
        "ns=2;i=x",
        "i=-5",
        "svr=x;i=5",
        "g=not-a-guid",
        "ns=2;ns=3;i=5",
        "ns=2;nsu=urn:x;i=5",
        "i=5;i=6",
        "ns=1;svr=2;i=5",
        "b=A",
    ],
)
def test_ua18_unknown_key_and_trailing_component_rejected(text: str) -> None:
    """Part 6, 5.1.12: only the grammar of Tables 5 and 6 is accepted."""
    with pytest.raises(UaStringParsingError):
        ua.NodeId.from_string(text)


def test_ua18_bytestring_base64_only() -> None:
    """Part 6, 5.1.12, Table 5: opaque identifiers are Base64."""
    assert ua.NodeId.from_string(f"b={OPAQUE}").Identifier == base64.b64decode(OPAQUE)
    for text in ("b=0x0102", "b=raw bytes!", "b=abc"):
        with pytest.raises(UaStringParsingError):
            ua.NodeId.from_string(text)
    assert ua.NodeId.from_string("b=AQID").Identifier == b"\x01\x02\x03"


def test_string_identifier_keeps_semicolons() -> None:
    """Part 3, 8.2.4: a String identifier may contain semicolons and equals signs."""
    node = ua.NodeId.from_string("ns=9;s=Line1.nsuri=MACHINE.NS;s=MACHINE.NS.State.Running")
    assert node.Identifier == "Line1.nsuri=MACHINE.NS;s=MACHINE.NS.State.Running"
    assert node.NamespaceIndex == 9


def _round_trip_cases() -> list[ua.NodeId]:
    return [
        ua.NodeId(),
        ua.NodeId(5, 3),
        ua.NodeId(70000, 300),
        ua.NodeId("a;b=c", 2),
        ua.NodeId("水 World", 2),
        ua.NodeId("", 1),
        ua.NodeId(uuid.UUID(GUID), 1),
        ua.NodeId(b"\x00\xff\x10", 4),
        ua.ExpandedNodeId("x", NamespaceUri="urn:a;b%c;d", ServerIndex=7),
        ua.ExpandedNodeId(b"abc", NamespaceUri="urn:%3B", ServerIndex=1),
        ua.ExpandedNodeId(8, 2, ServerIndex=9),
        ua.ExpandedNodeId("s;i=1", NamespaceUri="urn:水"),
    ]


@pytest.mark.parametrize("node", _round_trip_cases())
def test_nodeid_string_round_trip_property(node: ua.NodeId) -> None:
    """Part 6, 5.1.12: the written form reads back to an equal value."""
    assert ua.NodeId.from_string(node.to_string()) == node


def test_single_trailing_semicolon_after_non_string_identifier_is_tolerated() -> None:
    assert ua.NodeId.from_string("ns=3;i=888;") == ua.NodeId(888, 3)
    assert ua.NodeId.from_string("s=a;").Identifier == "a;"

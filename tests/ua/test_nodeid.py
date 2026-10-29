import io
import uuid

import pytest

from enginir_opcua import ua
from enginir_opcua.ua.ua_binary import (
    nodeid_from_binary,
    nodeid_to_binary,
    variant_from_binary,
    variant_to_binary,
)


def test_ua17_incompatible_identifier_rejected() -> None:
    """Part 6, 5.2.2.9, Tables 17 to 20: identifier kind and Python type must agree."""
    with pytest.raises(ua.UaError):
        ua.NodeId("abc", 0, ua.NodeIdType.ByteString)
    with pytest.raises(ua.UaError):
        ua.NodeId(b"abc", 0, ua.NodeIdType.TwoByte)
    with pytest.raises(ua.UaError):
        ua.NodeId(b"abc", 1, ua.NodeIdType.FourByte)
    with pytest.raises(ua.UaError):
        ua.NodeId(5, 0, ua.NodeIdType.String)
    ua.NodeId(b"abc", 0, ua.NodeIdType.ByteString)
    ua.NodeId("abc", 0, ua.NodeIdType.String)


def test_nodeid_type_guess() -> None:
    """Part 6, 5.2.2.9."""
    assert ua.NodeId(5).NodeIdType is ua.NodeIdType.TwoByte
    assert ua.NodeId(5, 3).NodeIdType is ua.NodeIdType.FourByte
    assert ua.NodeId(70000, 3).NodeIdType is ua.NodeIdType.Numeric
    assert ua.NodeId("a").NodeIdType is ua.NodeIdType.String
    assert ua.NodeId(b"a").NodeIdType is ua.NodeIdType.ByteString
    assert ua.NodeId(uuid.uuid4()).NodeIdType is ua.NodeIdType.Guid


def test_ua20_limit_messages_name_the_limit() -> None:
    with pytest.raises(ValueError, match="NamespaceIndex > 255"):
        ua.FourByteNodeId(5, 300)
    with pytest.raises(ValueError, match="TwoByteNodeId cannot have NamespaceIndex != 0"):
        ua.TwoByteNodeId(5, 1)


def test_ua21_lt_non_nodeid_type_error() -> None:
    """Python data model: comparing with a foreign type yields TypeError."""
    with pytest.raises(TypeError):
        ua.NodeId(1) < 5  # type: ignore[operator]
    with pytest.raises(TypeError):
        ua.NodeId(1) < "i=1"  # type: ignore[operator]


def test_ua55_order_consistent_with_equality() -> None:
    """Part 6, 5.2.2.9: FourByte and Numeric are encodings of one NodeId, so they sort alike."""
    four = ua.FourByteNodeId(9, 1)
    numeric = ua.NumericNodeId(9, 1)
    assert four == numeric
    assert not four < numeric
    assert not numeric < four
    assert sorted([ua.NumericNodeId(3, 1), ua.FourByteNodeId(9, 1)]) == [ua.NodeId(3, 1), ua.NodeId(9, 1)]
    assert ua.NodeId(1, 1) <= ua.NodeId(1, 1)
    assert ua.NodeId(2, 1) > ua.NodeId(1, 1)
    assert ua.NodeId(2, 1) >= ua.NodeId(1, 1)


def test_ua55_order_by_family_namespace_identifier() -> None:
    """Design: numeric, string, Guid, opaque; then namespace; then identifier."""
    nodes = [
        ua.NodeId(b"aaa", 5, ua.NodeIdType.ByteString),
        ua.NodeId(uuid.UUID(int=1), 1),
        ua.NodeId("b", 2),
        ua.NodeId("a", 2),
        ua.NodeId("z", 1),
        ua.NumericNodeId(70000, 0),
        ua.FourByteNodeId(3, 1),
        ua.TwoByteNodeId(201),
    ]
    assert sorted(nodes) == [
        ua.TwoByteNodeId(201),
        ua.NumericNodeId(70000, 0),
        ua.FourByteNodeId(3, 1),
        ua.NodeId("z", 1),
        ua.NodeId("a", 2),
        ua.NodeId("b", 2),
        ua.NodeId(uuid.UUID(int=1), 1),
        ua.NodeId(b"aaa", 5, ua.NodeIdType.ByteString),
    ]


def test_ua14_expanded_equality_includes_uri_and_server() -> None:
    """Part 6, 5.2.2.10: the URI and the server index are part of an ExpandedNodeId."""
    assert ua.ExpandedNodeId(1, NamespaceUri="a") != ua.ExpandedNodeId(1, NamespaceUri="b")
    assert ua.ExpandedNodeId(1, ServerIndex=1) != ua.ExpandedNodeId(1, ServerIndex=2)
    assert ua.ExpandedNodeId(1, NamespaceUri="a") == ua.ExpandedNodeId(1, 5, NamespaceUri="a")
    assert hash(ua.ExpandedNodeId(1, NamespaceUri="a")) == hash(ua.ExpandedNodeId(1, 5, NamespaceUri="a"))
    assert len({ua.ExpandedNodeId(1, NamespaceUri="a"), ua.ExpandedNodeId(1, NamespaceUri="b")}) == 2


def test_ua14_plain_nodeid_equals_expanded_only_without_uri_and_server() -> None:
    """Design: a local ExpandedNodeId is the same node as the plain NodeId."""
    plain = ua.NodeId(5, 2)
    assert plain == ua.ExpandedNodeId(5, 2)
    assert ua.ExpandedNodeId(5, 2) == plain
    assert hash(plain) == hash(ua.ExpandedNodeId(5, 2))
    assert plain != ua.ExpandedNodeId(5, 2, ServerIndex=1)
    assert ua.ExpandedNodeId(5, 2, ServerIndex=1) != plain
    assert plain != ua.ExpandedNodeId(5, 2, NamespaceUri="urn:x")
    assert ua.ExpandedNodeId(5, 2, NamespaceUri="urn:x") != plain


def test_null_nodeid_alternatives_part3_8_2_4() -> None:
    """Part 3, 8.2.4, Table 24."""
    assert ua.NodeId().is_null()
    assert ua.NodeId("", 0).is_null()
    assert ua.NodeId(uuid.UUID(int=0), 0).is_null()
    assert ua.NodeId(b"", 0).is_null()
    assert not ua.NodeId(0, 1).is_null()


def test_ua49_expanded_node_id_with_uri_encodes_namespace_index_zero() -> None:
    """Part 6, 5.2.2.10: the NamespaceIndex in the stream is 0 when the NamespaceUri is present."""
    node = ua.ExpandedNodeId(100, 2, NamespaceUri="urn:x", ServerIndex=4)
    expected = bytes.fromhex("c100640005000000" + b"urn:x".hex() + "04000000")
    assert nodeid_to_binary(node) == expected
    again = nodeid_from_binary(ua.utils.Buffer(expected))
    assert again == node


def test_ua49_expanded_node_id_without_uri_keeps_index() -> None:
    """Part 6, 5.2.2.10."""
    assert nodeid_to_binary(ua.ExpandedNodeId(100, 2)) == bytes.fromhex("01026400")


def test_limits_not_enforced_by_constructor() -> None:
    """Design: Part 3, 8.2.4 limits are enforced where nodes are added."""
    assert ua.NodeId("x" * 5000, 1).Identifier == "x" * 5000


def test_nodeid_nsu():
    n1 = ua.ExpandedNodeId(100, 2, NamespaceUri="http://freeopcua/tests", ServerIndex=4)
    data = nodeid_to_binary(n1)
    n2 = nodeid_from_binary(ua.utils.Buffer(data))
    assert n1 == n2
    string = n1.to_string()
    n3 = ua.NodeId.from_string(string)
    assert n1 == n3


def test_nodeid_ordering():
    a = ua.NodeId(2000, 1)
    b = ua.NodeId(3000, 1)
    c = ua.NodeId(20, 0)
    d = ua.NodeId("tititu", 1)
    e = ua.NodeId("aaaaa", 1)
    f = ua.NodeId("aaaaa", 2)
    g = ua.NodeId(uuid.uuid4(), 1)
    h = ua.TwoByteNodeId(201)
    i = ua.NodeId(b"lkjkl", 1, ua.NodeIdType.ByteString)
    j = ua.NodeId(b"aaa", 5, ua.NodeIdType.ByteString)

    mylist = [a, b, c, d, e, f, g, h, i, j]
    mylist.sort()
    expected = [c, h, a, b, e, d, f, g, i, j]
    assert mylist == expected


def test_guid():
    v = ua.Variant(uuid.uuid4(), ua.VariantType.Guid)
    v2 = variant_from_binary(ua.utils.Buffer(variant_to_binary(v)))
    assert v.VariantType == v2.VariantType
    assert v == v2


def test_nodeid_guid_string():
    n = ua.GuidNodeId(Identifier=uuid.uuid4())
    s = n.to_string()
    n2 = ua.NodeId.from_string(s)
    s2 = n2.to_string()
    assert n == n2
    assert s == s2


def test_nodeid_bytestring():
    n = ua.ByteStringNodeId(Identifier=b"qwerty", NamespaceIndex=1)
    s = n.to_string()
    n2 = ua.NodeId.from_string(s)
    s2 = n2.to_string()
    assert n == n2
    assert s == s2
    n = ua.ByteStringNodeId(Identifier=b"\x01\x00\x05\x55")
    s = n.to_string()
    n2 = ua.NodeId.from_string(s)
    s2 = n2.to_string()
    assert n == n2
    assert s == s2
    with pytest.raises(ua.UaStringParsingError):
        ua.NodeId.from_string("b=0xaabbccdd")


def test__nodeid():
    nid = ua.NodeId()
    assert nid.NodeIdType == ua.NodeIdType.TwoByte
    nid = ua.NodeId(446, 3, ua.NodeIdType.FourByte)
    assert nid.NodeIdType == ua.NodeIdType.FourByte
    d = nodeid_to_binary(nid)
    new_nid = nodeid_from_binary(io.BytesIO(d))
    assert new_nid == nid
    assert new_nid.NodeIdType == ua.NodeIdType.FourByte
    assert new_nid.Identifier == 446
    assert new_nid.NamespaceIndex == 3

    tb = ua.TwoByteNodeId(53)
    fb = ua.FourByteNodeId(53)
    n = ua.NumericNodeId(53)
    n1 = ua.NumericNodeId(53, 0)
    s1 = ua.StringNodeId("53", 0)
    bs = ua.ByteStringNodeId(b"53", 0)
    gid = uuid.uuid4()
    g = ua.ByteStringNodeId(gid.bytes, 0)
    guid = ua.GuidNodeId(gid)
    assert tb == n
    assert tb == n1
    assert n1 == fb
    assert g != guid
    assert tb == nodeid_from_binary(ua.utils.Buffer(nodeid_to_binary(tb)))
    assert fb == nodeid_from_binary(ua.utils.Buffer(nodeid_to_binary(fb)))
    assert n == nodeid_from_binary(ua.utils.Buffer(nodeid_to_binary(n)))
    assert s1 == nodeid_from_binary(ua.utils.Buffer(nodeid_to_binary(s1)))
    assert bs == nodeid_from_binary(ua.utils.Buffer(nodeid_to_binary(bs)))
    assert guid == nodeid_from_binary(ua.utils.Buffer(nodeid_to_binary(guid)))


def test_nodeid_string():
    nid0 = ua.NodeId(45)
    assert nid0 == ua.NodeId.from_string("i=45")
    assert nid0 == ua.NodeId.from_string("ns=0;i=45")
    nid = ua.NodeId(45, 10)
    assert nid == ua.NodeId.from_string("ns=10;i=45")
    assert nid != ua.NodeId.from_string("ns=11;i=45")
    assert nid != ua.NodeId.from_string("ns=10;i=5")
    assert nid != ua.NodeId.from_string("svr=3;ns=10;i=45")
    nid1 = ua.NodeId("myid.mynodeid", 7)
    assert nid1 == ua.NodeId.from_string("ns=7;s=myid.mynodeid")


def test_expandednodeid():
    nid = ua.ExpandedNodeId()
    assert nid.NodeIdType == ua.NodeIdType.TwoByte
    nid2 = nodeid_from_binary(ua.utils.Buffer(nodeid_to_binary(nid)))
    assert nid == nid2


def test_equal_nodeid():
    nid1 = ua.NodeId(999, 2)
    nid2 = ua.NodeId(999, 2)
    assert nid1 == nid2
    assert id(nid1) != id(nid2)


def test_to_nodeid_int_ranges():
    """_to_nodeid must encode large integer identifiers (GH-1831).

    Standard reference types such as HasDictionaryEntry (17597) exceed the
    TwoByteNodeId range and previously raised ValueError.
    """
    from enginir_opcua.common.node import _to_nodeid

    # Inclusive TwoByte upper bound (0..255)
    for value in (0, 53, 255):
        n = _to_nodeid(value)
        assert n.NodeIdType == ua.NodeIdType.TwoByte
        assert n.Identifier == value
        assert n.NamespaceIndex == 0

    # FourByte for mid-range identifiers (256..65535), ns=0
    for value in (256, ua.ObjectIds.HasDictionaryEntry, 65535):
        n = _to_nodeid(value)
        assert n.NodeIdType == ua.NodeIdType.FourByte
        assert n.Identifier == value

    # Numeric for identifiers beyond uint16
    n = _to_nodeid(65536)
    assert n.NodeIdType == ua.NodeIdType.Numeric
    assert n.Identifier == 65536

    n = _to_nodeid(70000)
    assert n.NodeIdType == ua.NodeIdType.Numeric
    assert n.Identifier == 70000


def test_nodeid_encoding_range_bounds():
    """NodeId auto-encoding must use inclusive TwoByte/FourByte bounds.

    TwoByteNodeId allows Identifier 0..255; FourByteNodeId allows
    Identifier 0..65535 and NamespaceIndex 0..255.  The previous
    NodeId.__post_init__ used strict < checks, so Identifier 255 and
    NamespaceIndex 255 were classified one encoding wider than needed.
    """
    assert ua.NodeId(255).NodeIdType == ua.NodeIdType.TwoByte
    assert ua.NodeId(256).NodeIdType == ua.NodeIdType.FourByte
    assert ua.NodeId(65535).NodeIdType == ua.NodeIdType.FourByte
    assert ua.NodeId(65536).NodeIdType == ua.NodeIdType.Numeric

    # NamespaceIndex 255 still fits in the FourByte namespace byte
    assert ua.NodeId(1, 255).NodeIdType == ua.NodeIdType.FourByte
    assert ua.NodeId(1, 256).NodeIdType == ua.NodeIdType.Numeric

    # Subclass constructors stay consistent with auto-guess
    assert ua.TwoByteNodeId(255).NodeIdType == ua.NodeIdType.TwoByte
    assert ua.FourByteNodeId(65535, 255).NodeIdType == ua.NodeIdType.FourByte


def test_zero_nodeid():
    assert ua.NodeId() == ua.NodeId(0, 0)
    assert ua.NodeId() == ua.NodeId.from_string("ns=0;i=0;")


def test_string_nodeid():
    nid = ua.NodeId("titi", 1)
    assert nid.NamespaceIndex == 1
    assert nid.Identifier == "titi"
    assert nid.NodeIdType == ua.NodeIdType.String


def test_unicode_string_nodeid():
    nid = ua.NodeId("hëllò", 1)
    assert nid.NamespaceIndex == 1
    assert nid.Identifier == "hëllò"
    assert nid.NodeIdType == ua.NodeIdType.String
    d = nodeid_to_binary(nid)
    new_nid = nodeid_from_binary(io.BytesIO(d))
    assert new_nid == nid
    assert new_nid.Identifier == "hëllò"
    assert new_nid.NodeIdType == ua.NodeIdType.String


def test_numeric_nodeid():
    nid = ua.NumericNodeId(999, 2)
    assert nid.NamespaceIndex == 2
    assert nid.Identifier == 999
    assert nid.NodeIdType == ua.NodeIdType.Numeric


def test_qualifiedstring_nodeid():
    nid = ua.NodeId.from_string("ns=2;s=PLC1.Manufacturer")
    assert nid.NamespaceIndex == 2
    assert nid.Identifier == "PLC1.Manufacturer"


def test_strrepr_nodeid():
    nid = ua.NodeId.from_string("ns=2;s=PLC1.Manufacturer")
    assert nid.to_string() == "ns=2;s=PLC1.Manufacturer"


def test_null():
    n = ua.NodeId()
    assert n.is_null()
    assert n.has_null_identifier()

    n = ua.NodeId(0, 0)
    assert n.is_null()
    assert n.has_null_identifier()

    n = ua.NodeId("", 0)
    assert n.is_null()
    assert n.has_null_identifier()

    n = ua.TwoByteNodeId(0)
    assert n.is_null()
    assert n.has_null_identifier()

    n = ua.NodeId(0, 3)
    assert n.is_null() is False
    assert n.has_null_identifier()


def test_expandedNodeId():
    d = b"\x40\x55\x00\x00\x00\x00"
    nid = nodeid_from_binary(ua.utils.Buffer(d))
    assert isinstance(nid, ua.ExpandedNodeId)
    assert nid.ServerIndex == 0
    assert nid.Identifier == 85

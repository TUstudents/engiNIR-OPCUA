import uuid

import pytest

from enginir_opcua import ua
from enginir_opcua.ua.ua_binary import nodeid_from_binary, nodeid_to_binary


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

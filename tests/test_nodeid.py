from enginir_opcua import ua
from enginir_opcua.ua.ua_binary import nodeid_from_binary, nodeid_to_binary


def test_ua49_expanded_node_id_with_uri_encodes_namespace_index_zero() -> None:
    """Part 6, 5.2.2.10: the NamespaceIndex in the stream is 0 when the NamespaceUri is present."""
    node = ua.ExpandedNodeId(100, 2, NamespaceUri="urn:x", ServerIndex=4)
    expected = bytes.fromhex("c100640005000000" + b"urn:x".hex() + "04000000")
    assert nodeid_to_binary(node) == expected
    again = nodeid_from_binary(ua.utils.Buffer(expected))
    assert isinstance(again, ua.ExpandedNodeId)
    assert (again.Identifier, again.NamespaceUri, again.ServerIndex) == (100, "urn:x", 4)


def test_ua49_expanded_node_id_without_uri_keeps_index() -> None:
    """Part 6, 5.2.2.10."""
    assert nodeid_to_binary(ua.ExpandedNodeId(100, 2)) == bytes.fromhex("01026400")

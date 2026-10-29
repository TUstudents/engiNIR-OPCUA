import pytest

from enginir_opcua import ua
from enginir_opcua.ua.ua_binary import (
    struct_from_binary,
    struct_to_binary,
)
from enginir_opcua.ua.uaerrors import UaStringParsingError


def test_ua15_swapped_arguments_type_error() -> None:
    """Part 6, 5.2.2.13: a QualifiedName is a name and a UInt16 index."""
    with pytest.raises(TypeError, match="swapped"):
        ua.QualifiedName(1, "x")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ua.QualifiedName("x", "y")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ua.QualifiedName(5)  # type: ignore[arg-type]


def test_ua15_swapped_arguments_do_not_log(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(TypeError):
        ua.QualifiedName(1, "x")  # type: ignore[arg-type]
    assert not caplog.records


def test_ua16_namespace_index_uint16_round_trip() -> None:
    """Part 6, 5.2.2.13: the NamespaceIndex is a UInt16."""
    for index in (0, 32767, 32768, 40000, 65535):
        name = ua.QualifiedName("x", index)
        again = struct_from_binary(ua.QualifiedName, ua.utils.Buffer(struct_to_binary(name)))
        assert again == name


def test_ua46_ns0_has_no_prefix_part6_table7() -> None:
    """Part 6, 5.1.12, Table 7: names in the OPC UA namespace use the form without a prefix."""
    assert ua.QualifiedName("InputArguments").to_string() == "InputArguments"
    assert ua.QualifiedName("Hello:World", 3).to_string() == "3:Hello:World"
    assert ua.QualifiedName("", 2).to_string() == "2:"


def test_ua46_ns0_name_that_looks_like_prefix_raises() -> None:
    """Part 6, 5.1.12, Table 7: such a name is prohibited in namespace 0."""
    with pytest.raises(ua.UaError):
        ua.QualifiedName("3:x").to_string()


def test_ua46_name_with_colon() -> None:
    """Part 6, 5.1.12, Table 7: everything after the first index colon is the name."""
    parsed = ua.QualifiedName.from_string("3:Hello:World")
    assert (parsed.NamespaceIndex, parsed.Name) == (3, "Hello:World")
    parsed = ua.QualifiedName.from_string("a:b")
    assert (parsed.NamespaceIndex, parsed.Name) == (0, "a:b")
    parsed = ua.QualifiedName.from_string("InputArguments", default_idx=4)
    assert (parsed.NamespaceIndex, parsed.Name) == (4, "InputArguments")
    parsed = ua.QualifiedName.from_string("0:Name")
    assert (parsed.NamespaceIndex, parsed.Name) == (0, "Name")


def test_ua46_nsu_form_with_namespace_table() -> None:
    """Part 6, 5.1.12, Table 7: nsu=<uri>;<name> needs the namespace table to find the index."""
    table = ["http://opcfoundation.org/UA/", "urn:a", "tag:acme.com,2023:schemas:data#off;"]
    parsed = ua.QualifiedName.from_string("nsu=tag:acme.com,2023:schemas:data#off%3B;Boiler2", namespaces=table)
    assert (parsed.NamespaceIndex, parsed.Name) == (2, "Boiler2")
    parsed = ua.QualifiedName.from_string("nsu=urn:a;Hello;World", namespaces=table)
    assert (parsed.NamespaceIndex, parsed.Name) == (1, "Hello;World")
    with pytest.raises(UaStringParsingError):
        ua.QualifiedName.from_string("nsu=urn:a;Boiler2")
    with pytest.raises(UaStringParsingError):
        ua.QualifiedName.from_string("nsu=urn:unknown;Boiler2", namespaces=table)
    with pytest.raises(UaStringParsingError):
        ua.QualifiedName.from_string("nsu=urn:a", namespaces=table)


def test_qualifiedname_string():
    qname1 = ua.QualifiedName.from_string("Name")
    assert (0, "Name") == (qname1.NamespaceIndex, qname1.Name)
    qname2 = ua.QualifiedName.from_string("1:Name")
    assert (1, "Name") == (qname2.NamespaceIndex, qname2.Name)
    qname3 = ua.QualifiedName.from_string("Name", default_idx=2)
    assert (2, "Name") == (qname3.NamespaceIndex, qname3.Name)
    qname4 = ua.QualifiedName.from_string("3:Name", default_idx=2)
    assert (3, "Name") == (qname4.NamespaceIndex, qname4.Name)


def test_bad_string():
    with pytest.raises(ua.UaStringParsingError):
        ua.NodeId.from_string("ns=r;s=yu")
    with pytest.raises(ua.UaStringParsingError):
        ua.NodeId.from_string("i=r;ns=1")
    with pytest.raises(ua.UaStringParsingError):
        ua.NodeId.from_string("ns=1")
    assert ua.QualifiedName.from_string("i:yu").Name == "i:yu"
    assert ua.QualifiedName.from_string("i:::yu").Name == "i:::yu"


def test_qualified_name():
    qn = ua.QualifiedName("qname", 2)
    assert qn.NamespaceIndex == 2
    assert qn.Name == "qname"
    assert qn.to_string() == "2:qname"


def test_bname():
    qn = ua.QualifiedName("TOTO", 2)
    d = struct_to_binary(qn)
    qn2 = struct_from_binary(ua.QualifiedName, ua.utils.Buffer(d))
    assert qn == qn2

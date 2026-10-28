import datetime

import pytest

from enginir_opcua.common.xmlparser import XMLParser

HEADER = (
    '<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd" '
    'xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
)


def parse(body: str) -> list:
    parser = XMLParser(keep_empty_body_values=True)
    parser.parse_sync(xmlstring=f"{HEADER}{body}</UANodeSet>")
    return parser.get_node_datas()


def variable(value: str, datatype: str = "i=24") -> str:
    return f'<UAVariable NodeId="i=1" BrowseName="1:V" DataType="{datatype}"><Value>{value}</Value></UAVariable>'


@pytest.mark.parametrize(
    ("value", "expected_type"),
    [
        ("<uax:LocalizedText><uax:Locale>en</uax:Locale><uax:Text>hi</uax:Text></uax:LocalizedText>", "LocalizedText"),
        ("<uax:NodeId><uax:Identifier>ns=1;i=5</uax:Identifier></uax:NodeId>", "NodeId"),
        (
            "<uax:QualifiedName><uax:NamespaceIndex>1</uax:NamespaceIndex><uax:Name>n</uax:Name></uax:QualifiedName>",
            "QualifiedName",
        ),
        ("<uax:StatusCode><uax:Code>2147483648</uax:Code></uax:StatusCode>", "StatusCode"),
        ("<uax:Guid><uax:String>3b2b8ea4-0e0e-4b8e-9d3a-0f6c0c9f2b11</uax:String></uax:Guid>", "Guid"),
        ("<uax:ListOfInt32><uax:Int32>1</uax:Int32><uax:Int32>2</uax:Int32></uax:ListOfInt32>", "ListOfInt32"),
    ],
)
def test_com80_compound_value_without_white_space(value: str, expected_type: str) -> None:
    pretty = parse(variable(f"\n{value}\n"))[0]
    minified = parse(variable(value))[0]
    assert minified.valuetype == expected_type
    assert minified.value is not None
    assert minified.value == pretty.value


def test_com80_extension_object_without_white_space() -> None:
    value = (
        "<uax:ExtensionObject><uax:TypeId><uax:Identifier>i=297</uax:Identifier></uax:TypeId>"
        "<uax:Body><Argument><Name>x</Name></Argument></uax:Body></uax:ExtensionObject>"
    )
    data = parse(variable(value))[0]
    assert data.valuetype == "ExtensionObject"
    assert data.value.objname == "Argument"
    assert data.value.body == [("Argument", [("Name", "x")])]


def test_com80_document_without_default_namespace() -> None:
    parser = XMLParser()
    parser.parse_sync(xmlstring='<UANodeSet><UAObject NodeId="i=1" BrowseName="1:O"/></UANodeSet>')
    assert [node.nodeid for node in parser.get_node_datas()] == ["i=1"]


@pytest.mark.parametrize(("text", "expected"), [("true", True), ("false", False), ("1", True), ("0", False)])
def test_com48_xml_schema_booleans(text: str, expected: bool) -> None:
    data = parse(f'<UADataType NodeId="i=1" BrowseName="1:T"><Definition Name="1:T" IsUnion="{text}"/></UADataType>')[0]
    assert (data.struct_type == "IsUnion") is expected


def test_com48_optional_false_is_not_optional() -> None:
    body = (
        '<UADataType NodeId="i=1" BrowseName="1:T"><Definition Name="1:T">'
        '<Field Name="A" DataType="i=6" IsOptional="false"/><Field Name="B" DataType="i=6" IsOptional="true"/>'
        "</Definition></UADataType>"
    )
    fields = parse(body)[0].definitions
    assert [f.optional for f in fields] == [False, True]


def test_com48_invalid_boolean_raises() -> None:
    with pytest.raises(ValueError, match="maybe"):
        parse('<UAVariable NodeId="i=1" BrowseName="1:V" Historizing="maybe"/>')


def test_com49_naive_datetime_is_utc() -> None:
    data = parse(variable("<uax:DateTime>2020-01-02T03:04:05</uax:DateTime>"))[0]
    assert data.value == datetime.datetime(2020, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)


def test_com49_datetime_with_offset_is_converted() -> None:
    data = parse(variable("<uax:DateTime>2020-01-02T03:04:05+01:00</uax:DateTime>"))[0]
    assert data.value == datetime.datetime(2020, 1, 2, 2, 4, 5, tzinfo=datetime.UTC)


@pytest.mark.parametrize("tag", ["String", "XmlElement"])
def test_com49_empty_string_value(tag: str) -> None:
    data = parse(variable(f"<uax:{tag}/>"))[0]
    assert data.valuetype == tag
    assert getattr(data.value, "Value", data.value) == ""


def test_com49_nil_string_is_null() -> None:
    data = parse(variable('<uax:String xsi:nil="true"/>'))[0]
    assert data.value is None


def test_com50_empty_values_survive_in_extension_object_body() -> None:
    value = (
        "<uax:ExtensionObject><uax:TypeId><uax:Identifier>i=1</uax:Identifier></uax:TypeId>"
        "<uax:Body><S><Name></Name><Number>3</Number></S></uax:Body></uax:ExtensionObject>"
    )
    data = parse(variable(value))[0]
    assert data.value.body == [("S", [("Name", ""), ("Number", "3")])]


def test_com50_publication_date_with_fraction() -> None:
    parser = XMLParser()
    parser.parse_sync(
        xmlstring=f'{HEADER}<Models><Model ModelUri="u" Version="1" PublicationDate="2020-01-02T03:04:05.250Z"/>'
        f"</Models></UANodeSet>"
    )
    ((_, _, date),) = parser.get_nodeset_namespaces()
    assert date.year == 2020 and date.microsecond == 250000


def test_com50_picks_empty_locale_display_name() -> None:
    body = (
        '<UAObject NodeId="i=1" BrowseName="1:O"><DisplayName Locale="de">Objekt</DisplayName>'
        "<DisplayName>Object</DisplayName></UAObject>"
    )
    assert parse(body)[0].displayname == "Object"


def test_com81_server_uris_are_not_nodes() -> None:
    nodes = parse('<ServerUris><Uri>urn:other</Uri></ServerUris><UAObject NodeId="i=1" BrowseName="1:O"/>')
    assert [node.nodetype for node in nodes] == ["UAObject"]


def test_com81_matrix_value() -> None:
    value = (
        "<uax:Matrix><uax:Dimensions><uax:Int32>2</uax:Int32><uax:Int32>2</uax:Int32></uax:Dimensions>"
        "<uax:Elements><uax:Int32>1</uax:Int32><uax:Int32>2</uax:Int32><uax:Int32>3</uax:Int32>"
        "<uax:Int32>4</uax:Int32></uax:Elements></uax:Matrix>"
    )
    data = parse(variable(value))[0]
    assert data.valuetype == "Matrix"
    assert data.value == ([2, 2], "Int32", [1, 2, 3, 4])


def test_com81_method_and_node_attributes_are_read() -> None:
    body = (
        '<UAMethod NodeId="i=1" BrowseName="1:M" Executable="false" UserExecutable="false" WriteMask="3"/>'
        '<UAVariable NodeId="i=2" BrowseName="1:V" Historizing="true" AccessLevel="0"/>'
    )
    method, var = parse(body)
    assert method.executable is False and method.userexecutable is False and method.writemask == 3
    assert var.historizing is True and var.accesslevel == 0


def test_com86_allow_subtypes_and_option_set_flags_are_read() -> None:
    body = (
        '<UADataType NodeId="i=1" BrowseName="1:T"><Definition Name="1:T" IsOptionSet="true">'
        '<Field Name="A" Value="0"><DisplayName>Alpha</DisplayName></Field></Definition></UADataType>'
        '<UADataType NodeId="i=2" BrowseName="1:S"><Definition Name="1:S">'
        '<Field Name="A" DataType="i=22" AllowSubTypes="true"/></Definition></UADataType>'
    )
    option_set, struct = parse(body)
    assert option_set.option_set is True
    assert option_set.definitions[0].dname == "Alpha"
    assert struct.definitions[0].allow_subtypes is True

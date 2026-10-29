import datetime

import pytest

from enginir_opcua import ua
from enginir_opcua.common.xmlimporter import NodeSetError
from enginir_opcua.common.xmlparser import XMLParser

pytestmark = pytest.mark.asyncio


PREFIX = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd" '
    'xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
)


ALIASES = (
    '<Aliases><Alias Alias="Boolean">i=1</Alias><Alias Alias="Int32">i=6</Alias><Alias Alias="Double">i=11</Alias>'
    '<Alias Alias="String">i=12</Alias><Alias Alias="HasComponent">i=47</Alias><Alias Alias="HasProperty">i=46</Alias>'
    '<Alias Alias="HasSubtype">i=45</Alias><Alias Alias="Organizes">i=35</Alias>'
    '<Alias Alias="HasTypeDefinition">i=40</Alias><Alias Alias="HasEncoding">i=38</Alias>'
    '<Alias Alias="HasInterface">i=17603</Alias></Aliases>'
)


def nodeset(uri: str, body: str, models: str = "") -> str:
    return f"{PREFIX}<NamespaceUris><Uri>{uri}</Uri></NamespaceUris>{models}{ALIASES}{body}</UANodeSet>"


def folder(identifier: int, name: str, parent: str = "i=85", reftype: str = "Organizes") -> str:
    return (
        f'<UAObject NodeId="ns=1;i={identifier}" BrowseName="1:{name}" ParentNodeId="{parent}">'
        f'<DisplayName>{name}</DisplayName><References><Reference ReferenceType="{reftype}" IsForward="false">'
        f'{parent}</Reference><Reference ReferenceType="HasTypeDefinition">i=61</Reference></References></UAObject>'
    )


async def test_com82_parent_is_the_hierarchical_reference_not_the_last_inverse_one(opc) -> None:
    uri = "urn:test:com82a"
    body = (
        folder(1001, "A") + '<UAObject NodeId="ns=1;i=1002" BrowseName="1:B" ParentNodeId="ns=1;i=1001"><References>'
        '<Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=1001</Reference>'
        '<Reference ReferenceType="HasInterface" IsForward="false">ns=1;i=1003</Reference>'
        '<Reference ReferenceType="HasTypeDefinition">i=58</Reference></References></UAObject>'
        '<UAObjectType NodeId="ns=1;i=1003" BrowseName="1:IThing"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=58</Reference></References></UAObjectType>'
    )
    nodes = await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    assert ua.NodeId(1002, ns) in nodes
    parents = await opc.opc.get_node(ua.NodeId(1002, ns)).get_references(
        ua.ObjectIds.HasComponent, ua.BrowseDirection.Inverse
    )
    assert [ref.NodeId for ref in parents] == [ua.NodeId(1001, ns)]


async def test_com82_non_hierarchical_inverse_reference_listed_last(opc) -> None:
    uri = "urn:test:com82b"
    body = (
        folder(1101, "A") + '<UAObject NodeId="ns=1;i=1102" BrowseName="1:B"><References>'
        '<Reference ReferenceType="HasInterface" IsForward="false">ns=1;i=1103</Reference>'
        '<Reference ReferenceType="Organizes" IsForward="false">ns=1;i=1101</Reference>'
        '<Reference ReferenceType="HasTypeDefinition">i=58</Reference></References></UAObject>'
        '<UAObjectType NodeId="ns=1;i=1103" BrowseName="1:IThing"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=58</Reference></References></UAObjectType>'
    )
    nodes = await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    assert ua.NodeId(1102, ns) in nodes


async def test_com82_encoding_object_gets_its_parent_from_the_data_type(opc) -> None:
    uri = "urn:test:com82c"
    body = (
        '<UADataType NodeId="ns=1;i=1201" BrowseName="1:Pair"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>'
        '<Reference ReferenceType="HasEncoding">ns=1;i=1202</Reference>'
        '<Reference ReferenceType="HasEncoding">ns=1;i=1203</Reference></References>'
        '<Definition Name="1:Pair"><Field Name="A" DataType="Int32"/></Definition></UADataType>'
        '<UAObject NodeId="ns=1;i=1202" BrowseName="Default Binary"><References>'
        '<Reference ReferenceType="HasTypeDefinition">i=76</Reference></References></UAObject>'
        '<UAObject NodeId="ns=1;i=1203" BrowseName="Default JSON"><References>'
        '<Reference ReferenceType="HasTypeDefinition">i=76</Reference></References></UAObject>'
    )
    nodes = await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    assert {ua.NodeId(1202, ns), ua.NodeId(1203, ns)} <= set(nodes)
    for node in nodes:
        await opc.opc.get_node(node).read_browse_name()


async def test_com67_orphan_node_is_reported_with_its_name(opc) -> None:
    uri = "urn:test:com67"
    body = (
        '<UAObject NodeId="ns=1;i=1301" BrowseName="1:Orphan"><References>'
        '<Reference ReferenceType="HasInterface">ns=1;i=1302</Reference>'
        '<Reference ReferenceType="HasTypeDefinition">i=58</Reference></References></UAObject>'
    )
    with pytest.raises(NodeSetError, match="Orphan"):
        await opc.opc.import_xml(xmlstring=nodeset(uri, body))


async def test_com58_a_refused_node_is_an_error_not_a_skip(opc) -> None:
    uri = "urn:test:com58a"
    body = (
        '<UAObject NodeId="ns=1;i=1401" BrowseName="Default Binary"><References>'
        '<Reference ReferenceType="Organizes" IsForward="false">i=999999</Reference>'
        '<Reference ReferenceType="HasTypeDefinition">i=76</Reference></References></UAObject>'
    )
    with pytest.raises(NodeSetError) as raised:
        await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    assert raised.value.status is not None


async def test_com58_non_strict_import_lists_only_nodes_that_exist(opc) -> None:
    uri = "urn:test:com58b"
    body = folder(1501, "Good") + folder(1502, "Bad", parent="ns=1;i=1599")
    importer_nodes = await opc.opc.import_xml(xmlstring=nodeset(uri, body), strict_mode=False)
    ns = await opc.opc.get_namespace_index(uri)
    assert importer_nodes == [ua.NodeId(1501, ns)]


async def test_com83_several_satisfied_required_models(opc) -> None:
    uri = "urn:test:com83"
    models = (
        f'<Models><Model ModelUri="{uri}" Version="1.0.0" PublicationDate="2020-01-01T00:00:00Z">'
        '<RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.04" PublicationDate="2000-01-01T00:00:00Z"/>'
        '<RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.0" PublicationDate="2000-01-01T00:00:00Z"/>'
        '<RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.01" PublicationDate="2000-01-01T00:00:00Z"/>'
        "</Model></Models>"
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, folder(1601, "A"), models))


async def test_com52_required_model_without_version_or_date(opc) -> None:
    uri = "urn:test:com52a"
    models = (
        f'<Models><Model ModelUri="{uri}"><RequiredModel ModelUri="http://opcfoundation.org/UA/"/></Model></Models>'
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, folder(1701, "A"), models))


async def test_com52_missing_model_reports_all_requirements(opc) -> None:
    uri = "urn:test:com52b"
    models = (
        f'<Models><Model ModelUri="{uri}"><RequiredModel ModelUri="urn:absent:one"/>'
        '<RequiredModel ModelUri="urn:absent:two" Version="1.0.0-rc1"/></Model></Models>'
    )
    with pytest.raises(NodeSetError, match=r"urn:absent:one.*urn:absent:two"):
        await opc.opc.import_xml(xmlstring=nodeset(uri, folder(1751, "A"), models))


async def test_com52_publication_date_with_fraction_is_compared_as_a_date(opc) -> None:
    uri = "urn:test:com52c"
    models = (
        f'<Models><Model ModelUri="{uri}"><RequiredModel ModelUri="http://opcfoundation.org/UA/" '
        'PublicationDate="2000-01-01T00:00:00.500+01:00"/></Model></Models>'
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, folder(1781, "A"), models))


async def test_com52_namespace_is_not_a_subset_after_a_full_import(opc) -> None:
    uri = "urn:test:com52d"
    models = f'<Models><Model ModelUri="{uri}" Version="2.0" PublicationDate="2021-02-03T04:05:06Z"/></Models>'
    await opc.opc.import_xml(xmlstring=nodeset(uri, folder(1801, "A"), models))
    for meta in await opc.opc.nodes.namespaces.get_children():
        if await (await meta.get_child("NamespaceUri")).read_value() == uri:
            assert await (await meta.get_child("IsNamespaceSubset")).read_value() is False
            assert await (await meta.get_child("NamespaceVersion")).read_value() == "2.0"
            return
    pytest.fail("no NamespaceMetadata object")


async def test_com51_method_that_is_not_executable(opc) -> None:
    uri = "urn:test:com51"
    body = (
        folder(1901, "Holder")
        + '<UAMethod NodeId="ns=1;i=1902" BrowseName="1:M" ParentNodeId="ns=1;i=1901" Executable="false">'
        '<References><Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=1901</Reference>'
        "</References></UAMethod>"
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    node = opc.opc.get_node(ua.NodeId(1902, ns))
    assert (await node.read_attribute(ua.AttributeIds.Executable)).Value.Value is False


async def test_com53_access_level_zero_is_kept(opc) -> None:
    uri = "urn:test:com53a"
    body = (
        folder(2001, "Holder")
        + '<UAVariable NodeId="ns=1;i=2002" BrowseName="1:V" ParentNodeId="ns=1;i=2001" DataType="Double" '
        'AccessLevel="0" Historizing="true" MinimumSamplingInterval="250" WriteMask="3"><References>'
        '<Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=2001</Reference>'
        '<Reference ReferenceType="HasTypeDefinition">i=63</Reference></References></UAVariable>'
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    node = opc.server.get_node(ua.NodeId(2002, ns))
    if opc.opc is opc.server:
        assert (await node.read_attribute(ua.AttributeIds.AccessLevel)).Value.Value == 0
    assert (await node.read_attribute(ua.AttributeIds.Historizing)).Value.Value is True
    assert (await node.read_attribute(ua.AttributeIds.MinimumSamplingInterval)).Value.Value == 250
    assert (await node.read_attribute(ua.AttributeIds.WriteMask)).Value.Value == 3


async def test_com53_variable_without_data_type_is_base_data_type(opc) -> None:
    uri = "urn:test:com53b"
    body = (
        folder(2101, "Holder")
        + '<UAVariable NodeId="ns=1;i=2102" BrowseName="1:V" ParentNodeId="ns=1;i=2101"><References>'
        '<Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=2101</Reference>'
        '<Reference ReferenceType="HasTypeDefinition">i=63</Reference></References></UAVariable>'
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    assert await opc.opc.get_node(ua.NodeId(2102, ns)).read_data_type() == ua.NodeId(ua.ObjectIds.BaseDataType)


async def test_com53_file_alias_beats_standard_name(opc) -> None:
    uri = "urn:test:com53c"
    body = (
        folder(2201, "Holder")
        + '<UAVariable NodeId="ns=1;i=2202" BrowseName="1:V" ParentNodeId="ns=1;i=2201" DataType="Boolean"><References>'
        '<Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=2201</Reference>'
        '<Reference ReferenceType="HasTypeDefinition">i=63</Reference></References></UAVariable>'
    )
    text = nodeset(uri, body).replace('<Alias Alias="Boolean">i=1</Alias>', '<Alias Alias="Boolean">i=12</Alias>')
    await opc.opc.import_xml(xmlstring=text)
    ns = await opc.opc.get_namespace_index(uri)
    assert await opc.opc.get_node(ua.NodeId(2202, ns)).read_data_type() == ua.NodeId(ua.ObjectIds.String)


async def test_com53_variable_type_keeps_falsy_value(opc) -> None:
    uri = "urn:test:com53d"
    body = (
        '<UAVariableType NodeId="ns=1;i=2301" BrowseName="1:VT" DataType="Int32"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=63</Reference></References>'
        "<Value><uax:Int32>0</uax:Int32></Value></UAVariableType>"
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    assert await opc.opc.get_node(ua.NodeId(2301, ns)).read_value() == 0


async def test_com81_view_is_imported(opc) -> None:
    uri = "urn:test:com81"
    body = (
        '<UAView NodeId="ns=1;i=2401" BrowseName="1:View" ContainsNoLoops="true"><References>'
        '<Reference ReferenceType="Organizes" IsForward="false">i=87</Reference></References></UAView>'
    )
    nodes = await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    assert nodes == [ua.NodeId(2401, ns)]
    assert await opc.opc.get_node(nodes[0]).read_node_class() == ua.NodeClass.View


async def test_com81_server_uris_are_skipped(opc) -> None:
    uri = "urn:test:com81b"
    text = nodeset(uri, folder(2451, "A")).replace(
        "<Aliases>", "<ServerUris><Uri>urn:other</Uri></ServerUris><Aliases>"
    )
    assert len(await opc.opc.import_xml(xmlstring=text)) == 1


async def test_com84_node_id_values_use_server_namespace_indices(opc) -> None:
    uri = "urn:test:com84"
    await opc.opc.register_namespace("urn:test:com84:shift")
    value = (
        "<Value><uax:ListOfNodeId><uax:NodeId><uax:Identifier>ns=1;i=2502</uax:Identifier></uax:NodeId>"
        "</uax:ListOfNodeId></Value>"
    )
    scalar = "<Value><uax:NodeId><uax:Identifier>ns=1;i=2502</uax:Identifier></uax:NodeId></Value>"
    qname = "<Value><uax:QualifiedName><uax:NamespaceIndex>1</uax:NamespaceIndex><uax:Name>q</uax:Name></uax:QualifiedName></Value>"

    def variable(identifier: int, datatype: str, rank: str, content: str) -> str:
        return (
            f'<UAVariable NodeId="ns=1;i={identifier}" BrowseName="1:V{identifier}" ParentNodeId="ns=1;i=2501" '
            f'DataType="{datatype}" ValueRank="{rank}"><References>'
            '<Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=2501</Reference>'
            f'<Reference ReferenceType="HasTypeDefinition">i=63</Reference></References>{content}</UAVariable>'
        )

    body = (
        folder(2501, "Holder")
        + variable(2502, "i=17", "1", value)
        + variable(2503, "i=17", "-1", scalar)
        + variable(2504, "i=20", "-1", qname)
    )
    await opc.opc.import_xml(xmlstring=nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    assert ns > 1
    assert await opc.opc.get_node(ua.NodeId(2502, ns)).read_value() == [ua.NodeId(2502, ns)]
    assert await opc.opc.get_node(ua.NodeId(2503, ns)).read_value() == ua.NodeId(2502, ns)
    assert await opc.opc.get_node(ua.NodeId(2504, ns)).read_value() == ua.QualifiedName("q", ns)


async def test_com58_nodes_without_references_do_not_stop_the_reverse_reference_pass(
    opc, monkeypatch: pytest.MonkeyPatch
) -> None:
    from enginir_opcua import Node

    real = Node.get_references

    async def refuse_one(self: Node, *args, **kwargs):
        if self.nodeid.Identifier == 2601:
            raise ua.uaerrors.BadNodeIdUnknown()
        return await real(self, *args, **kwargs)

    monkeypatch.setattr(Node, "get_references", refuse_one)
    nodes = await opc.opc.import_xml(xmlstring=nodeset("urn:test:com58c", folder(2601, "A") + folder(2602, "B")))
    assert len(nodes) == 2


def datatype_nodeset(uri: str, body: str) -> str:
    return nodeset(uri, body)


async def test_com85_option_set_gets_a_definition_and_a_class(opc) -> None:
    uri = "urn:test:com85"
    body = (
        '<UADataType NodeId="ns=1;i=2701" BrowseName="1:Switches"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=7</Reference></References>'
        '<Definition Name="1:Switches" IsOptionSet="true"><Field Name="Left" Value="0"/><Field Name="Right" Value="3"/>'
        "</Definition></UADataType>"
    )
    await opc.opc.import_xml(xmlstring=datatype_nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    definition = await opc.opc.get_node(ua.NodeId(2701, ns)).read_data_type_definition()
    assert [(f.Name, f.Value) for f in definition.Fields] == [("Left", 0), ("Right", 3)]
    cls = opc.opc.types.get(ua.NodeId(2701, ns))
    assert cls.Right == 8 and cls.Left == 1


STRUCTS = (
    '<UADataType NodeId="ns=1;i={b}" BrowseName="1:Base"><References>'
    '<Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>'
    '<Reference ReferenceType="HasEncoding">ns=1;i={be}</Reference></References>'
    '<Definition Name="1:Base"><Field Name="A" DataType="Int32"/></Definition></UADataType>'
    '<UADataType NodeId="ns=1;i={d}" BrowseName="1:Derived"><DisplayName>Shown Name</DisplayName><References>'
    '<Reference ReferenceType="HasSubtype" IsForward="false">ns=1;i={b}</Reference>'
    '<Reference ReferenceType="HasEncoding">ns=1;i={dx}</Reference>'
    '<Reference ReferenceType="HasEncoding">ns=1;i={de}</Reference></References>'
    '<Definition Name="1:Derived"><Field Name="B" DataType="Int32"/></Definition></UADataType>'
    '<UAObject NodeId="ns=1;i={be}" BrowseName="Default Binary"><References>'
    '<Reference ReferenceType="HasTypeDefinition">i=76</Reference></References></UAObject>'
    '<UAObject NodeId="ns=1;i={de}" BrowseName="Default Binary"><References>'
    '<Reference ReferenceType="HasTypeDefinition">i=76</Reference></References></UAObject>'
    '<UAObject NodeId="ns=1;i={dx}" BrowseName="Default XML"><References>'
    '<Reference ReferenceType="HasTypeDefinition">i=76</Reference></References></UAObject>'
)


async def test_com86_derived_structure_has_inherited_fields_binary_encoding_and_browse_name_class(opc) -> None:
    uri = "urn:test:com86a"
    body = STRUCTS.format(b=2801, be=2802, d=2803, de=2804, dx=2805)
    await opc.opc.import_xml(xmlstring=datatype_nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    definition = await opc.opc.get_node(ua.NodeId(2803, ns)).read_data_type_definition()
    assert [f.Name for f in definition.Fields] == ["A", "B"]
    assert definition.DefaultEncodingId == ua.NodeId(2804, ns)
    assert definition.BaseDataType == ua.NodeId(2801, ns)
    cls = opc.opc.types.get(ua.NodeId(2803, ns))
    assert cls.__name__ == "Derived"
    assert cls.__name__ != "Shown_Name"


async def test_com86_subtyped_values_flag_is_kept(opc) -> None:
    uri = "urn:test:com86b"
    body = (
        '<UADataType NodeId="ns=1;i=2901" BrowseName="1:Holder"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference></References>'
        '<Definition Name="1:Holder"><Field Name="Any" DataType="i=22" AllowSubTypes="true"/>'
        '<Field Name="Fixed" DataType="Int32"/></Definition></UADataType>'
    )
    await opc.opc.import_xml(xmlstring=datatype_nodeset(uri, body))
    ns = await opc.opc.get_namespace_index(uri)
    definition = await opc.opc.get_node(ua.NodeId(2901, ns)).read_data_type_definition()
    assert definition.StructureType == ua.StructureType.StructureWithSubtypedValues
    assert [f.IsOptional for f in definition.Fields] == [True, False]


async def test_com86_mutually_recursive_structures_import(opc) -> None:
    uri = "urn:test:com86c"
    body = (
        '<UADataType NodeId="ns=1;i=3001" BrowseName="1:Ping"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference></References>'
        '<Definition Name="1:Ping"><Field Name="Other" DataType="ns=1;i=3002" ValueRank="1"/></Definition></UADataType>'
        '<UADataType NodeId="ns=1;i=3002" BrowseName="1:Pong"><References>'
        '<Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference></References>'
        '<Definition Name="1:Pong"><Field Name="Other" DataType="ns=1;i=3001" ValueRank="1"/></Definition></UADataType>'
    )
    nodes = await opc.opc.import_xml(xmlstring=datatype_nodeset(uri, body))
    assert len(nodes) == 2


EXT_PREFIX = (
    '<UADataType NodeId="ns=1;i={d}" BrowseName="1:Pick"><References>'
    '<Reference ReferenceType="HasSubtype" IsForward="false">i=12756</Reference>'
    '<Reference ReferenceType="HasEncoding">ns=1;i={e}</Reference></References>'
    '<Definition Name="1:Pick" IsUnion="true"><Field Name="Count" DataType="Int32"/>'
    '<Field Name="Label" DataType="String"/></Definition></UADataType>'
    '<UAObject NodeId="ns=1;i={e}" BrowseName="Default Binary"><References>'
    '<Reference ReferenceType="HasTypeDefinition">i=76</Reference></References></UAObject>'
)


def pick_variable(value: str) -> str:
    return (
        '<UAVariable NodeId="ns=1;i=3103" BrowseName="1:PickVar" ParentNodeId="i=85" DataType="ns=1;i=3101">'
        '<References><Reference ReferenceType="Organizes" IsForward="false">i=85</Reference>'
        f'<Reference ReferenceType="HasTypeDefinition">i=63</Reference></References><Value>{value}</Value></UAVariable>'
    )


async def test_com88_union_value_in_xml(opc) -> None:
    uri = "urn:test:com88a"
    body = EXT_PREFIX.format(d=3101, e=3102) + pick_variable(
        "<uax:ExtensionObject><uax:TypeId><uax:Identifier>ns=1;i=3102</uax:Identifier></uax:TypeId><uax:Body>"
        "<Pick><SwitchField>2</SwitchField><Label>hi</Label></Pick></uax:Body></uax:ExtensionObject>"
    )
    nodes = await opc.opc.import_xml(xmlstring=datatype_nodeset(uri, body))
    value = await opc.opc.get_node(nodes[-1]).read_value()
    assert value.Label == "hi" and value.Encoding == 2


async def test_com88_binary_body_in_xml(opc) -> None:
    import base64

    uri = "urn:test:com88b"
    binary = base64.b64encode(bytes([2, 0, 0, 0, 2, 0, 0, 0]) + b"hi").decode()
    body = EXT_PREFIX.format(d=3101, e=3102) + pick_variable(
        "<uax:ExtensionObject><uax:TypeId><uax:Identifier>ns=1;i=3102</uax:Identifier></uax:TypeId><uax:Body>"
        f"<uax:ByteString>{binary}</uax:ByteString></uax:Body></uax:ExtensionObject>"
    )
    nodes = await opc.opc.import_xml(xmlstring=datatype_nodeset(uri, body))
    value = await opc.opc.get_node(nodes[-1]).read_value()
    assert value.Label == "hi"


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


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2020-01-02T03:04:05", datetime.datetime(2020, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)),
        ("2020-01-02T03:04:05+01:00", datetime.datetime(2020, 1, 2, 2, 4, 5, tzinfo=datetime.UTC)),
    ],
    ids=["com49-naive-is-utc", "com49-offset-is-converted"],
)
def test_datetime_value_is_normalised_to_utc(text: str, expected: datetime.datetime) -> None:
    data = parse(variable(f"<uax:DateTime>{text}</uax:DateTime>"))[0]
    assert data.value == expected


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


def test_sort_nodes_progress_check_and_type_class_typedef():
    """XmlImporter._sort_nodes must not hang and must sort Type-class nodes (GH-1996).

    1. Progress detection: last_len must be updated each iteration so an
       unresolvable graph raises instead of spinning forever.
    2. Type-class nodes: a UAObjectType whose typedef points at an instance
       of itself (TwinCAT export pattern) must still sort.
    """
    from enginir_opcua.common.xmlimporter import XmlImporter
    from enginir_opcua.common.xmlparser import NodeData

    importer = XmlImporter.__new__(XmlImporter)

    # --- Type-class + instance cycle that previously hung ---
    type_node = NodeData()
    type_node.nodeid = "ns=1;i=1000"
    type_node.nodetype = "UAObjectType"
    type_node.parent = None
    type_node.typedef = "ns=1;i=1001"  # points at instance (export quirk)
    type_node.datatype = None
    type_node.definitions = []

    instance = NodeData()
    instance.nodeid = "ns=1;i=1001"
    instance.nodetype = "UAObject"
    instance.parent = None
    instance.typedef = "ns=1;i=1000"  # real TypeDefinition of the type
    instance.datatype = None
    instance.definitions = []

    sorted_nodes = importer._sort_nodes([type_node, instance])
    assert {n.nodeid for n in sorted_nodes} == {type_node.nodeid, instance.nodeid}
    # Type must come before instance (instance depends on typedef)
    ids = [n.nodeid for n in sorted_nodes]
    assert ids.index(type_node.nodeid) < ids.index(instance.nodeid)

    # --- Truly unresolvable: mutual parent cycle, no progress ---
    a = NodeData()
    a.nodeid = "ns=1;i=1"
    a.nodetype = "UAObject"
    a.parent = "ns=1;i=2"
    a.typedef = None
    a.datatype = None
    a.definitions = []

    b = NodeData()
    b.nodeid = "ns=1;i=2"
    b.nodetype = "UAObject"
    b.parent = "ns=1;i=1"
    b.typedef = None
    b.datatype = None
    b.definitions = []

    try:
        importer._sort_nodes([a, b])
        raise AssertionError("expected ValueError for unresolvable parent cycle")
    except ValueError as exc:
        assert "Ordering of nodes is not possible" in str(exc)

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.xmlexporter import XmlExporter
from tests.model.test_nodeset_import import nodeset

pytestmark = pytest.mark.asyncio

SCHEMA = Path(__file__).resolve().parents[2] / "nodeset" / "Schema" / "UANodeSet.xsd"
XS = "{http://www.w3.org/2001/XMLSchema}"
NS = "{http://opcfoundation.org/UA/2011/03/UANodeSet.xsd}"
URI = "urn:test:export"


def declared_attributes() -> dict[str, set[str]]:
    root = ET.parse(SCHEMA).getroot()
    types = {el.get("name"): el for el in root.iter(f"{XS}complexType")}

    def collect(name: str) -> set[str]:
        element = types[name]
        found = {str(a.get("name")) for a in element.iter(f"{XS}attribute")}
        for extension in element.iter(f"{XS}extension"):
            base = extension.get("base")
            if base in types:
                found |= collect(base)
        return found

    return {name: collect(name) for name in types}


async def exported(server: Server, nodes, tmp_path: Path, **kwargs) -> Path:
    path = tmp_path / "out.xml"
    await server.export_xml(nodes, str(path), **kwargs)
    return path


async def new_server() -> Server:
    server = Server()
    await server.init()
    return server


SOURCE = nodeset(
    URI,
    '<UAReferenceType NodeId="ns=1;i=3001" BrowseName="1:Sym" Symmetric="true" IsAbstract="true">'
    '<DisplayName>Sym</DisplayName><References><Reference ReferenceType="HasSubtype" IsForward="false">i=32'
    "</Reference></References></UAReferenceType>"
    '<UADataType NodeId="ns=1;i=3002" BrowseName="1:AbstractStruct" IsAbstract="true"><References>'
    '<Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference></References>'
    '<Definition Name="1:AbstractStruct"><Field Name="A" DataType="Int32"/></Definition></UADataType>'
    '<UADataType NodeId="ns=1;i=3003" BrowseName="1:Flags"><References>'
    '<Reference ReferenceType="HasSubtype" IsForward="false">i=5</Reference></References>'
    '<Definition Name="1:Flags" IsOptionSet="true"><Field Name="One" Value="0"><DisplayName>Eins</DisplayName>'
    '</Field><Field Name="Two" Value="1"/></Definition></UADataType>'
    '<UADataType NodeId="ns=1;i=3004" BrowseName="1:Holder"><References>'
    '<Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference></References>'
    '<Definition Name="1:Holder"><Field Name="Any" DataType="i=22" AllowSubTypes="true"/>'
    '<Field Name="Rows" DataType="Int32" ValueRank="2" ArrayDimensions="3,0"/></Definition></UADataType>'
    '<UAObject NodeId="ns=1;i=3005" BrowseName="1:Folder" ParentNodeId="i=85" EventNotifier="1" WriteMask="5">'
    '<DisplayName>Folder</DisplayName><References><Reference ReferenceType="Organizes" IsForward="false">i=85'
    '</Reference><Reference ReferenceType="HasTypeDefinition">i=61</Reference></References></UAObject>'
    '<UAVariable NodeId="ns=1;i=3006" BrowseName="1:NoAccess" ParentNodeId="ns=1;i=3005" DataType="Double" '
    'AccessLevel="0" Historizing="true" MinimumSamplingInterval="250"><References>'
    '<Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=3005</Reference>'
    '<Reference ReferenceType="HasTypeDefinition">i=63</Reference></References></UAVariable>'
    '<UAMethod NodeId="ns=1;i=3007" BrowseName="1:Off" ParentNodeId="ns=1;i=3005" Executable="false">'
    '<References><Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=3005</Reference></References>'
    "</UAMethod>"
    '<UAView NodeId="ns=1;i=3008" BrowseName="1:View" ContainsNoLoops="true" EventNotifier="1"><References>'
    '<Reference ReferenceType="Organizes" IsForward="false">i=87</Reference></References></UAView>',
)


async def round_trip(tmp_path: Path) -> tuple[Server, Server, Path]:
    first = await new_server()
    await first.import_xml(xmlstring=SOURCE)
    ns = await first.get_namespace_index(URI)
    ids = [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008]
    path = await exported(first, [first.get_node(ua.NodeId(i, ns)) for i in ids], tmp_path)
    second = await new_server()
    await second.import_xml(str(path))
    return first, second, path


async def attribute(server: Server, identifier: int, attribute_id: ua.AttributeIds):
    ns = await server.get_namespace_index(URI)
    value = (await server.get_node(ua.NodeId(identifier, ns)).read_attribute(attribute_id)).Value
    assert value is not None
    return value.Value


async def test_com55_reference_type_and_data_type_attributes_survive_a_round_trip(tmp_path: Path) -> None:
    _, second, _ = await round_trip(tmp_path)
    assert await attribute(second, 3001, ua.AttributeIds.Symmetric) is True
    assert await attribute(second, 3001, ua.AttributeIds.IsAbstract) is True
    assert await attribute(second, 3002, ua.AttributeIds.IsAbstract) is True


async def test_com55_instance_attributes_survive_a_round_trip(tmp_path: Path) -> None:
    _, second, _ = await round_trip(tmp_path)
    assert await attribute(second, 3006, ua.AttributeIds.AccessLevel) == 0
    assert await attribute(second, 3006, ua.AttributeIds.Historizing) is True
    assert await attribute(second, 3006, ua.AttributeIds.MinimumSamplingInterval) == 250
    assert await attribute(second, 3005, ua.AttributeIds.WriteMask) == 5
    assert await attribute(second, 3005, ua.AttributeIds.EventNotifier) == 1
    assert await attribute(second, 3007, ua.AttributeIds.Executable) is False
    assert await attribute(second, 3008, ua.AttributeIds.ContainsNoLoops) is True


async def test_com55_definitions_survive_a_round_trip(tmp_path: Path) -> None:
    first, second, _ = await round_trip(tmp_path)
    ns = await first.get_namespace_index(URI)
    for identifier in (3002, 3003, 3004):
        node = ua.NodeId(identifier, ns)
        expected = await first.get_node(node).read_data_type_definition()
        actual = await second.get_node(node).read_data_type_definition()
        assert actual == expected, identifier
    subtyped = await second.get_node(ua.NodeId(3004, ns)).read_data_type_definition()
    assert isinstance(subtyped, ua.StructureDefinition)
    assert subtyped.StructureType == ua.StructureType.StructureWithSubtypedValues
    assert subtyped.Fields[1].ArrayDimensions == [3, 0]
    option_set = await second.get_node(ua.NodeId(3003, ns)).read_data_type_definition()
    assert isinstance(option_set, ua.EnumDefinition)
    assert [(f.Name, f.Value, f.DisplayName.Text) for f in option_set.Fields][0] == ("One", 0, "Eins")


async def test_com87_export_uses_only_attributes_of_the_schema(tmp_path: Path) -> None:
    _, _, path = await round_trip(tmp_path)
    allowed = declared_attributes()
    root = ET.parse(path).getroot()
    checked = 0
    for element in root.iter():
        name = element.tag.removeprefix(NS)
        if name == "Definition":
            name = "DataTypeDefinition"
        if name == "Field":
            name = "DataTypeField"
        if name in allowed:
            assert set(element.attrib) <= allowed[name] | {"xmlns"}, (name, element.attrib)
            checked += 1
    assert checked > 10


async def test_com87_all_namespaces_do_not_list_the_base_namespace_first(tmp_path: Path) -> None:
    server = await new_server()
    await server.import_xml(xmlstring=SOURCE)
    exporter = XmlExporter(server)
    await exporter.build_etree([server.nodes.objects], add_all_namespaces=True)
    root = exporter.etree.getroot()
    assert root is not None
    namespace_uris = root.find("NamespaceUris")
    assert namespace_uris is not None
    uris = [el.text for el in namespace_uris]
    assert "http://opcfoundation.org/UA/" not in uris
    assert uris[0] == "urn:enginir:opcua:server"


async def test_com87_chunked_export_writes_every_node(tmp_path: Path) -> None:
    server = await new_server()
    await server.import_xml(xmlstring=SOURCE)
    ns = await server.get_namespace_index(URI)
    nodes = [server.get_node(ua.NodeId(i, ns)) for i in (3005, 3006, 3007)]
    exporter = XmlExporter(server)
    await exporter.build_etree_chunked(nodes, chunk_size=2)
    root = exporter.etree.getroot()
    assert root is not None
    names = [el.get("BrowseName") for el in root if el.get("BrowseName")]
    assert len(names) == 3


async def test_com87_node_id_values_keep_their_namespace(tmp_path: Path) -> None:
    server = await new_server()
    other = await server.register_namespace("urn:test:other")
    mine = await server.register_namespace("urn:test:mine")
    holder = await server.nodes.objects.add_variable(mine, "Ref", ua.NodeId("target", other))
    path = await exported(server, [holder], tmp_path, export_values=True)
    fresh = await new_server()
    await fresh.register_namespace("urn:test:padding")
    await fresh.import_xml(str(path))
    new_other = await fresh.get_namespace_index("urn:test:other")
    new_mine = await fresh.get_namespace_index("urn:test:mine")
    value = await fresh.get_node(ua.NodeId(holder.nodeid.Identifier, new_mine)).read_value()
    assert value == ua.NodeId("target", new_other)


async def test_com87_export_by_namespace_writes_the_model(tmp_path: Path) -> None:
    server = await new_server()
    models = f'<Models><Model ModelUri="{URI}" Version="2.1" PublicationDate="2022-02-03T04:05:06Z"/></Models>'
    text = SOURCE.replace("<Aliases>", f"{models}<Aliases>", 1)
    await server.import_xml(xmlstring=text)
    path = tmp_path / "ns.xml"
    await server.export_xml_by_ns(str(path), [URI])
    root = ET.parse(path).getroot()
    model = root.find(f"{NS}Models/{NS}Model") if root.find(f"{NS}Models") is not None else root.find("Models/Model")
    assert model is not None
    assert model.get("ModelUri") == URI and model.get("Version") == "2.1"
    assert str(model.get("PublicationDate")).startswith("2022-02-03T04:05:06")
    assert [child.get("ModelUri") for child in model] == ["http://opcfoundation.org/UA/"]

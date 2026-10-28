import pathlib
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.xmlparser import XMLParser

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.slow(
        "enginir_opcua/common/xmlimporter.py",
        "enginir_opcua/common/xmlparser.py",
        "enginir_opcua/common/xmlexporter.py",
        "enginir_opcua/common/structures104.py",
        "enginir_opcua/common/instantiate_util.py",
    ),
    pytest.mark.usefixtures("restore_ua_registry"),
]

NODESETS = pathlib.Path(__file__).resolve().parents[1] / "nodeset"
DI = NODESETS / "DI" / "Opc.Ua.Di.NodeSet2.xml"
ADI = NODESETS / "ADI" / "Opc.Ua.Adi.NodeSet2.xml"
AMB = NODESETS / "AMB" / "Opc.Ua.AMB.NodeSet2.xml"
IA = NODESETS / "IA" / "Opc.Ua.IA.NodeSet2.xml"
MACHINERY = NODESETS / "Machinery" / "Opc.Ua.Machinery.NodeSet2.xml"
LADS = NODESETS / "LADS" / "Opc.Ua.LADS.NodeSet2.xml"
AGGREGATES = (ua.ObjectIds.HasComponent, ua.ObjectIds.HasProperty)


def parse(path: pathlib.Path) -> tuple[list[str], list[Any]]:
    parser = XMLParser()
    parser.parse_sync(xmlpath=str(path))
    return parser.get_used_namespaces(), parser.get_node_datas()


def declared_nodeid(uris: list[str], text: str, indices: dict[str, int]) -> ua.NodeId:
    nodeid = ua.NodeId.from_string(text)
    if nodeid.NamespaceIndex == 0:
        return nodeid
    return ua.NodeId(nodeid.Identifier, indices[uris[nodeid.NamespaceIndex - 1]])


class Companion:
    def __init__(self, opc: Any) -> None:
        self.opc = opc
        self.imported: dict[str, list[ua.NodeId]] = {}
        self.indices: dict[str, int] = {}
        self.instances: dict[str, ua.NodeId] = {}

    @property
    def aspace(self) -> Any:
        return self.opc.server.iserver.aspace

    async def load(self, path: pathlib.Path) -> None:
        self.imported[path.name] = await self.opc.opc.import_xml(path)
        for uri in parse(path)[0]:
            self.indices[uri] = await self.opc.opc.get_namespace_index(uri)

    def type_id(self, path: pathlib.Path, browse_name: str) -> ua.NodeId:
        uris, nodes = parse(path)
        for node in nodes:
            if node.browsename.endswith(f":{browse_name}") or node.browsename == browse_name:
                return declared_nodeid(uris, node.nodeid, self.indices)
        raise KeyError(browse_name)

    async def instantiate(self, key: str, path: pathlib.Path, type_name: str) -> None:
        namespace = self.indices["http://opcfoundation.org/UA/DI/"]
        node = await self.opc.opc.nodes.objects.add_object(
            ua.NodeId(NamespaceIndex=namespace), f"{namespace}:{key}", objecttype=self.type_id(path, type_name)
        )
        self.instances[key] = node.nodeid

    def subtree(self, root: ua.NodeId) -> list[ua.NodeId]:
        found, pending = [], [root]
        while pending:
            current = pending.pop()
            for reference in self.aspace[current].references:
                if reference.IsForward and reference.ReferenceTypeId.Identifier in AGGREGATES:
                    found.append(reference.NodeId)
                    pending.append(reference.NodeId)
        return found


@pytest.fixture(scope="module")
async def companion(opc: Any) -> Companion:
    result = Companion(opc)
    await opc.server.register_namespace("http://placeholder.toincrease.nsindex")
    for path in (DI, ADI):
        await result.load(path)
    await result.instantiate("Spectrometer", ADI, "SpectrometerDeviceType")
    for path in (AMB, IA, MACHINERY, LADS):
        await result.load(path)
    await result.instantiate("LadsDevice", LADS, "LADSDeviceType")
    return result


async def test_every_imported_node_exists(companion: Companion) -> None:
    missing = [nodeid for nodes in companion.imported.values() for nodeid in nodes if nodeid not in companion.aspace]
    assert missing == []
    assert all(len(nodes) > 50 for nodes in companion.imported.values())


async def test_design_tool_only_nodes_are_not_in_the_address_space(companion: Companion) -> None:
    checked = 0
    for path in (DI, ADI, AMB, IA, MACHINERY, LADS):
        uris, nodes = parse(path)
        for node in nodes:
            if node.design_tool_only:
                assert declared_nodeid(uris, node.nodeid, companion.indices) not in companion.aspace
                checked += 1
    assert checked >= 9


async def test_every_encoding_of_an_imported_data_type_exists(companion: Companion) -> None:
    has_encoding = ua.NodeId(ua.ObjectIds.HasEncoding)
    checked = 0
    for nodes in companion.imported.values():
        for nodeid in nodes:
            data = companion.aspace[nodeid]
            if companion.aspace.node_class_of(data) != ua.NodeClass.DataType:
                continue
            for reference in data.references:
                if reference.ReferenceTypeId == has_encoding and reference.IsForward:
                    assert reference.NodeId in companion.aspace
                    checked += 1
    assert checked > 10


async def test_instances_have_no_placeholder_nodes(companion: Companion) -> None:
    for key, root in companion.instances.items():
        names = [companion.aspace.browse_name_of(companion.aspace[n]).Name for n in companion.subtree(root)]
        assert names, key
        assert [name for name in names if name.startswith("<")] == [], key


async def test_every_structure_of_the_nodesets_gets_a_class(opc: Any, companion: Companion) -> None:
    await opc.opc.load_data_type_definitions()
    expected = set()
    for path in (DI, ADI, AMB, IA, MACHINERY, LADS):
        for node in parse(path)[1]:
            if node.nodetype == "UADataType" and node.has_definition and not node.abstract and not node.option_set:
                expected.add(node.browsename.split(":", 1)[-1])
    names = set(opc.opc.types.names())
    assert sorted(expected - names - {"Structure"}) == []


async def test_a_client_reads_the_variables_of_both_instances(opc: Any, companion: Companion) -> None:
    for root in companion.instances.values():
        children = await opc.opc.get_node(root).get_children()
        assert children
        for node in (opc.opc.get_node(n) for n in companion.subtree(root)):
            if await node.read_node_class() == ua.NodeClass.Variable:
                value = await node.read_data_value(raise_on_bad_status=False)
                assert (
                    value.StatusCode is None
                    or value.StatusCode.is_good()
                    or value.StatusCode.value == (ua.StatusCodes.BadWaitingForInitialData)
                )


async def test_instances_have_the_mandatory_children_of_their_declared_types(companion: Companion) -> None:
    mandatory = ua.NodeId(ua.ObjectIds.ModellingRule_Mandatory)
    has_modelling_rule = ua.NodeId(ua.ObjectIds.HasModellingRule)
    has_type = ua.NodeId(ua.ObjectIds.HasTypeDefinition)
    aspace = companion.aspace

    def children(nodeid: ua.NodeId) -> list[ua.NodeId]:
        return [
            r.NodeId for r in aspace[nodeid].references if r.IsForward and r.ReferenceTypeId.Identifier in AGGREGATES
        ]

    def key(nodeid: ua.NodeId) -> tuple[int, str | None]:
        name = aspace.browse_name_of(aspace[nodeid])
        return (name.NamespaceIndex, name.Name)

    def names(nodeids: list[ua.NodeId]) -> set[tuple[int, str | None]]:
        return {key(n) for n in nodeids}

    missing = []
    checked = 0
    for root in companion.instances.values():
        for nodeid in [root, *companion.subtree(root)]:
            for reference in aspace[nodeid].references:
                if reference.ReferenceTypeId != has_type or aspace.node_class_of(aspace[nodeid]) not in (
                    ua.NodeClass.Object,
                    ua.NodeClass.Variable,
                ):
                    continue
                declared = [
                    child
                    for child in children(reference.NodeId)
                    if any(
                        r.ReferenceTypeId == has_modelling_rule and r.NodeId == mandatory
                        for r in aspace[child].references
                    )
                ]
                for child in declared:
                    checked += 1
                    if key(child) not in names(children(nodeid)):
                        missing.append((nodeid, child))
    assert checked > 0
    assert missing == []

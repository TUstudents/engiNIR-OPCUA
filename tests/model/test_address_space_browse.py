from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.structures104 import new_struct, new_struct_field
from enginir_opcua.ua import Int16, NodeId, NodeIdType, String
from tests.access_rig import declare_writable

pytestmark = pytest.mark.asyncio


async def test_find_servers(opc):
    await opc.opc.find_servers()
    # FIXME : finish


@pytest.mark.parametrize(
    "nodeid, is_abstract, symmetric",
    [
        (ua.ObjectIds.References, True, True),
        (ua.ObjectIds.HierarchicalReferences, True, False),
        (ua.ObjectIds.Organizes, False, False),
        (ua.ObjectIds.HasSubtype, False, False),
        (ua.ObjectIds.AssociatedWith, False, True),
    ],
)
async def test_standard_reference_type_attributes(opc: Any, nodeid: int, is_abstract: bool, symmetric: bool) -> None:
    node = opc.opc.get_node(nodeid)
    assert is_abstract == (await node.read_attribute(ua.AttributeIds.IsAbstract)).Value.Value
    assert symmetric == (await node.read_attribute(ua.AttributeIds.Symmetric)).Value.Value


@pytest.mark.parametrize(
    "nodeid, is_abstract",
    [
        (ua.ObjectIds.BaseVariableType, True),
        (ua.ObjectIds.BaseDataVariableType, False),
        (ua.ObjectIds.PropertyType, False),
    ],
)
async def test_standard_variable_type_is_abstract(opc: Any, nodeid: int, is_abstract: bool) -> None:
    node = opc.opc.get_node(nodeid)
    assert is_abstract == (await node.read_attribute(ua.AttributeIds.IsAbstract)).Value.Value


async def test_server_node(opc):
    node = opc.opc.nodes.server
    assert ua.QualifiedName("Server", 0) == await node.read_browse_name()


async def test_root(opc):
    root = opc.opc.nodes.root
    assert ua.QualifiedName("Root", 0) == await root.read_browse_name()
    assert ua.LocalizedText("Root") == await root.read_display_name()
    nid = ua.NodeId(84, 0)
    assert nid == root.nodeid


async def test_objects(opc):
    objects = opc.opc.nodes.objects
    assert ua.QualifiedName("Objects", 0) == await objects.read_browse_name()
    nid = ua.NodeId(85, 0)
    assert nid == objects.nodeid


async def test_browse(opc):
    objects = opc.opc.nodes.objects
    obj = await objects.add_object(4, "browsetest")
    folder = await obj.add_folder(4, "folder")
    prop = await obj.add_property(4, "property", 1)
    prop2 = await obj.add_property(4, "property2", 2)
    var = await obj.add_variable(4, "variable", 3)
    obj2 = await obj.add_object(4, "obj")
    alle = await obj.get_children()
    assert prop in alle
    assert prop2 in alle
    assert var in alle
    assert folder in alle
    assert obj not in alle
    props = await obj.get_children(refs=ua.ObjectIds.HasProperty)
    assert prop in props
    assert prop2 in props
    assert var not in props
    assert folder not in props
    assert obj2 not in props
    all_vars = await obj.get_children(nodeclassmask=ua.NodeClass.Variable)
    assert prop in all_vars
    assert var in all_vars
    assert folder not in props
    assert obj2 not in props
    all_objs = await obj.get_children(nodeclassmask=ua.NodeClass.Object)
    assert folder in all_objs
    assert obj2 in all_objs
    assert var not in all_objs
    await opc.opc.delete_nodes([folder, prop, prop2, var, obj2, obj])
    await opc.opc.delete_nodes(props)
    await opc.opc.delete_nodes(all_vars)
    await opc.opc.delete_nodes(all_objs)


async def test_browse_references(opc):
    objects = opc.opc.nodes.objects
    folder = await objects.add_folder(4, "folder")

    childs = await objects.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert folder in childs

    childs = await objects.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Both,
        includesubtypes=False,
    )
    assert folder in childs

    childs = await objects.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert folder not in childs

    parents = await folder.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert objects in parents

    parents = await folder.get_referenced_nodes(
        refs=ua.ObjectIds.HierarchicalReferences,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=True,
    )
    assert objects in parents

    parents = await folder.get_referenced_nodes(
        refs=ua.ObjectIds.HierarchicalReferences,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert objects not in parents

    assert await folder.get_parent() == objects


async def test_browsename_with_spaces(opc):
    o = opc.opc.nodes.objects
    v = await o.add_variable(3, "BNVariable with spaces and %+?", 1.3)
    v2 = await o.get_child("/3:BNVariable with spaces and %+?")
    assert v == v2
    await opc.opc.delete_nodes([v])


async def test_non_existing_path(opc):
    root = opc.opc.nodes.root
    with pytest.raises(ua.UaStatusCodeError):
        await root.get_child("0:Objects/0:Server/0:nonexistingnode")


async def test_bad_attribute(opc):
    root = opc.opc.nodes.root
    with pytest.raises(ua.UaStatusCodeError):
        await root.write_value(99)


async def test_get_node_by_nodeid(opc):
    root = opc.opc.nodes.root
    server_time_node = await root.get_child("/Objects/Server/ServerStatus.CurrentTime")
    correct = opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
    assert server_time_node == correct


async def test_get_children_by_path(opc):
    root = opc.opc.nodes.root
    [server_time_nodes] = await root.get_children_by_path(
        [["0:Objects", "0:Server", "0:ServerStatus", "0:CurrentTime"]]
    )
    correct = opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
    assert len(server_time_nodes) == 1
    assert server_time_nodes[0] == correct
    with pytest.raises(ua.UaStatusCodeError) as e:
        await root.get_children_by_path(
            [
                ["0:Objects", "0:Server", "0:ServerStatus", "0:CurrentTime"],
                ["0:Objects", "0:Unknown"],
            ]
        )
    assert e.type == ua.UaStatusCodeErrors
    assert e.value.codes == [ua.StatusCodes.Good, ua.StatusCodes.BadNoMatch]
    assert e.value.code == ua.StatusCodes.BadNoMatch
    [server_time_nodes, unknown] = await root.get_children_by_path(
        [
            ["0:Objects", "0:Server", "0:ServerStatus", "0:CurrentTime"],
            ["0:Objects", "0:Unknown"],
        ],
        raise_on_partial_error=False,
    )
    assert len(server_time_nodes) == 1
    assert server_time_nodes[0] == correct
    assert unknown is None


async def test_node_path(opc):
    objects = opc.opc.nodes.objects
    o = await objects.add_object("ns=2;i=105;", "2:NodePathObject")
    root = opc.opc.nodes.root
    o2 = await root.get_child(["0:Objects", "2:NodePathObject"])
    assert o == o2
    await opc.opc.delete_nodes([o, o2])


async def test_read_server_state(opc):
    statenode = opc.opc.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_State))
    assert 0 == await statenode.read_value()


async def test_incl_subtypes(opc):
    base_type = await opc.opc.nodes.root.get_child(["0:Types", "0:ObjectTypes", "0:BaseObjectType"])
    descs = await base_type.get_children_descriptions(includesubtypes=True)
    assert len(descs) > 10
    descs = await base_type.get_children_descriptions(includesubtypes=False)
    assert 0 == len(descs)


async def test_browse_reflects_written_display_name(opc):
    objects = opc.opc.nodes.objects
    f = await objects.add_folder(3, "MyFolder_BrowseRefresh")
    o = await f.add_object(3, "MyObject_BrowseRefresh", ua.ObjectIds.BaseObjectType)
    await declare_writable(opc, o, attributes=(ua.AttributeIds.DisplayName,))

    await o.write_attribute(
        ua.AttributeIds.DisplayName,
        ua.DataValue(ua.Variant(ua.LocalizedText("Renamed"), ua.VariantType.LocalizedText)),
    )

    descs = await f.get_children_descriptions()
    desc = next(d for d in descs if d.NodeId == o.nodeid)
    assert ua.LocalizedText("Renamed") == desc.DisplayName
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == desc.TypeDefinition

    await opc.opc.delete_nodes([o, f])


async def test_path_string(opc):
    o = await (await opc.opc.nodes.objects.add_folder(1, "titif")).add_object(3, "opath")
    path = await o.get_path(as_string=True)
    assert ["Root", "Objects", "1:titif", "3:opath"] == path
    path = await o.get_path(2, as_string=True)
    assert ["1:titif", "3:opath"] == path


async def test_path(opc):
    of = await opc.opc.nodes.objects.add_folder(1, "titifpath")
    op = await of.add_object(3, "opath")
    path = await op.get_path()
    assert [opc.opc.nodes.root, opc.opc.nodes.objects, of, op] == path
    path = await op.get_path(2)
    assert [of, op] == path
    target = opc.opc.get_node("i=13387")
    path = await target.get_path()
    assert [
        opc.opc.nodes.root,
        opc.opc.nodes.types,
        opc.opc.nodes.object_types,
        opc.opc.nodes.base_object_type,
        opc.opc.nodes.folder_type,
        opc.opc.get_node(ua.ObjectIds.FileDirectoryType),
        target,
    ] == path


async def test_get_endpoints(opc):
    endpoints = await opc.opc.get_endpoints()
    assert len(endpoints) > 0
    assert endpoints[0].EndpointUrl.startswith("opc.tcp://")


async def test_alias(opc):
    """
    Testing renaming buildin datatypes like UInt32, str and test it in a struct
    """
    idx = 4
    parent = opc.opc.get_node(ua.ObjectIds.String)
    dt_str = await parent.add_data_type(ua.NodeId(NamespaceIndex=idx), "MyString")

    data_type, _ = await new_struct(
        opc.opc,
        idx,
        "MyAliasStruct",
        [
            new_struct_field("MyStringType", dt_str),
        ],
    )
    await opc.opc.load_data_type_definitions()
    assert type(ua.MyString()) is ua.String
    var = await opc.opc.nodes.objects.add_variable(idx, "AliasedString", "1234", datatype=dt_str.nodeid)
    val = await var.read_value()
    assert val == "1234"

    v = ua.MyAliasStruct()
    var = await opc.opc.nodes.objects.add_variable(idx, "AliasedStruct", v, datatype=data_type.nodeid)
    await declare_writable(opc, var)
    val = await var.read_value()
    assert val == v
    v.MyStringType = "1234"
    await var.write_value(v)
    val = await var.read_value()


async def test_parse_nodeid_name_contains_multiple_dividers():
    raw_node_name = "ns=9;s=Line1.nsuri=MACHINE.NS;s=MACHINE.NS.State.Running"
    expected_node_id = NodeId(
        Identifier=String("Line1.nsuri=MACHINE.NS;s=MACHINE.NS.State.Running"),
        NamespaceIndex=Int16(9),
        NodeIdType=NodeIdType.String,
    )
    got_node_id = NodeId.from_string(string=raw_node_name)
    assert got_node_id == expected_node_id

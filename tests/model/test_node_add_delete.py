from base64 import b64encode

import pytest

from enginir_opcua import ua
from enginir_opcua.common.copy_node_util import copy_node

pytestmark = pytest.mark.asyncio


async def test_add_node_bad_args(opc):
    obj = opc.opc.nodes.objects

    with pytest.raises(TypeError):
        await obj.add_folder(1.2, "kk")

    with pytest.raises(TypeError):
        await obj.add_folder(ua.UaError, "khjh")

    with pytest.raises(ua.UaError):
        await obj.add_folder("kjk", 1.2)

    with pytest.raises(TypeError):
        await obj.add_folder("s='oooo'", 1.2)

    with pytest.raises(ua.UaError):
        await obj.add_folder("i=0;s='oooo'", "tt:oioi")


async def test_delete_nodes(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToDelete")
    var = await fold.add_variable(2, "VarToDelete", 9.1)
    childs = await fold.get_children()
    assert var in childs
    await opc.opc.delete_nodes([var])
    with pytest.raises(ua.UaStatusCodeError):
        await var.write_value(7.8)
    with pytest.raises(ua.UaStatusCodeError):
        await obj.get_child(["2:FolderToDelete", "2:VarToDelete"])
    childs = await fold.get_children()
    assert var not in childs
    await opc.opc.delete_nodes([fold])


async def test_node_bytestring(opc):
    obj = opc.opc.nodes.objects
    var = await obj.add_variable(
        ua.ByteStringNodeId(b"VarByteString", 2),
        ua.QualifiedName("toto", 2),
        ua.UInt16(9),
    )
    node = opc.opc.get_node(f"ns=2;b={b64encode(b'VarByteString').decode()}")
    assert node == var


async def test_delete_nodes_with_inverse_references(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToDelete")
    var = await fold.add_variable(2, "VarToDelete", 9.1)
    var2 = await fold.add_variable(2, "VarWithReference", 9.2)
    childs = await fold.get_children()
    assert var in childs
    assert var2 in childs
    # add two references to var, this includes adding the inverse references to var2
    await var.add_reference(
        var2.nodeid,
        reftype=ua.ObjectIds.HasDescription,
        forward=True,
        bidirectional=True,
    )
    await var.add_reference(var2.nodeid, reftype=ua.ObjectIds.HasEffect, forward=True, bidirectional=True)
    await opc.opc.delete_nodes([var])
    childs = await fold.get_children()
    assert var not in childs
    has_desc_refs = await var2.get_referenced_nodes(
        refs=ua.ObjectIds.HasDescription, direction=ua.BrowseDirection.Inverse
    )
    assert len(has_desc_refs) == 0
    has_effect_refs = await var2.get_referenced_nodes(refs=ua.ObjectIds.HasEffect, direction=ua.BrowseDirection.Inverse)
    assert len(has_effect_refs) == 0
    await opc.opc.delete_nodes([fold])


async def test_delete_nodes_removes_one_way_references(opc):
    fold = await opc.opc.nodes.objects.add_folder(2, "FolderOneWayRefs")
    target = await fold.add_variable(2, "OneWayTarget", 1.0)
    source = await fold.add_variable(2, "OneWaySource", 2.0)
    await source.add_reference(target.nodeid, reftype=ua.ObjectIds.HasEffect, forward=True, bidirectional=False)
    assert [target] == await source.get_referenced_nodes(refs=ua.ObjectIds.HasEffect)
    await opc.opc.delete_nodes([target])
    assert [] == await source.get_referenced_nodes(refs=ua.ObjectIds.HasEffect)
    await opc.opc.delete_nodes([fold], recursive=True)


async def test_delete_nodes_recursive(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToDeleteR")
    var = await fold.add_variable(2, "VarToDeleteR", 9.1)
    await opc.opc.delete_nodes([fold, var])
    with pytest.raises(ua.UaStatusCodeError):
        await var.write_value(7.8)
    with pytest.raises(ua.UaStatusCodeError):
        await obj.get_child(["2:FolderToDelete", "2:VarToDelete"])


async def test_delete_nodes_recursive2(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_object(2, "FolderToDeleteRoot")
    mynodes = []
    for i in range(7):
        nfold = await fold.add_object(2, f"FolderToDeleteRoot{i}")
        var = await nfold.add_variable(2, "VarToDeleteR", 9.1)
        var = await nfold.add_property(2, "ProToDeleteR", 9.1)
        prop = await nfold.add_property(2, "ProToDeleteR2", 9.1)
        o = await nfold.add_object(3, "ObjToDeleteR")
        mynodes.append(nfold)
        mynodes.append(var)
        mynodes.append(prop)
        mynodes.append(o)
    await opc.opc.delete_nodes([fold], recursive=True)
    for node in mynodes:
        with pytest.raises(ua.UaStatusCodeError):
            await node.read_browse_name()
    await opc.opc.delete_nodes([fold])


async def test_delete_references(opc):
    newtype = await opc.opc.get_node(ua.ObjectIds.HierarchicalReferences).add_reference_type(
        ua.NodeId(NamespaceIndex=2), "0:HasSuperSecretVariable", symmetric=False, inversename="IsSuperSecretVariableOf"
    )

    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToRef")
    var = await fold.add_variable(2, "VarToRef", 42)

    await fold.add_reference(var, newtype)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [var] == await fold.get_referenced_nodes(newtype)

    await fold.delete_reference(var, newtype)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    await fold.add_reference(var, newtype, bidirectional=False)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [var] == await fold.get_referenced_nodes(newtype)

    await fold.delete_reference(var, newtype)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    await var.add_reference(fold, newtype, forward=False, bidirectional=False)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    with pytest.raises(ua.UaStatusCodeError):
        await fold.delete_reference(var, newtype)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    with pytest.raises(ua.UaStatusCodeError):
        await var.delete_reference(fold, newtype)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    await var.delete_reference(fold, newtype, forward=False)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    # clean-up
    await opc.opc.delete_nodes([fold, newtype], recursive=True)


async def test_readded_reference_preserves_target_type_definition(opc):
    parent = await opc.opc.nodes.objects.add_folder(2, "TypeDefinitionParent")
    obj_type = await opc.opc.nodes.base_object_type.add_object_type(2, "ReferenceTargetType")
    obj = await parent.add_object(2, "ReferenceTarget", obj_type.nodeid)
    var = await parent.add_variable(2, "ReferenceVariable", 42)

    for target, reference_type, expected_type in (
        (obj, ua.ObjectIds.Organizes, obj_type.nodeid),
        (var, ua.ObjectIds.HasComponent, ua.NodeId(ua.ObjectIds.BaseDataVariableType)),
    ):
        await parent.delete_reference(target, reference_type)
        await parent.add_reference(target, reference_type)
        refs = await parent.get_references(
            refs=reference_type,
            direction=ua.BrowseDirection.Forward,
        )
        ref = next(ref for ref in refs if ref.NodeId == target.nodeid)
        assert ref.TypeDefinition == expected_type
        inverse_refs = await target.get_references(
            refs=reference_type,
            direction=ua.BrowseDirection.Inverse,
        )
        inverse_ref = next(ref for ref in inverse_refs if ref.NodeId == parent.nodeid)
        assert inverse_ref.TypeDefinition == ua.NodeId(ua.ObjectIds.FolderType)

    await opc.opc.delete_nodes([parent, obj_type], recursive=True)


async def test_reference_with_nodeid_reftype(opc):
    """Test that add_reference/get_referenced_nodes/delete_reference accept ua.NodeId as reftype.

    Regression test for https://github.com/FreeOpcUa/opcua-asyncio/issues/1896
    where the type annotation enforced int, but _to_nodeid() already supports
    Node, ua.NodeId, str, and int at runtime.
    """
    newtype = await opc.opc.get_node(ua.ObjectIds.HierarchicalReferences).add_reference_type(
        ua.NodeId(NamespaceIndex=2), "0:HasNodeIdRefType"
    )
    reftype_nodeid = newtype.nodeid  # ua.NodeId, not int

    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderNodeIdRef")
    var = await fold.add_variable(2, "VarNodeIdRef", 42)

    # Use ua.NodeId as reftype (this is what issue #1896 requests)
    await fold.add_reference(var, reftype_nodeid)
    assert [var] == await fold.get_referenced_nodes(reftype_nodeid)
    assert [fold] == await var.get_referenced_nodes(reftype_nodeid)

    await fold.delete_reference(var, reftype_nodeid)
    assert [] == await fold.get_referenced_nodes(reftype_nodeid)

    # clean-up
    await opc.opc.delete_nodes([fold, newtype], recursive=True)


async def test_add_numeric_node(opc):
    objects = opc.opc.nodes.objects
    nid = ua.NodeId(9999, 3)
    qn = ua.QualifiedName("AddNodeVar1", 3)
    v1 = await objects.add_variable(nid, qn, 0)
    assert nid == v1.nodeid
    assert qn == await v1.read_browse_name()
    await opc.opc.delete_nodes([v1])


async def test_add_string_node(opc):
    objects = opc.opc.nodes.objects
    qn = ua.QualifiedName("AddNodeVar2", 3)
    nid = ua.NodeId("AddNodeVar2Id", 3)
    v2 = await objects.add_variable(nid, qn, 0)
    assert nid == v2.nodeid
    assert qn == await v2.read_browse_name()
    await opc.opc.delete_nodes([v2])


async def test_add_find_node_(opc):
    objects = opc.opc.nodes.objects
    o = await objects.add_object("ns=2;i=101;", "2:AddFindObject")
    o2 = await objects.get_child("2:AddFindObject")
    assert o == o2
    await opc.opc.delete_nodes([o, o2])


async def test_same_browse_name(opc):
    objects = opc.opc.nodes.objects
    f = await objects.add_folder("ns=2;i=201;", "2:MyBNameFolder")
    o = await f.add_object("ns=2;i=202;", "2:MyBName")
    v = await o.add_variable("ns=2;i=203;", "2:MyBNameTarget", 2.0)
    if opc.opc is not opc.server:
        with pytest.raises(ua.uaerrors.BadBrowseNameDuplicated):
            await f.add_object("ns=2;i=206;", "2:MyBName")
    attrs = ua.ObjectAttributes()
    attrs.DisplayName = ua.LocalizedText("MyBName")
    item = ua.AddNodesItem(
        ParentNodeId=f.nodeid,
        ReferenceTypeId=ua.NodeId(ua.ObjectIds.HasComponent),
        RequestedNewNodeId=ua.NodeId.from_string("ns=2;i=204;"),
        BrowseName=ua.QualifiedName("MyBName", 2),
        NodeClass=ua.NodeClass.Object,
        NodeAttributes=attrs,
        TypeDefinition=ua.NodeId(ua.ObjectIds.BaseObjectType),
    )
    (await f.session.add_nodes([item]))[0].StatusCode.check()
    o2 = opc.opc.get_node(item.RequestedNewNodeId)
    v2 = await o2.add_variable("ns=2;i=205;", "2:MyBNameTarget", 2.0)
    nodes = await objects.get_child("/2:MyBNameFolder/2:MyBName/2:MyBNameTarget", return_all=True)
    assert len(nodes) == 2
    assert nodes[0] == v
    assert nodes[1] == v2
    [nodes] = await objects.get_children_by_path(["/2:MyBNameFolder/2:MyBName/2:MyBNameTarget"])
    assert len(nodes) == 2
    assert nodes[0] == v
    assert nodes[1] == v2
    await opc.opc.delete_nodes([f, o, o2, v, v2])


async def test_use_namespace(opc):
    idx = await opc.opc.get_namespace_index("urn:enginir:opcua:server")
    assert 1 == idx
    root = opc.opc.nodes.root
    myvar = await root.add_variable(idx, "var_in_custom_namespace", [5])
    myid = myvar.nodeid
    assert idx == myid.NamespaceIndex
    await opc.opc.delete_nodes([myvar])


async def test_add_nodes(opc):
    objects = opc.opc.nodes.objects
    f = await objects.add_folder(3, "MyFolder")
    child = await objects.get_child("3:MyFolder")
    assert child == f
    o = await f.add_object(3, "MyObject")
    child = await f.get_child("3:MyObject")
    assert child == o
    v = await f.add_variable(3, "MyVariable", 6)
    child = await f.get_child("3:MyVariable")
    assert child == v
    p = await f.add_property(3, "MyProperty", 10)
    child = await f.get_child("3:MyProperty")
    assert child == p
    childs = await f.get_children()
    assert o in childs
    assert v in childs
    assert p in childs
    await opc.opc.delete_nodes([f, o, v, p, child])


async def test_add_node_with_type(opc):
    objects = opc.opc.nodes.objects
    f = await objects.add_folder(3, "MyFolder_TypeTest")

    o = await f.add_object(3, "MyObject1", ua.ObjectIds.BaseObjectType)
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o.read_type_definition()

    o = await f.add_object(3, "MyObject2", ua.NodeId(ua.ObjectIds.BaseObjectType, 0))
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o.read_type_definition()

    base_otype = opc.opc.get_node(ua.ObjectIds.BaseObjectType)
    custom_otype = await base_otype.add_object_type(2, "MyFooObjectType2")

    o = await f.add_object(3, "MyObject3", custom_otype.nodeid)
    assert custom_otype.nodeid == await o.read_type_definition()

    references = await o.get_references(refs=ua.ObjectIds.HasTypeDefinition, direction=ua.BrowseDirection.Forward)
    assert 1 == len(references)
    assert custom_otype.nodeid == references[0].NodeId
    await opc.opc.delete_nodes([f, o])


async def test_references_for_added_nodes(opc):
    objects = opc.opc.nodes.objects
    o = await objects.add_object(3, "MyObject4")
    nodes = await objects.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert o in nodes
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert objects in nodes
    assert objects == await o.get_parent()
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o.read_type_definition()
    assert [] == await o.get_references(ua.ObjectIds.HasModellingRule)

    o2 = await o.add_object(3, "MySecondObject")
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert o2 in nodes
    nodes = await o2.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert o in nodes
    assert o == await o2.get_parent()
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o2.read_type_definition()
    assert [] == await o2.get_references(ua.ObjectIds.HasModellingRule)

    v = await o.add_variable(3, "MyVariable", 6)
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert v in nodes
    nodes = await v.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert o in nodes
    assert o == await v.get_parent()
    assert ua.NodeId(ua.ObjectIds.BaseDataVariableType) == await v.read_type_definition()
    assert [] == await v.get_references(ua.ObjectIds.HasModellingRule)

    p = await o.add_property(3, "MyProperty", 2)
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.HasProperty,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert p in nodes
    nodes = await p.get_referenced_nodes(
        refs=ua.ObjectIds.HasProperty,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert o in nodes
    assert o == await p.get_parent()
    assert ua.NodeId(ua.ObjectIds.PropertyType) == await p.read_type_definition()
    assert [] == await p.get_references(ua.ObjectIds.HasModellingRule)

    m = await objects.get_child("2:ServerMethod")
    assert [] == await m.get_references(ua.ObjectIds.HasModellingRule)


async def test_copy_node(opc):
    dev_t = await opc.opc.nodes.base_structure_type.add_object_type(ua.NodeId(NamespaceIndex=2), "0:MyDevice")
    _ = await dev_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:sensor", 1.0)
    _ = await dev_t.add_property(ua.NodeId(NamespaceIndex=2), "0:sensor_id", "0340")
    ctrl_t = await dev_t.add_object(ua.NodeId(NamespaceIndex=2), "0:controller")
    prop_t = await ctrl_t.add_property(ua.NodeId(NamespaceIndex=2), "0:state", "Running")
    # Create device sutype
    devd_t = await dev_t.add_object_type(ua.NodeId(NamespaceIndex=2), "0:MyDeviceDerived")
    _ = await devd_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:childparam", 1.0)
    _ = await devd_t.add_property(ua.NodeId(NamespaceIndex=2), "0:sensorx_id", "0340")
    nodes = await copy_node(opc.opc.nodes.objects, dev_t)
    mydevice = nodes[0]
    assert ua.NodeClass.ObjectType == await mydevice.read_node_class()
    assert 3 == len(await mydevice.get_children())
    _ = await mydevice.get_child(["0:controller"])
    prop = await mydevice.get_child(["0:controller", "0:state"])
    assert ua.NodeId(ua.ObjectIds.PropertyType) == await prop.read_type_definition()
    assert "Running" == await prop.read_value()
    assert prop.nodeid != prop_t.nodeid


async def test_duplicated_browsenames_same_ns_protperties(opc):
    parentfolder = await opc.opc.nodes.objects.add_folder(2, "parent_folder")
    _ = await parentfolder.add_property(2, "Myproperty", 123)
    try:
        _ = await parentfolder.add_property(2, "Myproperty", 456)
        await opc.opc.delete_nodes([parentfolder])
        pytest.fail("childproperty2 should never be created!")
    except Exception:
        await opc.opc.delete_nodes([parentfolder])
        return

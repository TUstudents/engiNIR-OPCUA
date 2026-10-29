from typing import Any

import pytest

from enginir_opcua import Client, ua
from enginir_opcua.ua.uaerrors import UaStatusCodeError
from tests.access_rig import AccessRig, make_access_rig  # noqa: F401

ATTRIBUTES = {
    ua.NodeClass.Object: ua.ObjectAttributes,
    ua.NodeClass.Variable: ua.VariableAttributes,
    ua.NodeClass.Method: ua.MethodAttributes,
    ua.NodeClass.ObjectType: ua.ObjectTypeAttributes,
    ua.NodeClass.VariableType: ua.VariableTypeAttributes,
    ua.NodeClass.ReferenceType: ua.ReferenceTypeAttributes,
    ua.NodeClass.DataType: ua.DataTypeAttributes,
    ua.NodeClass.View: ua.ViewAttributes,
}
ORGANIZES = ua.NodeId(ua.ObjectIds.Organizes)
HAS_COMPONENT = ua.NodeId(ua.ObjectIds.HasComponent)
OBJECTS = ua.NodeId(ua.ObjectIds.ObjectsFolder)


def code(value: int) -> ua.StatusCode:
    return ua.StatusCode(value)


def new_item(
    rig: AccessRig,
    name: str,
    node_class: ua.NodeClass = ua.NodeClass.Object,
    parent: ua.NodeId = OBJECTS,
    reference_type: ua.NodeId = ORGANIZES,
    type_definition: ua.NodeId | None = None,
    attributes: Any = None,
    requested: ua.NodeId | None = None,
    browse_name: ua.QualifiedName | None = None,
) -> ua.AddNodesItem:
    if attributes is None:
        attributes = ATTRIBUTES[node_class]()
        attributes.DisplayName = ua.LocalizedText(name)
        if node_class == ua.NodeClass.Variable:
            attributes.DataType = ua.NodeId(ua.ObjectIds.Int32)
            attributes.Value = ua.Variant(1, ua.VariantType.Int32)
    return ua.AddNodesItem(
        ParentNodeId=parent,
        ReferenceTypeId=reference_type,
        RequestedNewNodeId=requested if requested is not None else ua.NodeId(name, rig.ns),
        BrowseName=browse_name if browse_name is not None else ua.QualifiedName(name, rig.ns),
        NodeClass=node_class,
        NodeAttributes=attributes,
        TypeDefinition=type_definition if type_definition is not None else ua.NodeId(),
    )


async def add_one(client: Client, item: ua.AddNodesItem) -> ua.AddNodesResult:
    return (await client.uaclient.add_nodes([item]))[0]


async def read_attribute(rig: AccessRig, nodeid: ua.NodeId, attribute: ua.AttributeIds) -> Any:
    dv = (await rig.admin.uaclient.read(ua.ReadParameters(NodesToRead=[ua.ReadValueId(nodeid, attribute)])))[0]
    return dv.Value.Value if dv.Value is not None else None


def mutated(attribute: str, value: Any) -> Any:
    return lambda item: setattr(item, attribute, value)


@pytest.mark.parametrize(
    ("mutate", "status"),
    [
        pytest.param(mutated("NodeClass", ua.NodeClass.Unspecified), ua.StatusCodes.BadNodeClassInvalid, id="class"),
        pytest.param(
            mutated("NodeClass", ua.NodeClass.Variable), ua.StatusCodes.BadNodeAttributesInvalid, id="attributes"
        ),
        pytest.param(mutated("BrowseName", ua.QualifiedName()), ua.StatusCodes.BadBrowseNameInvalid, id="name"),
        pytest.param(
            mutated("ParentNodeId", ua.NodeId("Nothing", 9)), ua.StatusCodes.BadParentNodeIdInvalid, id="parent"
        ),
        pytest.param(
            mutated("ReferenceTypeId", ua.NodeId(ua.ObjectIds.Server)),
            ua.StatusCodes.BadReferenceTypeIdInvalid,
            id="not-a-reference-type",
        ),
        pytest.param(
            mutated("ReferenceTypeId", ua.NodeId(ua.ObjectIds.HasTypeDefinition)),
            ua.StatusCodes.BadReferenceNotAllowed,
            id="not-hierarchical",
        ),
        pytest.param(
            mutated("ReferenceTypeId", ua.NodeId(ua.ObjectIds.HierarchicalReferences)),
            ua.StatusCodes.BadReferenceNotAllowed,
            id="abstract-reference-type",
        ),
        pytest.param(
            mutated("TypeDefinition", ua.NodeId(ua.ObjectIds.BaseDataVariableType)),
            ua.StatusCodes.BadTypeDefinitionInvalid,
            id="wrong-type-definition",
        ),
        pytest.param(
            mutated("TypeDefinition", ua.NodeId("Nothing", 9)),
            ua.StatusCodes.BadTypeDefinitionInvalid,
            id="unknown-type-definition",
        ),
        pytest.param(
            mutated("RequestedNewNodeId", ua.NodeId(70000, 0)), ua.StatusCodes.BadNodeIdRejected, id="namespace-0"
        ),
        pytest.param(
            mutated("RequestedNewNodeId", ua.NodeId(0, 0)), ua.StatusCodes.BadNodeIdRejected, id="null-in-namespace-0"
        ),
        pytest.param(
            mutated("RequestedNewNodeId", ua.NodeId(ua.ObjectIds.ObjectsFolder)),
            ua.StatusCodes.BadNodeIdRejected,
            id="existing-in-namespace-0",
        ),
    ],
)
async def test_srv19_add_nodes_checks(access_rig: AccessRig, mutate: Any, status: int) -> None:
    """Part 4, 5.8.2.2, 5.8.2.4."""
    item = new_item(access_rig, "CheckedObject")
    mutate(item)
    result = await add_one(access_rig.admin, item)
    assert result.StatusCode == code(status)
    assert result.AddedNodeId.is_null()
    assert ua.NodeId("CheckedObject", access_rig.ns) not in access_rig.server.iserver.aspace


async def test_srv19_add_nodes_existing_id_and_duplicate_browse_name(access_rig: AccessRig) -> None:
    """Part 4, 5.8.2.4."""
    first = await add_one(access_rig.admin, new_item(access_rig, "FirstObject"))
    assert first.StatusCode.is_good()
    assert first.AddedNodeId == ua.NodeId("FirstObject", access_rig.ns)
    again = await add_one(access_rig.admin, new_item(access_rig, "FirstObject"))
    assert again.StatusCode == code(ua.StatusCodes.BadNodeIdExists)
    same_name = new_item(access_rig, "OtherId", browse_name=ua.QualifiedName("FirstObject", access_rig.ns))
    assert (await add_one(access_rig.admin, same_name)).StatusCode == code(ua.StatusCodes.BadBrowseNameDuplicated)
    other_reference = new_item(
        access_rig,
        "OtherIdOtherReference",
        browse_name=ua.QualifiedName("FirstObject", access_rig.ns),
        reference_type=HAS_COMPONENT,
    )
    assert (await add_one(access_rig.admin, other_reference)).StatusCode.is_good()


async def test_srv19_add_nodes_allocates_a_null_identifier_outside_namespace_zero(access_rig: AccessRig) -> None:
    """Part 4, 5.8.2.2."""
    item = new_item(access_rig, "Allocated", requested=ua.NodeId(0, access_rig.ns))
    result = await add_one(access_rig.admin, item)
    assert result.StatusCode.is_good()
    assert result.AddedNodeId.NamespaceIndex == access_rig.ns
    assert not result.AddedNodeId.is_null()


async def test_srv19_add_nodes_in_namespace_zero_is_allowed_in_process(access_rig: AccessRig) -> None:
    """Design: only Session requests are kept out of namespace 0."""
    node = await access_rig.server.nodes.objects.add_object(ua.NodeId(990001, 0), "InProcessNamespaceZero")
    assert node.nodeid == ua.NodeId(990001, 0)
    await access_rig.server.delete_nodes([node])


async def test_srv19_add_nodes_by_a_user_is_refused(access_rig: AccessRig) -> None:
    """Part 4, 5.8.2."""
    with pytest.raises(UaStatusCodeError) as error:
        await add_one(access_rig.user, new_item(access_rig, "NotForUsers"))
    assert error.value.code == ua.StatusCodes.BadUserAccessDenied


async def test_srv63_added_nodes_have_the_mandatory_attributes(access_rig: AccessRig) -> None:
    """Part 4, 5.8.2.2; Part 3, 5.6.2."""
    bare = ua.VariableAttributes()
    bare.SpecifiedAttributes = 0
    bare.DataType = ua.NodeId(ua.ObjectIds.Int32)
    bare.Value = ua.Variant(1, ua.VariantType.Int32)
    bare.SpecifiedAttributes = ua.NodeAttributesMask.DataType | ua.NodeAttributesMask.Value
    result = await add_one(
        access_rig.admin, new_item(access_rig, "BareVariable", ua.NodeClass.Variable, attributes=bare)
    )
    assert result.StatusCode.is_good()
    nodeid = result.AddedNodeId
    expected = {
        ua.AttributeIds.ValueRank: -2,
        ua.AttributeIds.AccessLevel: 1,
        ua.AttributeIds.UserAccessLevel: 1,
        ua.AttributeIds.Historizing: False,
        ua.AttributeIds.MinimumSamplingInterval: -1,
    }
    for attribute, value in expected.items():
        assert await read_attribute(access_rig, nodeid, attribute) == value, attribute.name
    assert (await read_attribute(access_rig, nodeid, ua.AttributeIds.DisplayName)).Text == "BareVariable"

    bare_object = ua.ObjectAttributes()
    bare_object.SpecifiedAttributes = 0
    created = await add_one(access_rig.admin, new_item(access_rig, "BareObject", attributes=bare_object))
    assert await read_attribute(access_rig, created.AddedNodeId, ua.AttributeIds.EventNotifier) == 0

    bare_method = ua.MethodAttributes()
    bare_method.SpecifiedAttributes = 0
    method = new_item(
        access_rig, "BareMethod", ua.NodeClass.Method, reference_type=HAS_COMPONENT, attributes=bare_method
    )
    created = await add_one(access_rig.admin, method)
    assert await read_attribute(access_rig, created.AddedNodeId, ua.AttributeIds.Executable) is True
    assert await read_attribute(access_rig, created.AddedNodeId, ua.AttributeIds.UserExecutable) is True

    bare_type = ua.ObjectTypeAttributes()
    bare_type.SpecifiedAttributes = 0
    type_item = new_item(access_rig, "BareType", ua.NodeClass.ObjectType, attributes=bare_type)
    type_item.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasSubtype)
    type_item.ParentNodeId = ua.NodeId(ua.ObjectIds.BaseObjectType)
    created = await add_one(access_rig.admin, type_item)
    assert await read_attribute(access_rig, created.AddedNodeId, ua.AttributeIds.IsAbstract) is False


async def test_srv63_added_objects_and_variables_get_the_base_type_definition(access_rig: AccessRig) -> None:
    """Part 4, 5.8.2.1."""
    created = await add_one(access_rig.admin, new_item(access_rig, "DefaultTypeObject"))
    node = access_rig.server.get_node(created.AddedNodeId)
    assert (await node.read_type_definition()) == ua.NodeId(ua.ObjectIds.BaseObjectType)
    variable = await add_one(access_rig.admin, new_item(access_rig, "DefaultTypeVariable", ua.NodeClass.Variable))
    node = access_rig.server.get_node(variable.AddedNodeId)
    assert (await node.read_type_definition()) == ua.NodeId(ua.ObjectIds.BaseDataVariableType)


async def references_from(rig: AccessRig, nodeid: ua.NodeId) -> list[ua.ReferenceDescription]:
    node = rig.server.iserver.aspace[nodeid]
    return list(node.references)


def reference(
    source: ua.NodeId,
    target: ua.NodeId,
    reference_type: ua.NodeId = ORGANIZES,
    forward: bool = True,
    target_class: ua.NodeClass = ua.NodeClass.Unspecified,
) -> ua.AddReferencesItem:
    return ua.AddReferencesItem(
        SourceNodeId=source,
        ReferenceTypeId=reference_type,
        IsForward=forward,
        TargetNodeId=target,
        TargetNodeClass=target_class,
    )


async def add_reference(client: Client, item: ua.AddReferencesItem) -> ua.StatusCode:
    return (await client.uaclient.add_references([item]))[0]


async def test_srv64_add_references_checks(access_rig: AccessRig) -> None:
    """Part 4, 5.8.3.4."""
    await add_one(access_rig.admin, new_item(access_rig, "RefSource"))
    await add_one(access_rig.admin, new_item(access_rig, "RefTarget"))
    source = ua.NodeId("RefSource", access_rig.ns)
    target = ua.NodeId("RefTarget", access_rig.ns)
    admin = access_rig.admin
    assert await add_reference(admin, reference(ua.NodeId("Nothing", 9), target)) == code(
        ua.StatusCodes.BadSourceNodeIdInvalid
    )
    assert await add_reference(admin, reference(source, ua.NodeId("Nothing", 9))) == code(
        ua.StatusCodes.BadTargetNodeIdInvalid
    )
    assert await add_reference(admin, reference(source, target, ua.NodeId(ua.ObjectIds.Server))) == code(
        ua.StatusCodes.BadReferenceTypeIdInvalid
    )
    assert await add_reference(admin, reference(source, target, ua.NodeId(ua.ObjectIds.References))) == code(
        ua.StatusCodes.BadReferenceTypeIdInvalid
    )
    foreign = reference(source, target)
    foreign.TargetServerUri = "urn:other:server"
    assert await add_reference(admin, foreign) == code(ua.StatusCodes.BadServerUriInvalid)
    wrong_class = reference(source, target, target_class=ua.NodeClass.Variable)
    assert await add_reference(admin, wrong_class) == code(ua.StatusCodes.BadNodeClassInvalid)
    assert await add_reference(admin, reference(source, source)) == code(ua.StatusCodes.BadInvalidSelfReference)
    assert await add_reference(admin, reference(source, target, target_class=ua.NodeClass.Object)) == code(0)
    assert await add_reference(admin, reference(source, target)) == code(ua.StatusCodes.BadDuplicateReferenceNotAllowed)
    assert await add_reference(admin, reference(source, target, forward=False)) == code(
        ua.StatusCodes.BadReferenceNotAllowed
    )
    assert len([r for r in await references_from(access_rig, source) if r.NodeId == target]) == 1


async def test_srv64_add_references_in_namespace_zero(access_rig: AccessRig) -> None:
    """Design: Sessions cannot change namespace 0, but may hang their nodes under it."""
    await add_one(access_rig.admin, new_item(access_rig, "HangingObject"))
    mine = ua.NodeId("HangingObject", access_rig.ns)
    both_standard = reference(ua.NodeId(ua.ObjectIds.Server), ua.NodeId(ua.ObjectIds.ObjectsFolder))
    assert await add_reference(access_rig.admin, both_standard) == code(ua.StatusCodes.BadReferenceNotAllowed)
    hung = reference(ua.NodeId(ua.ObjectIds.Server), mine, HAS_COMPONENT)
    assert await add_reference(access_rig.admin, hung) == code(0)


async def delete_reference_item(
    source: ua.NodeId, target: ua.NodeId, reference_type: ua.NodeId = ORGANIZES, bidirectional: bool = False
) -> ua.DeleteReferencesItem:
    return ua.DeleteReferencesItem(
        SourceNodeId=source,
        ReferenceTypeId=reference_type,
        IsForward=True,
        TargetNodeId=target,
        DeleteBidirectional=bidirectional,
    )


async def test_srv64_delete_references_checks(access_rig: AccessRig) -> None:
    """Part 4, 5.8.5.2."""
    await add_one(access_rig.admin, new_item(access_rig, "DelRefSource"))
    await add_one(access_rig.admin, new_item(access_rig, "DelRefTarget"))
    source = ua.NodeId("DelRefSource", access_rig.ns)
    target = ua.NodeId("DelRefTarget", access_rig.ns)
    assert await add_reference(access_rig.admin, reference(source, target)) == code(0)
    client = access_rig.admin.uaclient

    async def delete(item: ua.DeleteReferencesItem) -> ua.StatusCode:
        return (await client.delete_references([item]))[0]

    assert await delete(await delete_reference_item(ua.NodeId("Nothing", 9), target)) == code(
        ua.StatusCodes.BadSourceNodeIdInvalid
    )
    assert await delete(await delete_reference_item(source, ua.NodeId("Nothing", 9))) == code(
        ua.StatusCodes.BadTargetNodeIdInvalid
    )
    assert await delete(await delete_reference_item(source, target, ua.NodeId(ua.ObjectIds.Server))) == code(
        ua.StatusCodes.BadReferenceTypeIdInvalid
    )
    assert await delete(
        await delete_reference_item(ua.NodeId(ua.ObjectIds.Server), ua.NodeId(ua.ObjectIds.ObjectsFolder))
    ) == code(ua.StatusCodes.BadNoDeleteRights)
    assert await delete(await delete_reference_item(source, target)) == code(0)
    assert await delete(await delete_reference_item(source, target)) == code(ua.StatusCodes.BadNotFound)


async def test_srv64_delete_nodes_namespace_zero_is_refused(access_rig: AccessRig) -> None:
    """Design: Sessions cannot change namespace 0."""
    client = access_rig.admin.uaclient
    params = ua.DeleteNodesParameters([ua.DeleteNodesItem(ua.NodeId(ua.ObjectIds.Server_ServerStatus_State), True)])
    assert (await client.delete_nodes(params))[0] == code(ua.StatusCodes.BadNoDeleteRights)
    assert ua.NodeId(ua.ObjectIds.Server_ServerStatus_State) in access_rig.server.iserver.aspace
    unknown = ua.DeleteNodesParameters(
        [ua.DeleteNodesItem(ua.NodeId("Nothing", access_rig.ns), True), ua.DeleteNodesItem()]
    )
    assert await client.delete_nodes(unknown) == [
        code(ua.StatusCodes.BadNodeIdUnknown),
        code(ua.StatusCodes.BadNodeIdInvalid),
    ]


async def test_srv64_delete_nodes_with_and_without_target_references(access_rig: AccessRig) -> None:
    """Part 4, 5.8.4.2."""
    parent = await add_one(access_rig.admin, new_item(access_rig, "DeleteParent"))
    child = new_item(access_rig, "DeleteChildA", parent=parent.AddedNodeId)
    other = new_item(access_rig, "DeleteChildB", parent=parent.AddedNodeId)
    for item in (child, other):
        assert (await add_one(access_rig.admin, item)).StatusCode.is_good()
    client = access_rig.admin.uaclient
    result = await client.delete_nodes(ua.DeleteNodesParameters([ua.DeleteNodesItem(child.RequestedNewNodeId, True)]))
    assert result == [code(0)]
    remaining = [r.NodeId for r in await references_from(access_rig, parent.AddedNodeId)]
    assert child.RequestedNewNodeId not in remaining
    result = await client.delete_nodes(ua.DeleteNodesParameters([ua.DeleteNodesItem(other.RequestedNewNodeId, False)]))
    assert result == [code(0)]
    assert other.RequestedNewNodeId in [r.NodeId for r in await references_from(access_rig, parent.AddedNodeId)]
    descriptions = await access_rig.admin.uaclient.browse(
        ua.BrowseParameters(
            NodesToBrowse=[
                ua.BrowseDescription(
                    NodeId=parent.AddedNodeId,
                    BrowseDirection=ua.BrowseDirection.Forward,
                    ReferenceTypeId=ua.NodeId(),
                    IncludeSubtypes=True,
                    ResultMask=ua.BrowseResultMask.All,
                )
            ]
        )
    )
    assert other.RequestedNewNodeId not in [r.NodeId for r in descriptions[0].References]

"""
Instantiate a new node and its child nodes from a node type.
"""

from __future__ import annotations

import logging
from typing import Any

import enginir_opcua
from enginir_opcua import ua

from .copy_node_util import _added_node, _rdesc_from_node, _read_and_copy_attrs, remove_created
from .node_factory import make_node
from .ua_utils import get_node_supertypes

_logger = logging.getLogger(__name__)

_MANDATORY = ua.NodeId(ua.ObjectIds.ModellingRule_Mandatory)
_OPTIONAL = ua.NodeId(ua.ObjectIds.ModellingRule_Optional)
_PLACEHOLDERS = (
    ua.NodeId(ua.ObjectIds.ModellingRule_MandatoryPlaceholder),
    ua.NodeId(ua.ObjectIds.ModellingRule_OptionalPlaceholder),
)
_EXPOSES_ITS_ARRAY = ua.NodeId(ua.ObjectIds.ModellingRule_ExposesItsArray)
_BASE_TYPES = (
    ua.NodeId(ua.ObjectIds.BaseObjectType),
    ua.NodeId(ua.ObjectIds.BaseDataVariableType),
    ua.NodeId(ua.ObjectIds.PropertyType),
)
_INSTANTIABLE = (ua.NodeClass.ObjectType, ua.NodeClass.VariableType)


async def is_abstract(node_type: enginir_opcua.Node) -> bool:
    result = await node_type.read_attribute(ua.AttributeIds.IsAbstract)
    return result.Value.Value  # type: ignore[union-attr]


async def instantiate(
    parent: enginir_opcua.Node,
    node_type: enginir_opcua.Node,
    nodeid: ua.NodeId | None = None,
    bname: ua.QualifiedName | str | None = None,
    dname: ua.LocalizedText | None = None,
    idx: int = 0,
    instantiate_optional: bool = True,
) -> list[enginir_opcua.Node]:
    """
    Instantiate an ObjectType or VariableType below a parent node. The new node, listed first in the result,
    gets the children its type and the supertypes declare with the ModellingRules Mandatory (and Optional
    if instantiate_optional). Placeholders are not instantiated. If a step fails the nodes made so far are removed.
    """
    rdesc = await _rdesc_from_node(parent, node_type)
    rdesc.TypeDefinition = node_type.nodeid
    if rdesc.NodeClass not in _INSTANTIABLE:
        raise ua.UaError(f"InstantiationError NodeId: {node_type.nodeid} is a {rdesc.NodeClass.name}, not a type")
    if await is_abstract(node_type):
        raise ua.UaError(f"InstantiationError NodeId: {node_type.nodeid} is abstract and cant be instantiated!")
    if nodeid is None:
        nodeid = ua.NodeId(NamespaceIndex=idx)
    if bname is None:
        bname = rdesc.BrowseName
    elif isinstance(bname, str):
        bname = ua.QualifiedName.from_string(bname)

    created: list[ua.NodeId] = []
    try:
        await _instantiate_node(
            parent.session,
            make_node(parent.session, rdesc.NodeId),
            parent.nodeid,
            rdesc,
            nodeid,
            bname,
            created,
            dname=dname,
            instantiate_optional=instantiate_optional,
        )
    except BaseException:
        await remove_created(parent.session, created)
        raise
    return [make_node(parent.session, nid) for nid in created]


async def _modelling_rule(session: Any, declaration: enginir_opcua.Node, name: ua.QualifiedName) -> ua.NodeId | None:
    rules = await declaration.get_referenced_nodes(ua.ObjectIds.HasModellingRule, ua.BrowseDirection.Forward)
    if not rules:
        return None
    if len(rules) > 1:
        _logger.warning("Instantiate: %s has several modelling rules, using the first", name)
    return rules[0].nodeid


async def _declaration_sources(
    node_type: enginir_opcua.Node, is_declaration: bool, typedef: ua.NodeId | None
) -> list[enginir_opcua.Node]:
    sources: list[enginir_opcua.Node] = []
    if is_declaration:
        sources.append(node_type)
        if typedef is None or typedef.is_null() or typedef in _BASE_TYPES:
            return sources
        typenode = make_node(node_type.session, typedef)
    else:
        typenode = node_type
    sources.extend(await get_node_supertypes(typenode, includeitself=True, skipbase=False))
    return sources


async def _instantiate_node(
    session: Any,
    node_type: enginir_opcua.Node,
    parentid: ua.NodeId,
    rdesc: ua.ReferenceDescription,
    nodeid: ua.NodeId,
    bname: ua.QualifiedName,
    created: list[ua.NodeId],
    dname: ua.LocalizedText | None = None,
    is_declaration: bool = False,
    instantiate_optional: bool = True,
) -> None:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = bname
    addnode.ParentNodeId = parentid
    addnode.ReferenceTypeId = rdesc.ReferenceTypeId
    addnode.TypeDefinition = rdesc.TypeDefinition

    if rdesc.NodeClass in (ua.NodeClass.Object, ua.NodeClass.ObjectType):
        addnode.NodeClass = ua.NodeClass.Object
        await _read_and_copy_attrs(node_type, ua.ObjectAttributes(), addnode)
    elif rdesc.NodeClass in (ua.NodeClass.Variable, ua.NodeClass.VariableType):
        addnode.NodeClass = ua.NodeClass.Variable
        await _read_and_copy_attrs(node_type, ua.VariableAttributes(), addnode)
    elif rdesc.NodeClass == ua.NodeClass.Method:
        addnode.NodeClass = ua.NodeClass.Method
        await _read_and_copy_attrs(node_type, ua.MethodAttributes(), addnode)
    else:
        _logger.error("Instantiate: Node class not supported: %s", rdesc.NodeClass)
        raise ua.UaError(f"Instantiate: Node class {rdesc.NodeClass} not supported")
    if addnode.NodeClass not in (ua.NodeClass.Object, ua.NodeClass.Variable):
        addnode.TypeDefinition = ua.NodeId()
    if dname is not None:
        addnode.NodeAttributes.DisplayName = dname

    added = await _added_node(session, addnode, created)

    names: set[tuple[int, str | None]] = set()
    typedef = rdesc.TypeDefinition if is_declaration else None
    for source in await _declaration_sources(node_type, is_declaration, typedef):
        for c_rdesc in await source.get_children_descriptions():
            if (c_rdesc.BrowseName.NamespaceIndex, c_rdesc.BrowseName.Name) in names:
                continue
            c_node = make_node(session, c_rdesc.NodeId)
            rule = await _modelling_rule(session, c_node, c_rdesc.BrowseName)
            if rule is None:
                _logger.info("Instantiate: skip %s without modelling rule", c_rdesc.BrowseName)
                continue
            if rule in _PLACEHOLDERS or rule == _EXPOSES_ITS_ARRAY:
                _logger.info("Instantiate: skip %s with modelling rule %s", c_rdesc.BrowseName, rule)
                continue
            if rule != _MANDATORY:
                if rule != _OPTIONAL:
                    _logger.info("Instantiate: treating the rule %s of %s as Optional", rule, c_rdesc.BrowseName)
                if not instantiate_optional:
                    continue
            if added.NodeIdType is ua.NodeIdType.String:
                child_id = ua.NodeId(f"{added.Identifier!s}.{c_rdesc.BrowseName.Name}", added.NamespaceIndex)
            else:
                child_id = ua.NodeId(NamespaceIndex=added.NamespaceIndex)
            names.add((c_rdesc.BrowseName.NamespaceIndex, c_rdesc.BrowseName.Name))
            await _instantiate_node(
                session,
                c_node,
                added,
                c_rdesc,
                child_id,
                c_rdesc.BrowseName,
                created,
                is_declaration=True,
                instantiate_optional=instantiate_optional,
            )

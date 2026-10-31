"""
add nodes defined in XML to address space
format is the one from opc-ua specification
"""

from __future__ import annotations

import dataclasses
import logging
import re
import uuid
from pathlib import Path
from typing import Any, cast

import enginir_opcua
from enginir_opcua import ua
from enginir_opcua.common.structures104 import (
    clean_name,
    load_basetype_alias_xml_import,
    load_custom_struct_xml_import,
    load_enum_xml_import,
    option_set_base_name,
)
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import get_safe_type_hints, struct_from_binary
from enginir_opcua.ua.uatypes import (
    type_from_list,
    type_from_optional,
    type_is_list,
    type_is_optional,
    type_is_union,
    types_from_union,
)

from ..ua.uaerrors import UaError
from .xmlparser import NULL_DATETIME, ExtObj, NodeData, RefStruct, XMLParser, parse_scalar, xs_datetime

_logger = logging.getLogger(__name__)

HAS_TYPE_DEFINITION = ua.NodeId(ua.ObjectIds.HasTypeDefinition)
HAS_ENCODING = ua.NodeId(ua.ObjectIds.HasEncoding)
DATA_TYPE_ENCODING_TYPE = ua.NodeId(ua.ObjectIds.DataTypeEncodingType)
HAS_COMPONENT = ua.NodeId(ua.ObjectIds.HasComponent)
HAS_SUBTYPE = ua.NodeId(ua.ObjectIds.HasSubtype)
BASE_DATA_TYPE = ua.NodeId(ua.ObjectIds.BaseDataType)
STRUCTURE = ua.NodeId(ua.ObjectIds.Structure)
UNION = ua.NodeId(ua.ObjectIds.Union)
HIERARCHICAL_NAMES = (
    "HierarchicalReferences",
    "HasChild",
    "Organizes",
    "HasEventSource",
    "HasNotifier",
    "Aggregates",
    "HasSubtype",
    "HasProperty",
    "HasComponent",
    "HasOrderedComponent",
    "HasAddIn",
)
HIERARCHICAL_BASE = frozenset(
    ua.NodeId(getattr(ua.ObjectIds, name)) for name in HIERARCHICAL_NAMES if hasattr(ua.ObjectIds, name)
)
WRITE_MASK_DEFINITION = 1 << ua.WriteMask.DataTypeDefinition
WRITE_MASK_OF_WRITE_MASKS = (1 << ua.WriteMask.WriteMask) | (1 << ua.WriteMask.UserWriteMask)


class NodeSetError(UaError, ValueError):
    """
    A UANodeSet could not be imported. `status` is the StatusCode a service answered with, if one did, and
    `added` lists the nodes that exist because of the import so far.
    """

    def __init__(self, message: str, status: ua.StatusCode | None = None, added: list[ua.NodeId] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.added: list[ua.NodeId] = added or []


def _semantic_version(text: str) -> tuple[tuple[int, ...], tuple[Any, ...]]:
    core, _, prerelease = text.split("+", 1)[0].partition("-")
    numbers = tuple(int(part) for part in re.findall(r"\d+", core))
    parts = tuple((0, int(p)) if p.isdigit() else (1, p) for p in prerelease.split(".")) if prerelease else ()
    return numbers, ((1,) if not parts else (0, *parts))


def _compare_versions(left: str, right: str) -> int:
    a, b = _semantic_version(left), _semantic_version(right)
    return (a > b) - (a < b)


def _parse_version(version_string: str) -> list[int]:
    return list(_semantic_version(version_string)[0])


class XmlImporter:
    def __init__(
        self,
        server: enginir_opcua.Server | enginir_opcua.Client,
        strict_mode: bool = True,
        auto_load_definitions: bool = True,
    ) -> None:
        """
        strict_mode: stop on an error, if False only an error message is logged,
                     but the import continues
        auto_load_definitions: auto generate code stubs on the fly for enum and structs
        """
        self.parser = XMLParser()
        self.session: Any = server
        self.namespaces: dict[int, int] = {}
        self.aliases: dict[str, ua.NodeId] = {}
        self._unmigrated_aliases: dict[str, str | None] = {}
        self.refs: list[ua.AddReferencesItem] = []
        self.strict_mode = strict_mode
        self.auto_load_definitions = auto_load_definitions
        self.failures: list[tuple[Any, Exception]] = []
        self._added: list[ua.NodeId] = []
        self._browsenames: dict[ua.NodeId, ua.QualifiedName] = {}
        self._definitions: dict[ua.NodeId, Any] = {}
        self._type_loads: list[tuple[str, ua.NodeId, str, Any, str]] = []
        self._hierarchical: dict[ua.NodeId, bool] = {}
        self._supertypes: dict[ua.NodeId, ua.NodeId] = {}

    async def _map_namespaces(self) -> dict[int, int]:
        """
        creates a mapping between the namespaces in the xml file and in the server.
        if not present the namespace is registered.
        """
        xml_uris = self.parser.get_used_namespaces()
        if xml_uris:
            if xml_uris[0] == "http://opcfoundation.org/UA/":
                xml_uris.pop(0)

        server_uris = await self.session.get_namespace_array()
        namespaces_map = {}
        for ns_index, ns_uri in enumerate(xml_uris, 1):
            if ns_uri in server_uris:
                namespaces_map[ns_index] = server_uris.index(ns_uri)
            else:
                ns_server_index = await self.session.register_namespace(ns_uri)
                namespaces_map[ns_index] = ns_server_index
        return namespaces_map

    def _map_aliases(self, aliases: dict[str, str | None]) -> dict[str, ua.NodeId]:
        """
        maps the import aliases to the correct namespaces
        """
        return {alias: self._to_migrated_nodeid(node_id) for alias, node_id in aliases.items()}

    async def _get_existing_model_in_namespace(self) -> list[dict[str, Any]]:
        server_model_list = []
        server_namespaces_node = await self.session.nodes.namespaces.get_children()
        for model_node in server_namespaces_node:
            model_version = None
            try:
                model_version = await (await model_node.get_child("ModelVersion")).read_value()
            except UaError:
                pass
            published = await (await model_node.get_child("NamespacePublicationDate")).read_value()
            server_model_list.append(
                {
                    "ModelUri": await (await model_node.get_child("NamespaceUri")).read_value(),
                    "Version": await (await model_node.get_child("NamespaceVersion")).read_value(),
                    "ModelVersion": model_version,
                    "PublicationDate": published,
                }
            )
        return server_model_list

    @staticmethod
    def _model_satisfies(model: dict[str, Any], required: dict[str, str]) -> bool:
        if model["ModelUri"] != required["ModelUri"]:
            return False
        required_date = xs_datetime(required["PublicationDate"]) if required.get("PublicationDate") else None
        model_date = model["PublicationDate"]
        if model_date is not None and model_date.tzinfo is None:
            model_date = model_date.replace(tzinfo=NULL_DATETIME.tzinfo)
        if required.get("ModelVersion") and model.get("ModelVersion"):
            order = _compare_versions(model["ModelVersion"], required["ModelVersion"])
            if order != 0:
                return order > 0
        if required_date is not None and model_date is not None:
            return model_date >= required_date
        return True

    async def _check_required_models(
        self, xmlpath: str | Path | None = None, xmlstring: str | bytes | None = None
    ) -> None:
        req_models = self.parser.list_required_models(xmlpath, xmlstring)
        if not req_models:
            return
        server_model_list = await self._get_existing_model_in_namespace()
        missing = [
            req_model
            for req_model in req_models
            if not any(self._model_satisfies(model, req_model) for model in server_model_list)
        ]
        if missing:
            described = ", ".join(
                f"{m['ModelUri']} (version {m.get('ModelVersion') or m.get('Version')},"
                f" published {m.get('PublicationDate')} or newer)"
                for m in missing
            )
            _logger.warning("Models are missing: %s", described)
            raise NodeSetError(f"Server doesn't satisfy the required models: {described}. Import them first!")

    async def _check_if_namespace_meta_information_is_added(self) -> None:
        """
        check if the NamespaceMetadata objects in server namespaces exists otherwise add them
        to prevent errors when other nodesets depend on this namespace.
        The whole nodeset of the namespace was imported, so it is not a subset (OPC 10000-5 v1.05, 6.3.13).
        """
        descs = await self.session.nodes.namespaces.get_children_descriptions()
        ns_objs = [n.BrowseName.Name for n in descs]
        for uri, version, pub_date in self.parser.get_nodeset_namespaces():
            if uri not in ns_objs:
                idx = await self.session.register_namespace(uri)
                obj = await self.session.nodes.namespaces.add_object(
                    idx, uri, ua.ObjectIds.NamespaceMetadataType, False
                )
                ns_uri = await obj.get_child("NamespaceUri")
                await ns_uri.write_value(uri, ua.VariantType.String)
                ns_ver = await obj.get_child("NamespaceVersion")
                await ns_ver.write_value(version, ua.VariantType.String)
                ns_date = await obj.get_child("NamespacePublicationDate")
                await ns_date.write_value(pub_date)
                ns_subset = await obj.get_child("IsNamespaceSubset")
                await ns_subset.write_value(False)

    async def import_xml(
        self, xmlpath: str | Path | None = None, xmlstring: str | bytes | None = None
    ) -> list[ua.NodeId]:
        """
        import xml and return added nodes
        """
        if (xmlpath is None and xmlstring is None) or (xmlpath and xmlstring):
            raise ValueError("Expected either xmlpath or xmlstring, not both or neither.")
        _logger.info("Importing XML file %s", xmlpath)
        self.parser = XMLParser(keep_empty_body_values=True)
        self.failures = []
        self._added = []
        self._definitions = {}
        self._type_loads = []
        await self._check_required_models(xmlpath, xmlstring)
        await self.parser.parse(xmlpath, xmlstring)
        self.namespaces = await self._map_namespaces()
        _logger.info("namespace map: %s", self.namespaces)
        self._unmigrated_aliases = self.parser.get_aliases()
        self.aliases = self._map_aliases(self._unmigrated_aliases)
        self.refs = []
        dnodes = self.make_objects(self.parser.get_node_datas())
        dnodes = self._drop_design_tool_only_nodes(dnodes)
        self._browsenames = {nd.nodeid: nd.browsename for nd in dnodes}
        self._supertypes = {nd.nodeid: ref.target for nd in dnodes for ref in nd.refs if self._is_inverse_subtype(ref)}
        dnodes = await self._assign_parents(dnodes)
        nodes_parsed = self._sort_nodes(dnodes)
        nodes: list[ua.NodeId] = []
        for nodedata in nodes_parsed:
            try:
                node = await self._add_node_data(nodedata, no_namespace_migration=True)
            except Exception as e:
                error = self._as_node_set_error(nodedata, e)
                _logger.warning("failure adding node %s %s", nodedata, error)
                self.failures.append((nodedata.nodeid, error))
                if self.strict_mode:
                    raise error from e
                continue
            nodes.append(node)
            self._added.append(node)
        self.refs, remaining_refs = [], self.refs
        await self._add_references(remaining_refs)
        missing_nodes = await self._add_missing_reverse_references(nodes)
        if missing_nodes:
            _logger.warning("The following references exist, but the Nodes are missing: %s", missing_nodes)
        if self.refs:
            _logger.warning(
                "The following references could not be imported and are probably broken: %s",
                self.refs,
            )
            self.failures.extend(
                (ref.SourceNodeId, UaError(f"Reference to {ref.TargetNodeId} failed")) for ref in self.refs
            )
        await self._load_types()
        await self._check_if_namespace_meta_information_is_added()
        return nodes

    @staticmethod
    def _is_inverse_subtype(ref: RefStruct) -> bool:
        return ref.reftype == HAS_SUBTYPE and not ref.forward

    def _as_node_set_error(self, nodedata: NodeData, error: Exception) -> NodeSetError:
        if isinstance(error, NodeSetError):
            error.added = list(self._added)
            return error
        status = error.code if isinstance(error, ua.UaStatusCodeError) else None
        text = f"Could not add node {nodedata.browsename} ({nodedata.nodeid}): {error}"
        return NodeSetError(text, ua.StatusCode(status) if status is not None else None, list(self._added))

    async def _is_hierarchical(self, reftype: ua.NodeId) -> bool:
        if reftype in HIERARCHICAL_BASE:
            return True
        if reftype in self._hierarchical:
            return self._hierarchical[reftype]
        result = False
        current = reftype
        seen: set[ua.NodeId] = set()
        while current not in seen:
            seen.add(current)
            if current in HIERARCHICAL_BASE:
                result = True
                break
            if current in self._supertypes:
                current = self._supertypes[current]
                continue
            try:
                refs = await self.session.get_node(current).get_references(
                    ua.ObjectIds.HasSubtype, ua.BrowseDirection.Inverse
                )
            except UaError:
                break
            if not refs:
                break
            current = refs[0].NodeId
        self._hierarchical[reftype] = result
        return result

    async def _assign_parents(self, dnodes: list[NodeData]) -> list[NodeData]:
        """
        OPC 10000-4 v1.05, 5.8.2: a node is added below a parent with a hierarchical reference. The parent is the node's
        ParentNodeId, else the source of a hierarchical reference to it, else the DataType that has it as an encoding.
        """
        forward_index: dict[ua.NodeId, list[tuple[ua.NodeId, ua.NodeId]]] = {}
        for nd in dnodes:
            for ref in nd.refs:
                if ref.forward and ref.reftype != HAS_TYPE_DEFINITION:
                    forward_index.setdefault(ref.target, []).append((nd.nodeid, ref.reftype))
        kept = []
        for nd in dnodes:
            nd.parent, nd.parentlink = await self._find_parent(nd, forward_index)
            if nd.parent is None:
                refs = ", ".join(f"{r.reftype} {'->' if r.forward else '<-'} {r.target}" for r in nd.refs)
                error = NodeSetError(
                    f"Node {nd.browsename} ({nd.nodeid}) has no hierarchical parent, so it cannot be added"
                    f" (OPC 10000-4 v1.05, 5.8.2). Its references: {refs or 'none'}"
                )
                self.failures.append((nd.nodeid, error))
                if self.strict_mode and nd.typedef != DATA_TYPE_ENCODING_TYPE:
                    raise error
                _logger.warning("%s", error)
                continue
            kept.append(nd)
        return kept

    async def _find_parent(
        self, nd: NodeData, forward_index: dict[ua.NodeId, list[tuple[ua.NodeId, ua.NodeId]]]
    ) -> tuple[ua.NodeId | None, ua.NodeId | None]:
        inverse = [r for r in nd.refs if not r.forward and r.reftype != HAS_TYPE_DEFINITION]
        incoming = forward_index.get(nd.nodeid, [])
        if nd.parent_attr:
            parent = nd.parent_attr
            for ref in inverse:
                if ref.target == parent and await self._is_hierarchical(ref.reftype):
                    return parent, ref.reftype
            for source, reftype in incoming:
                if source == parent and await self._is_hierarchical(reftype):
                    return parent, reftype
            return parent, HAS_COMPONENT
        for ref in inverse:
            if ref.reftype == HAS_ENCODING:
                return ref.target, HAS_ENCODING
        for source, reftype in incoming:
            if reftype == HAS_ENCODING:
                return source, HAS_ENCODING
        for ref in inverse:
            if await self._is_hierarchical(ref.reftype):
                return ref.target, ref.reftype
        for source, reftype in incoming:
            if await self._is_hierarchical(reftype):
                return source, reftype
        return None, None

    async def _add_missing_reverse_references(self, new_nodes: list[ua.NodeId]) -> set[ua.NodeId]:
        __unidirectional_types = {
            ua.ObjectIds.GuardVariableType,
            ua.ObjectIds.HasGuard,
            ua.ObjectIds.TransitionVariableType,
            ua.ObjectIds.StateMachineType,
            ua.ObjectIds.StateVariableType,
            ua.ObjectIds.TwoStateVariableType,
            ua.ObjectIds.StateType,
            ua.ObjectIds.TransitionType,
            ua.ObjectIds.FiniteTransitionVariableType,
            ua.ObjectIds.HasInterface,
        }
        dangling_refs_to_missing_nodes = set(new_nodes)

        node_reference_map: dict[tuple[ua.NodeId, ua.NodeId, ua.NodeId], ua.ReferenceDescription] = {}

        for new_node_id in new_nodes:
            node = self.session.get_node(new_node_id)
            try:
                node_ref_list: list[ua.ReferenceDescription] = await node.get_references()
            except (ua.uaerrors.BadNodeIdUnknown, ua.uaerrors.BadNodeIdInvalid):
                continue

            for ref in node_ref_list:
                dangling_refs_to_missing_nodes.discard(new_node_id)
                dangling_refs_to_missing_nodes.discard(ref.NodeId)

                if (
                    ref.ReferenceTypeId.NamespaceIndex != 0
                    or ref.ReferenceTypeId.Identifier not in __unidirectional_types
                ):
                    node_reference_map[(new_node_id, ref.NodeId, ref.ReferenceTypeId)] = ref

        for node in dangling_refs_to_missing_nodes:
            _logger.warning("Node %s has no references, so it does not exist in Server!", node)

        reference_fixes = []

        for ref_spec, ref in node_reference_map.items():
            source_node_id, target_node_id, ref_type = ref_spec
            reverse_ref_spec = (target_node_id, source_node_id, ref_type)
            if reverse_ref_spec not in node_reference_map:
                _logger.debug(
                    "Adding missing reference: %s <-> %s (%s)", target_node_id, source_node_id, ref.ReferenceTypeId
                )

                new_ref = ua.AddReferencesItem(
                    SourceNodeId=target_node_id,
                    TargetNodeId=source_node_id,
                    ReferenceTypeId=ref_type,
                    IsForward=(not ref.IsForward),
                )
                reference_fixes.append(new_ref)
        await self._add_references(reference_fixes)

        return dangling_refs_to_missing_nodes

    @staticmethod
    def _drop_design_tool_only_nodes(dnodes: list[NodeData]) -> list[NodeData]:
        skipped = {nd.nodeid for nd in dnodes if nd.design_tool_only}
        if not skipped:
            return dnodes
        grown = True
        while grown:
            grown = False
            for nd in dnodes:
                if nd.nodeid not in skipped and nd.parent in skipped:
                    skipped.add(nd.nodeid)
                    grown = True
        kept = [nd for nd in dnodes if nd.nodeid not in skipped]
        for nd in kept:
            nd.refs = [ref for ref in nd.refs if ref.target not in skipped]
        return kept

    async def _add_node_data(self, nodedata: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        if nodedata.nodetype == "UAObject":
            node = await self.add_object(nodedata, no_namespace_migration)
        elif nodedata.nodetype == "UAObjectType":
            node = await self.add_object_type(nodedata, no_namespace_migration)
        elif nodedata.nodetype == "UAVariable":
            node = await self.add_variable(nodedata, no_namespace_migration)
        elif nodedata.nodetype == "UAVariableType":
            node = await self.add_variable_type(nodedata, no_namespace_migration)
        elif nodedata.nodetype == "UAReferenceType":
            node = await self.add_reference_type(nodedata, no_namespace_migration)
        elif nodedata.nodetype == "UADataType":
            node = await self.add_datatype(nodedata, no_namespace_migration)
        elif nodedata.nodetype == "UAMethod":
            node = await self.add_method(nodedata, no_namespace_migration)
        elif nodedata.nodetype == "UAView":
            node = await self.add_view(nodedata, no_namespace_migration)
        else:
            raise ValueError(f"Not implemented node type: {nodedata.nodetype} ")
        return node

    def _get_server(self) -> Any:
        if hasattr(self.session, "iserver"):
            return self.session.iserver.isession
        return self.session.uaclient

    async def _add_references(self, refs: list[ua.AddReferencesItem]) -> None:
        if not refs:
            return
        res = await self._get_server().add_references(refs)

        for sc, ref in zip(res, refs):
            if not sc.is_good() and sc.value != ua.StatusCodes.BadDuplicateReferenceNotAllowed:
                self.refs.append(ref)

    def make_objects(self, node_data: list[NodeData]) -> list[NodeData]:
        """Replace the NodeIds and BrowseNames of the parsed nodes by objects in the namespaces of the server."""
        new_nodes = []
        for node_datum in node_data:
            node_datum.nodeid = self._to_migrated_nodeid(node_datum.nodeid)
            node_datum.browsename = self._migrate_ns(ua.QualifiedName.from_string(node_datum.browsename))
            node_datum.parent = None
            node_datum.parentlink = None
            if node_datum.parent_attr:
                node_datum.parent_attr = self._to_migrated_nodeid(node_datum.parent_attr)
            if node_datum.typedef:
                node_datum.typedef = self._to_migrated_nodeid(node_datum.typedef)
            if node_datum.datatype:
                node_datum.datatype = self._to_migrated_nodeid(node_datum.datatype)
            new_nodes.append(node_datum)
            for ref in node_datum.refs:
                ref.reftype = self._to_migrated_nodeid(ref.reftype)
                ref.target = self._to_migrated_nodeid(ref.target)
            for field in node_datum.definitions:
                if field.datatype:
                    field.datatype = self._to_migrated_nodeid(field.datatype)
        return new_nodes

    def _migrate_ns(self, obj: ua.NodeId | ua.QualifiedName) -> ua.NodeId | ua.QualifiedName:
        """
        Translate the namespace index of a NodeId or BrowseName in the file to the index of the same namespace URI
        in the server. Index 1 without a URI in the file stays 1, the first namespace of the server.
        """
        if obj.NamespaceIndex > 1 and obj.NamespaceIndex not in self.namespaces:
            raise UaError(f"Namespace index '{obj.NamespaceIndex}' referenced by '{obj}' is not defined in xml")
        if isinstance(obj, ua.ExpandedNodeId):
            if obj.NamespaceIndex in self.namespaces:
                obj = dataclasses.replace(obj, NamespaceIndex=self.namespaces[obj.NamespaceIndex])
        elif isinstance(obj, ua.NodeId):
            if obj.NamespaceIndex in self.namespaces:
                obj = ua.NodeId(
                    Identifier=obj.Identifier,
                    NamespaceIndex=self.namespaces[obj.NamespaceIndex],
                    NodeIdType=obj.NodeIdType,
                )
        if isinstance(obj, ua.QualifiedName):
            if obj.NamespaceIndex in self.namespaces:
                obj = ua.QualifiedName(Name=obj.Name, NamespaceIndex=self.namespaces[obj.NamespaceIndex])
        return obj

    def _get_add_node_item(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.AddNodesItem:
        node = ua.AddNodesItem()
        node.NodeClass = getattr(ua.NodeClass, (obj.nodetype or "")[2:])
        if no_namespace_migration:
            node.RequestedNewNodeId = obj.nodeid
            node.BrowseName = obj.browsename
            if obj.parent and obj.parentlink:
                node.ParentNodeId = obj.parent
                node.ReferenceTypeId = obj.parentlink
            if obj.typedef:
                node.TypeDefinition = obj.typedef
        else:
            node.RequestedNewNodeId = self._migrate_ns(obj.nodeid)
            node.BrowseName = self._migrate_ns(obj.browsename)
            if obj.parent and obj.parentlink:
                node.ParentNodeId = self._migrate_ns(obj.parent)
                node.ReferenceTypeId = self._migrate_ns(obj.parentlink)
            if obj.typedef:
                node.TypeDefinition = self._migrate_ns(obj.typedef)
        _logger.info(
            "Importing xml node (%s, %s) as (%s %s)",
            obj.browsename,
            obj.nodeid,
            node.BrowseName,
            node.RequestedNewNodeId,
        )
        return node

    def _to_migrated_nodeid(self, nodeid: ua.NodeId | str | None) -> ua.NodeId:
        return cast(ua.NodeId, self._migrate_ns(self._to_nodeid(nodeid)))

    def _to_nodeid(self, nodeid: ua.NodeId | str | None) -> ua.NodeId:
        if isinstance(nodeid, ua.NodeId):
            return nodeid
        if not nodeid:
            return BASE_DATA_TYPE
        nodeid = nodeid.strip()
        alias = self._unmigrated_aliases.get(nodeid)
        if alias is not None:
            return ua.NodeId.from_string(alias)
        if "=" in nodeid:
            return ua.NodeId.from_string(nodeid)
        if hasattr(ua.ObjectIds, nodeid):
            return ua.NodeId(getattr(ua.ObjectIds, nodeid))
        raise UaError(f"Unknown alias or symbolic name '{nodeid}'")

    async def _send_add(self, obj: NodeData, node: ua.AddNodesItem, attrs: Any) -> ua.NodeId:
        node.NodeAttributes = attrs
        res = await self._get_server().add_nodes([node])
        if not res[0].StatusCode.is_good():
            raise NodeSetError(
                f"AddNodes of {obj.browsename} ({obj.nodeid}) was answered with {res[0].StatusCode.name}",
                res[0].StatusCode,
                list(self._added),
            )
        await self._add_refs(obj)
        return res[0].AddedNodeId

    @staticmethod
    def _apply_common(obj: NodeData, attrs: Any) -> None:
        if obj.desc:
            attrs.Description = ua.LocalizedText(obj.desc)
        attrs.DisplayName = ua.LocalizedText(obj.displayname)
        if obj.writemask is not None:
            attrs.WriteMask = obj.writemask

    async def add_object(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.ObjectAttributes()
        self._apply_common(obj, attrs)
        attrs.EventNotifier = obj.eventnotifier
        return await self._send_add(obj, node, attrs)

    async def add_view(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.ViewAttributes()
        self._apply_common(obj, attrs)
        attrs.EventNotifier = obj.eventnotifier
        attrs.ContainsNoLoops = bool(obj.containsnoloops)
        return await self._send_add(obj, node, attrs)

    async def add_object_type(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.ObjectTypeAttributes()
        self._apply_common(obj, attrs)
        attrs.IsAbstract = obj.abstract
        return await self._send_add(obj, node, attrs)

    async def add_variable(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.VariableAttributes()
        self._apply_common(obj, attrs)
        attrs.DataType = obj.datatype if obj.datatype is not None else BASE_DATA_TYPE
        if obj.value is not None:
            attrs.Value = await self._add_variable_value(obj)
        attrs.ValueRank = obj.rank
        if obj.accesslevel is not None:
            attrs.AccessLevel = obj.accesslevel
            attrs.UserAccessLevel = obj.accesslevel
        if obj.useraccesslevel is not None:
            attrs.UserAccessLevel = obj.useraccesslevel
        if obj.minsample is not None:
            attrs.MinimumSamplingInterval = obj.minsample
        attrs.Historizing = obj.historizing
        if obj.dimensions:
            attrs.ArrayDimensions = obj.dimensions
        return await self._send_add(obj, node, attrs)

    def _get_ext_class(self, name: str) -> Any:
        types = self.session.types
        if name in self.aliases:
            nodeid = self.aliases[name]
            class_type = types.find(nodeid) or types.class_for_encoding(nodeid)
            if class_type:
                return class_type
        try:
            return types.by_name(name)
        except KeyError:
            pass
        if hasattr(ua, name):
            return getattr(ua, name)
        if name in self.aliases:
            raise UaError(f"No extension class is registered for {name} ({self.aliases[name]})")
        raise UaError(f"No alias or class found for the extension object {name}")

    async def _make_ext_obj(self, obj: ExtObj) -> Any:
        typeid = self._to_migrated_nodeid(obj.typeid) if obj.typeid else None
        if obj.objname == "ByteString":
            await self._load_types(final=False)
            types = self.session.types
            extclass = types.class_for_encoding(typeid) if typeid is not None else None
            if extclass is None:
                return ua.ExtensionObject(TypeId=typeid or ua.NodeId(), Body=obj.body)
            return struct_from_binary(extclass, Buffer(obj.body, types=types))
        objname = obj.objname or ""
        try:
            extclass = self._get_ext_class(objname)
        except Exception:
            if not self.auto_load_definitions:
                raise
            await self.session.load_data_type_definitions()
            extclass = self._get_ext_class(objname)
        if issubclass(extclass, ua.UaUnion):
            return self._make_union(extclass, obj.body)
        return extclass(**self._body_arguments(extclass, obj.body))

    def _body_arguments(self, extclass: type, body: list[tuple[str, Any]]) -> dict[str, Any]:
        resolved_types = get_safe_type_hints(extclass, {"ua": ua})
        args: dict[str, Any] = {}
        for name, val in body:
            if not isinstance(val, list):
                raise UaError(f"The body of an extension object must be a list of fields, got {name}: {val!r}")
            for attname, v in val:
                if attname in ("EncodingMask", "SwitchField") or issubclass(extclass, ua.UaUnion):
                    continue
                if attname not in resolved_types:
                    raise UaError(f"Attribute '{attname}' defined in xml is not found in object '{extclass}'")
                self._set_attr(resolved_types[attname], args, attname, v)
        return args

    def _make_union(self, extclass: Any, body: list[tuple[str, Any]]) -> Any:
        names = [key for key, value in extclass.__dict__.items() if isinstance(value, property)]
        result = extclass()
        for _, val in body:
            for attname, v in val:
                if attname == "SwitchField":
                    continue
                index = names.index(attname)
                field_type = extclass._union_types[index]
                converted = parse_scalar(v, field_type) if isinstance(v, str) and isinstance(field_type, type) else v
                setattr(result, attname, converted)
        return result

    def _set_attr(self, atttype: Any, fargs: dict[str, Any], attname: str, val: Any) -> None:
        if type_is_optional(atttype):
            atttype = type_from_optional(atttype)
        elif type_is_union(atttype):
            atttype = types_from_union(atttype)[0]
        if isinstance(val, str):
            if type_is_list(atttype):
                fargs[attname] = []
            elif dataclasses.is_dataclass(atttype) and not val:
                fargs[attname] = atttype()  # type: ignore[operator]
            else:
                fargs[attname] = parse_scalar(val, atttype)
            return
        if type_is_list(atttype):
            atttype = type_from_list(atttype)
            my_list = []
            for vtype, v2 in val:
                if isinstance(v2, str):
                    my_list.append(parse_scalar(v2, vtype))
                else:
                    my_list.append(v2)
            fargs[attname] = my_list

        elif issubclass(atttype, ua.NodeId):
            for attname2, v2 in val:
                if attname2 == "Identifier":
                    if hasattr(ua.ObjectIds, v2):
                        obj2 = ua.NodeId(getattr(ua.ObjectIds, v2))
                    else:
                        obj2 = ua.NodeId.from_string(v2)
                    fargs[attname] = self._migrate_ns(obj2)
                    break
        elif isinstance(atttype, type) and dataclasses.is_dataclass(atttype):
            subargs: dict[str, Any] = {}
            resolved_sub_type = get_safe_type_hints(atttype, {"ua": ua})
            for attname2, v2 in val:
                if attname2 != "EncodingMask":
                    self._set_attr(resolved_sub_type[attname2], subargs, attname2, v2)
            subargs.pop("Encoding", None)
            if atttype is ua.LocalizedText:
                subargs = {key: value or None for key, value in subargs.items()}
            fargs[attname] = atttype(**subargs)  # type: ignore[operator]
        else:
            raise RuntimeError(f"Could not handle type {atttype} of type {type(atttype)}")

    def _migrate_value_ns(self, value: Any) -> Any:
        if isinstance(value, str):
            value = ua.NodeId.from_string(value)
        if value.NamespaceIndex > 1 and value.NamespaceIndex not in self.namespaces:
            return value
        return self._migrate_ns(value)

    _nodeid_value = _migrate_value_ns

    async def _add_variable_value(self, obj: NodeData) -> ua.Variant:
        """
        Returns the value for a Variable based on the objects value type.
        """
        _logger.debug("Setting value with type %s and value %s", obj.valuetype, obj.value)
        if obj.valuetype is None:
            raise NodeSetError(f"The value of {obj.browsename} ({obj.nodeid}) has no type")
        if obj.valuetype == "Matrix":
            dimensions, element_type, elements = obj.value
            return ua.Variant(elements, getattr(ua.VariantType, element_type), Dimensions=dimensions)
        if obj.valuetype == "ListOfExtensionObject":
            values = []
            for ext in obj.value:
                extobj = await self._make_ext_obj(ext)
                values.append(extobj)
            return ua.Variant(values, ua.VariantType.ExtensionObject)
        if obj.valuetype == "ListOfGuid":
            return ua.Variant([uuid.UUID(guid) for guid in obj.value], getattr(ua.VariantType, obj.valuetype[6:]))
        if obj.valuetype == "ListOfNodeId":
            return ua.Variant([self._nodeid_value(v) for v in obj.value], ua.VariantType.NodeId)
        if obj.valuetype in ("ListOfExpandedNodeId", "ListOfQualifiedName"):
            return ua.Variant(
                [self._migrate_value_ns(v) for v in obj.value], getattr(ua.VariantType, obj.valuetype[6:])
            )
        if obj.valuetype is not None and obj.valuetype.startswith("ListOf"):
            vtype = obj.valuetype[6:]
            if hasattr(ua.ua_binary.Primitives, vtype):
                return ua.Variant(obj.value, getattr(ua.VariantType, vtype))
            if vtype == "LocalizedText":
                return ua.Variant(
                    [ua.LocalizedText(Text=item["Text"] or None, Locale=item["Locale"] or None) for item in obj.value]
                )
            if vtype in ["XmlElement", "StatusCode"]:
                return ua.Variant(obj.value)
            return ua.Variant([getattr(ua, vtype)(v) for v in obj.value])
        if obj.valuetype == "ExtensionObject":
            extobj = await self._make_ext_obj(obj.value)
            return ua.Variant(extobj, getattr(ua.VariantType, obj.valuetype))
        if obj.valuetype == "Guid":
            return ua.Variant(uuid.UUID(obj.value), getattr(ua.VariantType, obj.valuetype))
        if obj.valuetype == "LocalizedText":
            myargs = {key: value or None for key, value in obj.value if key in ("Locale", "Text")}
            ltext = ua.LocalizedText(**myargs)
            return ua.Variant(ltext, ua.VariantType.LocalizedText)
        if obj.valuetype == "NodeId":
            return ua.Variant(self._nodeid_value(obj.value), ua.VariantType.NodeId)
        if obj.valuetype in ("ExpandedNodeId", "QualifiedName"):
            return ua.Variant(self._migrate_value_ns(obj.value), getattr(ua.VariantType, obj.valuetype))
        return ua.Variant(obj.value, getattr(ua.VariantType, obj.valuetype))

    async def add_variable_type(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.VariableTypeAttributes()
        self._apply_common(obj, attrs)
        attrs.DataType = obj.datatype if obj.datatype is not None else BASE_DATA_TYPE
        if obj.value is not None:
            attrs.Value = await self._add_variable_value(obj)
        attrs.ValueRank = obj.rank
        attrs.IsAbstract = obj.abstract
        if obj.dimensions:
            attrs.ArrayDimensions = obj.dimensions
        return await self._send_add(obj, node, attrs)

    async def add_method(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.MethodAttributes()
        self._apply_common(obj, attrs)
        attrs.Executable = True if obj.executable is None else obj.executable
        attrs.UserExecutable = attrs.Executable if obj.userexecutable is None else obj.userexecutable
        return await self._send_add(obj, node, attrs)

    async def add_reference_type(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.ReferenceTypeAttributes()
        self._apply_common(obj, attrs)
        if obj.inversename:
            attrs.InverseName = ua.LocalizedText(obj.inversename)
        attrs.IsAbstract = obj.abstract
        attrs.Symmetric = obj.symmetric
        return await self._send_add(obj, node, attrs)

    async def _definition_kind(self, obj: NodeData) -> str | None:
        if not obj.has_definition:
            return None
        if obj.option_set:
            return "option_set"
        if obj.parent == self.session.nodes.enum_data_type.nodeid:
            return "enum"
        if obj.parent in (self.session.nodes.base_structure_type.nodeid, self.session.nodes.base_union_type.nodeid):
            return "struct"
        path = await self.session.get_node(obj.parent).get_path()
        if self.session.nodes.option_set_type in path:
            return "option_set"
        if self.session.nodes.enum_data_type in path:
            return "enum"
        if self.session.nodes.base_structure_type in path:
            return "struct"
        _logger.warning("%s has a definition and path %s but it is neither a structure nor an enumeration", obj, path)
        return None

    async def add_datatype(self, obj: NodeData, no_namespace_migration: bool = False) -> ua.NodeId:
        node = self._get_add_node_item(obj, no_namespace_migration)
        attrs = ua.DataTypeAttributes()
        self._apply_common(obj, attrs)
        attrs.IsAbstract = obj.abstract
        kind = await self._definition_kind(obj)
        file_write_mask = obj.writemask or 0
        if kind is not None:
            attrs.WriteMask = WRITE_MASK_DEFINITION | WRITE_MASK_OF_WRITE_MASKS
            attrs.UserWriteMask = attrs.WriteMask
        added = await self._send_add(obj, node, attrs)
        name = clean_name(obj.browsename.Name)
        if kind is not None:
            definition: ua.StructureDefinition | ua.EnumDefinition = (
                await self._structure_definition(obj) if kind == "struct" else self._enum_definition(obj)
            )
            data_type_node = self.session.get_node(added)
            await data_type_node.write_data_type_definition(definition)
            await data_type_node.write_attribute(
                ua.AttributeIds.UserWriteMask,
                ua.DataValue(ua.Variant(1 << ua.WriteMask.WriteMask, ua.VariantType.UInt32)),
            )
            await data_type_node.write_attribute(
                ua.AttributeIds.WriteMask, ua.DataValue(ua.Variant(file_write_mask, ua.VariantType.UInt32))
            )
            self._definitions[added] = definition
            self._type_loads.append((kind, added, name, definition, option_set_base_name(obj.parent)))
        elif obj.parent != STRUCTURE and obj.parent != UNION and obj.parent is not None:
            self._type_loads.append(("alias", added, name, obj.parent, "UInt32"))
        return added

    async def _load_types(self, final: bool = True) -> None:
        if not self.auto_load_definitions:
            return
        types = self.session.types
        for attempt in range(3 if final else 1):
            failed: list[tuple[str, ua.NodeId, str, Any, str]] = []
            for entry in self._type_loads:
                kind, nodeid, name, payload, option_set_base = entry
                try:
                    if kind == "struct":
                        await load_custom_struct_xml_import(types, nodeid, name, payload)
                    elif kind in ("enum", "option_set"):
                        await load_enum_xml_import(types, nodeid, name, payload, kind == "option_set", option_set_base)
                    else:
                        await load_basetype_alias_xml_import(self.session, name, nodeid, payload)
                except Exception:
                    if final and attempt == 2:
                        _logger.exception("Could not create a class for the DataType %s (%s)", name, nodeid)
                    failed.append(entry)
            self._type_loads = failed
            if not failed:
                break

    async def _add_refs(self, obj: NodeData) -> None:
        refs = []
        for data in obj.refs:
            if not data.forward and data.target == obj.parent and data.reftype == obj.parentlink:
                continue
            ref = ua.AddReferencesItem()
            ref.IsForward = data.forward
            ref.ReferenceTypeId = data.reftype
            ref.SourceNodeId = obj.nodeid
            ref.TargetNodeId = data.target
            refs.append(ref)
        await self._add_references(refs)

    def _enum_definition(self, obj: NodeData) -> ua.EnumDefinition:
        edef = ua.EnumDefinition()
        for field in obj.definitions:
            f = ua.EnumField()
            f.Name = field.name
            f.DisplayName = ua.LocalizedText(Text=field.dname or field.name)
            f.Value = field.value
            f.Description = ua.LocalizedText(Text=field.desc)
            edef.Fields.append(f)
        return edef

    async def _supertype_fields(self, obj: NodeData) -> list[ua.StructureField]:
        if obj.parent in (STRUCTURE, UNION) or obj.parent is None:
            return []
        base = self._definitions.get(obj.parent)
        if base is None:
            try:
                base = await self.session.get_node(obj.parent).read_data_type_definition()
            except UaError:
                return []
        return list(base.Fields) if isinstance(base, ua.StructureDefinition) else []

    async def _structure_definition(self, obj: NodeData) -> ua.StructureDefinition:
        sdef = ua.StructureDefinition()
        sdef.BaseDataType = obj.parent
        sdef.DefaultEncodingId = ua.NodeId()
        if not obj.abstract:
            for ref in obj.refs:
                name = self._browsenames.get(ref.target)
                if (
                    ref.reftype == HAS_ENCODING
                    and ref.forward
                    and name is not None
                    and name.Name == "Default Binary"
                    and name.NamespaceIndex == 0
                ):
                    sdef.DefaultEncodingId = ref.target
                    break
        allows_subtypes = any(field.allow_subtypes for field in obj.definitions)
        optional = any(field.optional for field in obj.definitions)
        union = obj.struct_type == "IsUnion"
        if allows_subtypes and optional:
            raise NodeSetError(
                f"{obj.browsename}: a field cannot be both IsOptional and AllowSubTypes (OPC 10000-6 v1.05, F.12)"
            )
        if union and optional:
            raise NodeSetError(f"{obj.browsename}: the fields of a union cannot be optional (OPC 10000-6 v1.05, F.12)")
        own = []
        for field in obj.definitions:
            f = ua.StructureField()
            f.Name = field.name
            f.DataType = field.datatype
            f.ValueRank = field.valuerank
            f.IsOptional = field.allow_subtypes if allows_subtypes else field.optional
            f.MaxStringLength = field.max_str_len
            f.ArrayDimensions = (
                None  # type: ignore[assignment]
                if field.arraydim is None or not field.arraydim.strip()
                else [int(i) for i in field.arraydim.split(",")]
            )
            f.Description = ua.LocalizedText(Text=field.desc)
            own.append(f)
        names = {f.Name for f in own}
        sdef.Fields = [f for f in await self._supertype_fields(obj) if f.Name not in names] + own
        if union:
            sdef.StructureType = ua.StructureType.UnionWithSubtypedValues if allows_subtypes else ua.StructureType.Union
        elif allows_subtypes:
            sdef.StructureType = ua.StructureType.StructureWithSubtypedValues
        elif optional or obj.struct_type == "IsOptional":
            sdef.StructureType = ua.StructureType.StructureWithOptionalFields
        else:
            sdef.StructureType = ua.StructureType.Structure
        return sdef

    def _sort_nodes(self, ndatas: list[NodeData]) -> list[NodeData]:
        """
        Order the nodes so that every node comes after its parent, its DataType, the DataTypes of its fields and,
        for an instance, its TypeDefinition. A type node may name an instance of itself as TypeDefinition, as
        TwinCAT exports do, so for type nodes the TypeDefinition does not decide the order.
        """
        sorted_ndatas = []
        all_nodes = {data.nodeid: data for data in ndatas}
        sorted_nodes: dict[Any, NodeData] = {}
        type_node_kinds = {
            "UAObjectType",
            "UAVariableType",
            "UADataType",
            "UAReferenceType",
        }

        def field_types_ready(ndata: NodeData) -> bool:
            return all(
                field.datatype == ndata.nodeid or field.datatype not in all_nodes or field.datatype in sorted_nodes
                for field in ndata.definitions
            )

        order_by_fields = True
        last_len = 0
        while len(sorted_nodes) < len(ndatas):
            for nid, ndata in all_nodes.items():
                if nid in sorted_nodes:
                    continue
                if ndata.datatype is not None and ndata.datatype in all_nodes:
                    if ndata.datatype not in sorted_nodes:
                        continue
                if ndata.typedef is not None and ndata.typedef in all_nodes and ndata.nodetype not in type_node_kinds:
                    if ndata.typedef not in sorted_nodes:
                        continue
                if ndata.parentlink in all_nodes and ndata.parentlink not in sorted_nodes:
                    continue
                if order_by_fields and not field_types_ready(ndata):
                    continue
                if ndata.parent is None or ndata.parent not in all_nodes or ndata.parent in sorted_nodes:
                    sorted_ndatas.append(ndata)
                    sorted_nodes[nid] = ndata
            if last_len == len(sorted_nodes):
                if order_by_fields:
                    order_by_fields = False
                    continue
                stuck = ", ".join(str(nid) for nid in all_nodes if nid not in sorted_nodes)
                raise NodeSetError(
                    f"Ordering of nodes is not possible, they depend on each other through parents or types: {stuck}"
                )
            last_len = len(sorted_nodes)
        return sorted_ndatas

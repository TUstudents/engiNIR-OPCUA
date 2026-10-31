"""
from a list of nodes in the address space, build an XML file
format is the one from opc-ua specification
"""

from __future__ import annotations

import asyncio
import base64
import functools
import logging
import xml.etree.ElementTree as Et
from collections.abc import Iterable
from dataclasses import is_dataclass
from datetime import UTC
from enum import Enum
from pathlib import Path
from typing import Any, cast

import enginir_opcua
from enginir_opcua import ua
from enginir_opcua.ua.uaerrors import UaError, UaInvalidParameterError
from enginir_opcua.ua.uatypes import type_string_from_type

from .. import Node
from ..ua import object_ids as o_ids
from .ua_utils import get_base_data_type
from .utils import fields_with_resolved_types

UINTEGER_TYPES = frozenset(
    (ua.ObjectIds.Byte, ua.ObjectIds.UInt16, ua.ObjectIds.UInt32, ua.ObjectIds.UInt64, ua.ObjectIds.UInteger)
)


class XmlExporter:
    """
    Writes nodes of an address space as a NodeSet2 XML document (OPC 10000-6 v1.05, Annex F).

    Namespace indexes are renumbered to the order of the NamespaceUris table of the file.
    """

    def __init__(self, server: enginir_opcua.Server | enginir_opcua.Client, export_values: bool = False) -> None:
        """
        :param export_values: also write the values of variables; values of custom structures may not be exported
            completely.
        """
        self.logger = logging.getLogger(__name__)
        self.server: Any = server
        self.aliases: dict[ua.NodeId, str] = {}
        self._addr_idx_to_xml_idx: dict[int, int] = {}
        self._models_written = False

        node_write_attributes: dict[str, str] = {}
        node_write_attributes["xmlns:xsi"] = "http://www.w3.org/2001/XMLSchema-instance"
        node_write_attributes["xmlns:uax"] = "http://opcfoundation.org/UA/2008/02/Types.xsd"
        node_write_attributes["xmlns:xsd"] = "http://www.w3.org/2001/XMLSchema"
        node_write_attributes["xmlns"] = "http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"

        self.etree = Et.ElementTree(Et.Element("UANodeSet", node_write_attributes))
        self._export_values = export_values
        if self._export_values:
            self.logger.warning("Exporting values of variables is limited and can result in invalid xmls.")

    async def build_etree(
        self, node_list: Iterable[Node], add_all_namespaces: bool = False, model_uris: list[str] | None = None
    ) -> None:
        """
        Build the document from the nodes. The namespaces the nodes use are always exported.

        :param add_all_namespaces: export every namespace of the server, used or not.
        :param model_uris: the namespaces the document defines; they get a Model element that requires the others.
        """
        self.logger.info("Building XML etree")
        node_list = list(node_list)
        await self._add_namespaces(node_list, add_all_namespaces)
        for node in node_list:
            await self.node_to_etree(node)
        if model_uris:
            await self._add_model_els(model_uris)
        self._add_alias_els()

    async def build_etree_chunked(
        self, node_list: Iterable[Node], add_all_namespaces: bool = False, chunk_size: int = 500
    ) -> None:
        """Like ``build_etree`` without Model elements; ``chunk_size`` is accepted for compatibility and has no effect."""
        self.logger.info("Building XML etree chunked")
        node_list = list(node_list)
        await self._add_namespaces(node_list, add_all_namespaces)
        for node in node_list:
            await self.node_to_etree(node)
        self._add_alias_els()

    async def _add_namespaces(self, nodes: list[Node], add_all_namespaces: bool = False) -> None:
        if add_all_namespaces:
            ns_array = await self.server.get_namespace_array()
            self._addr_idx_to_xml_idx = {count: count for count in range(len(ns_array))}
            self._add_namespace_uri_els(ns_array[1:])
        else:
            ns_array = await self.server.get_namespace_array()
            idxs = await self._get_ns_idxs_of_nodes(nodes)

            self._addr_idx_to_xml_idx = self._make_idx_dict(idxs, ns_array)
            ns_to_export = [ns_array[i] for i in sorted(self._addr_idx_to_xml_idx) if i != 0]
            self._add_namespace_uri_els(ns_to_export)

    def _make_idx_dict(self, idxs: list[int], ns_array: list[str]) -> dict[int, int]:
        idxs.sort()
        addr_idx_to_xml_idx = {0: 0}
        for xml_idx, addr_idx in enumerate(idxs):
            if addr_idx >= len(ns_array):
                raise UaError(f"Namespace index '{addr_idx}' is not present in the namespace array")
            addr_idx_to_xml_idx[addr_idx] = xml_idx + 1
        return addr_idx_to_xml_idx

    async def _get_ns_idxs_of_nodes(self, nodes: list[Node]) -> list[int]:
        idxs: list[int] = []
        for node in nodes:
            node_idxs = [node.nodeid.NamespaceIndex]
            try:
                node_idxs.append((await node.read_browse_name()).NamespaceIndex)
            except UaError:
                self.logger.exception("Error retrieving browse name of node %s", node)
                raise

            for ref in await node.get_references():
                node_idxs.append(ref.NodeId.NamespaceIndex)
                node_idxs.append(ref.ReferenceTypeId.NamespaceIndex)
            if node.nodeid.NamespaceIndex != 0:
                try:
                    node_idxs.append((await node.read_data_type()).NamespaceIndex)
                except ua.UaStatusCodeError:
                    pass
            node_idxs.extend(await self._indices_in_attributes(node))
            for i in set(node_idxs):
                if i != 0 and i not in idxs:
                    idxs.append(i)
        return idxs

    async def _indices_in_attributes(self, node: Node) -> list[int]:
        found: list[int] = []
        try:
            definition = await node.read_data_type_definition()
        except ua.UaError:
            definition = None
        if isinstance(definition, ua.StructureDefinition):
            found.extend(field.DataType.NamespaceIndex for field in definition.Fields)
            found.append(definition.BaseDataType.NamespaceIndex)
        if self._export_values:
            try:
                value = await node.read_data_value(raise_on_bad_status=False)
            except ua.UaError:
                return found
            if value.Value is not None:
                self._collect_value_indices(value.Value.Value, found, 0)
        return found

    def _collect_value_indices(self, value: Any, found: list[int], depth: int) -> None:
        if depth > 20 or value is None:
            return
        if isinstance(value, ua.NodeId | ua.QualifiedName):
            found.append(value.NamespaceIndex)
        elif isinstance(value, list | tuple):
            for item in value:
                self._collect_value_indices(item, found, depth + 1)
        elif is_dataclass(value) and not isinstance(value, type):
            for name in getattr(value, "__dataclass_fields__", {}):
                self._collect_value_indices(getattr(value, name, None), found, depth + 1)

    async def write_xml(self, xmlpath: str | Path, pretty: bool = True) -> None:
        """
        Write the document to a file, UTF-8 with an XML declaration.

        :param pretty: indent the elements, two spaces per level.
        """
        self.logger.info("Exporting XML file to %s", xmlpath)
        if pretty:
            indent(self._root())
        func = functools.partial(self.etree.write, xmlpath, encoding="utf-8", xml_declaration=True)
        await asyncio.get_running_loop().run_in_executor(None, func)

    def dump_etree(self) -> None:
        """Print the document to standard output, for debugging."""
        self.logger.info("Dumping XML etree to console")
        Et.dump(self.etree)

    async def node_to_etree(self, node: Node) -> None:
        """Add the element of one node, with its attributes and references, to the document."""
        node_class = await node.read_node_class()

        if node_class is ua.NodeClass.Object:
            await self.add_etree_object(node)
        elif node_class is ua.NodeClass.ObjectType:
            await self.add_etree_object_type(node)
        elif node_class is ua.NodeClass.Variable:
            await self.add_etree_variable(node)
        elif node_class is ua.NodeClass.VariableType:
            await self.add_etree_variable_type(node)
        elif node_class is ua.NodeClass.ReferenceType:
            await self.add_etree_reference_type(node)
        elif node_class is ua.NodeClass.DataType:
            await self.add_etree_datatype(node)
        elif node_class is ua.NodeClass.Method:
            await self.add_etree_method(node)
        elif node_class is ua.NodeClass.View:
            await self.add_etree_view(node)
        else:
            raise UaInvalidParameterError(f"Exporting node class {node_class} is not implemented")

    def _add_sub_el(self, el: Et.Element, name: str, text: str | None) -> Et.Element:
        child_el = Et.SubElement(el, name)
        child_el.text = text
        return child_el

    def _node_to_string(self, nodeid: ua.NodeId | Node) -> str:
        if not isinstance(nodeid, ua.NodeId):
            nodeid = nodeid.nodeid

        if nodeid.NamespaceIndex in self._addr_idx_to_xml_idx:
            nodeid = ua.NodeId(nodeid.Identifier, NamespaceIndex=self._addr_idx_to_xml_idx[nodeid.NamespaceIndex])
        return nodeid.to_string()

    def _bname_to_string(self, bname: ua.QualifiedName) -> str:
        if bname.NamespaceIndex in self._addr_idx_to_xml_idx:
            bname = ua.QualifiedName(Name=bname.Name, NamespaceIndex=self._addr_idx_to_xml_idx[bname.NamespaceIndex])
        return bname.to_string()

    async def _add_node_common(self, nodetype: str, node: Node) -> Et.Element:
        browsename = await node.read_browse_name()
        nodeid = node.nodeid
        parent = await node.get_parent()
        displayname = (await node.read_display_name()).Text
        desc: str | None
        try:
            description = await node.read_description()
            desc = description.Text if description else None
        except ua.uaerrors.BadAttributeIdInvalid:
            desc = None
        node_el = Et.SubElement(self._root(), nodetype)
        node_el.attrib["NodeId"] = self._node_to_string(nodeid)
        node_el.attrib["BrowseName"] = self._bname_to_string(browsename)
        if parent is not None:
            node_class = await node.read_node_class()
            if node_class in (ua.NodeClass.Object, ua.NodeClass.Variable, ua.NodeClass.Method):
                node_el.attrib["ParentNodeId"] = self._node_to_string(parent)
        self._add_sub_el(node_el, "DisplayName", displayname)
        if desc not in (None, ""):
            self._add_sub_el(node_el, "Description", desc)
        await self._add_ref_els(node_el, node)
        write_mask = await self._read_optional(node, ua.AttributeIds.WriteMask)
        user_write_mask = await self._read_optional(node, ua.AttributeIds.UserWriteMask)
        if write_mask:
            node_el.attrib["WriteMask"] = str(int(write_mask))
        if user_write_mask is not None and user_write_mask != (write_mask or 0):
            node_el.attrib["UserWriteMask"] = str(int(user_write_mask))
        return node_el

    async def _read(self, node: Node, attribute: ua.AttributeIds) -> Any:
        value = await node.read_attribute(attribute)
        return None if value.Value is None else value.Value.Value

    async def _read_optional(self, node: Node, attribute: ua.AttributeIds) -> Any:
        value = await node.read_attribute(attribute, raise_on_bad_status=False)
        if value is None or value.Value is None:
            return None
        return value.Value.Value

    async def add_etree_object(self, node: Node) -> None:
        """Add a UAObject element."""
        obj_el = await self._add_node_common("UAObject", node)
        notifier = await self._read(node, ua.AttributeIds.EventNotifier)
        if notifier != 0:
            obj_el.attrib["EventNotifier"] = str(notifier)

    async def add_etree_view(self, node: Node) -> None:
        """Add a UAView element."""
        view_el = await self._add_node_common("UAView", node)
        notifier = await self._read_optional(node, ua.AttributeIds.EventNotifier)
        if notifier:
            view_el.attrib["EventNotifier"] = str(int(notifier))
        if await self._read_optional(node, ua.AttributeIds.ContainsNoLoops):
            view_el.attrib["ContainsNoLoops"] = "true"

    async def add_etree_object_type(self, node: Node) -> None:
        """Add a UAObjectType element."""
        obj_el = await self._add_node_common("UAObjectType", node)
        if await self._read(node, ua.AttributeIds.IsAbstract):
            obj_el.attrib["IsAbstract"] = "true"

    async def add_variable_common(self, node: Node, el: Et.Element, export_value: bool) -> None:
        """Write the DataType, ValueRank and ArrayDimensions of a variable or variable type, and its value if asked."""
        dtype = await node.read_data_type()
        if dtype.NamespaceIndex == 0 and isinstance(dtype.Identifier, int) and dtype.Identifier in o_ids.ObjectIdNames:
            dtype_name = o_ids.ObjectIdNames[dtype.Identifier]
            self.aliases[dtype] = dtype_name
        else:
            dtype_name = self._node_to_string(dtype)
        try:
            rank = await node.read_value_rank()
            if rank != -1:
                el.attrib["ValueRank"] = str(int(rank))
        except ua.uaerrors.BadAttributeIdInvalid:
            pass

        dimensions = await self._read_optional(node, ua.AttributeIds.ArrayDimensions)
        if dimensions:
            el.attrib["ArrayDimensions"] = ",".join([str(i) for i in dimensions])
        el.attrib["DataType"] = dtype_name
        if export_value:
            await self.value_to_etree(el, dtype_name, dtype, node)

    async def add_etree_variable(self, node: Node) -> None:
        """Add a UAVariable element."""
        var_el = await self._add_node_common("UAVariable", node)
        await self.add_variable_common(node, var_el, self._export_values)

        accesslevel = await self._read(node, ua.AttributeIds.AccessLevel)
        useraccesslevel = await self._read(node, ua.AttributeIds.UserAccessLevel)

        if accesslevel != ua.AccessLevel.CurrentRead.mask:
            var_el.attrib["AccessLevel"] = str(accesslevel)
        if useraccesslevel != accesslevel:
            var_el.attrib["UserAccessLevel"] = str(useraccesslevel)

        sampling = await self._read_optional(node, ua.AttributeIds.MinimumSamplingInterval)
        if sampling:
            var_el.attrib["MinimumSamplingInterval"] = str(sampling)
        if await self._read(node, ua.AttributeIds.Historizing):
            var_el.attrib["Historizing"] = "true"

    async def add_etree_variable_type(self, node: Node) -> None:
        """Add a UAVariableType element, always with its value."""
        var_el = await self._add_node_common("UAVariableType", node)
        await self.add_variable_common(node, var_el, True)
        if await self._read(node, ua.AttributeIds.IsAbstract):
            var_el.attrib["IsAbstract"] = "true"

    async def add_etree_method(self, node: Node) -> None:
        """Add a UAMethod element."""
        obj_el = await self._add_node_common("UAMethod", node)
        if await self._read(node, ua.AttributeIds.Executable) is False:
            obj_el.attrib["Executable"] = "false"
        if await self._read(node, ua.AttributeIds.UserExecutable) is False:
            obj_el.attrib["UserExecutable"] = "false"

    async def add_etree_reference_type(self, obj: Node) -> None:
        """Add a UAReferenceType element."""
        obj_el = await self._add_node_common("UAReferenceType", obj)
        inverse_name = await self._read_optional(obj, ua.AttributeIds.InverseName)
        if inverse_name is not None and inverse_name.Text is not None:
            self._add_sub_el(obj_el, "InverseName", inverse_name.Text)
        if await self._read_optional(obj, ua.AttributeIds.Symmetric):
            obj_el.attrib["Symmetric"] = "true"
        if await self._read_optional(obj, ua.AttributeIds.IsAbstract):
            obj_el.attrib["IsAbstract"] = "true"

    async def add_etree_datatype(self, obj: Node) -> None:
        """Add a UADataType element with the Definition of a structure, enumeration or option set."""
        obj_el = await self._add_node_common("UADataType", obj)
        if await self._read_optional(obj, ua.AttributeIds.IsAbstract):
            obj_el.attrib["IsAbstract"] = "true"
        sdef = await self._read_optional(obj, ua.AttributeIds.DataTypeDefinition)
        if sdef:
            bname = await self._read(obj, ua.AttributeIds.BrowseName)
            sdef_el = Et.SubElement(obj_el, "Definition")
            sdef_el.attrib["Name"] = self._bname_to_string(bname)
            supers = await obj.get_references(ua.ObjectIds.HasSubtype, ua.BrowseDirection.Inverse)
            parent = supers[0].NodeId if supers else None
            if isinstance(sdef, ua.StructureDefinition):
                if sdef.StructureType in (ua.StructureType.Union, ua.StructureType.UnionWithSubtypedValues):
                    sdef_el.attrib["IsUnion"] = "true"
                inherited = await self._inherited_field_names(parent)
                self._structure_fields_to_etree(sdef_el, sdef, inherited)
            elif isinstance(sdef, ua.EnumDefinition):
                if parent is not None and parent.NamespaceIndex == 0 and parent.Identifier in UINTEGER_TYPES:
                    sdef_el.attrib["IsOptionSet"] = "true"
                self._enum_fields_to_etree(sdef_el, sdef)
            else:
                self.logger.warning("Unknown DataTypeSpecification element: %s", sdef)

    async def _inherited_field_names(self, parent: ua.NodeId | None) -> set[str]:
        if parent is None or parent.NamespaceIndex == 0:
            return set()
        try:
            definition = await self.server.get_node(parent).read_data_type_definition()
        except ua.UaError:
            return set()
        return {field.Name for field in definition.Fields} if isinstance(definition, ua.StructureDefinition) else set()

    def _structure_fields_to_etree(
        self, sdef_el: Et.Element, sdef: ua.StructureDefinition, inherited: set[str] | frozenset[str] = frozenset()
    ) -> None:
        subtyped = sdef.StructureType in (
            ua.StructureType.StructureWithSubtypedValues,
            ua.StructureType.UnionWithSubtypedValues,
        )
        for field in sdef.Fields:
            if field.Name in inherited:
                continue
            field_el = Et.SubElement(sdef_el, "Field")
            field_el.attrib["Name"] = field.Name
            field_el.attrib["DataType"] = self._node_to_string(field.DataType)
            if field.ValueRank != -1:
                field_el.attrib["ValueRank"] = str(int(field.ValueRank))
            if field.ArrayDimensions:
                field_el.attrib["ArrayDimensions"] = ",".join([str(i) for i in field.ArrayDimensions])
            if field.MaxStringLength:
                field_el.attrib["MaxStringLength"] = str(field.MaxStringLength)
            if field.IsOptional:
                field_el.attrib["AllowSubTypes" if subtyped else "IsOptional"] = "true"
            if field.Description and field.Description.Text not in (None, ""):
                self._add_sub_el(field_el, "Description", field.Description.Text)

    def _enum_fields_to_etree(self, sdef_el: Et.Element, sdef: ua.EnumDefinition) -> None:
        for field in sdef.Fields:
            field_el = Et.SubElement(sdef_el, "Field")
            field_el.attrib["Name"] = field.Name
            field_el.attrib["Value"] = str(field.Value)
            display = field.DisplayName.Text if field.DisplayName else None
            if display not in (None, "", field.Name):
                self._add_sub_el(field_el, "DisplayName", display)
            if field.Description and field.Description.Text not in (None, ""):
                self._add_sub_el(field_el, "Description", field.Description.Text)

    def _add_namespace_uri_els(self, uris: list[str]) -> None:
        nuris_el = Et.Element("NamespaceUris")
        for uri in uris:
            self._add_sub_el(nuris_el, "Uri", uri)
        self._root().insert(0, nuris_el)

    def _root(self) -> Et.Element:
        root = self.etree.getroot()
        assert root is not None
        return root

    async def _namespace_metadata(self) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        try:
            children = await self.server.nodes.namespaces.get_children()
        except ua.UaError:
            return found
        for child in children:
            try:
                uri = await (await child.get_child("NamespaceUri")).read_value()
                version = await (await child.get_child("NamespaceVersion")).read_value()
                published = await (await child.get_child("NamespacePublicationDate")).read_value()
            except ua.UaError:
                continue
            model_version = None
            try:
                model_version = await (await child.get_child("ModelVersion")).read_value()
            except ua.UaError:
                pass
            found[uri] = {"Version": version, "PublicationDate": published, "ModelVersion": model_version}
        return found

    @staticmethod
    def _model_attributes(uri: str, meta: dict[str, Any] | None) -> dict[str, str]:
        attributes = {"ModelUri": uri}
        if meta is None:
            return attributes
        if meta["Version"]:
            attributes["Version"] = meta["Version"]
        published = meta["PublicationDate"]
        if published is not None and published.year > 1601:
            attributes["PublicationDate"] = published.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        if meta["ModelVersion"]:
            attributes["ModelVersion"] = meta["ModelVersion"]
        return attributes

    async def _add_model_els(self, model_uris: list[str]) -> None:
        metadata = await self._namespace_metadata()
        ns_array = await self.server.get_namespace_array()
        used = [ns_array[i] for i in sorted(self._addr_idx_to_xml_idx) if i < len(ns_array)]
        models_el = Et.Element("Models")
        for uri in model_uris:
            model_el = Et.SubElement(models_el, "Model", self._model_attributes(uri, metadata.get(uri)))
            for other in used:
                if other != uri:
                    Et.SubElement(model_el, "RequiredModel", self._model_attributes(other, metadata.get(other)))
        self._root().insert(1, models_el)
        self._models_written = True

    def _add_alias_els(self) -> None:
        aliases_el = Et.Element("Aliases")
        for nodeid in sorted(self.aliases):
            name = self.aliases[nodeid]
            ref_el = Et.SubElement(aliases_el, "Alias", Alias=name)
            ref_el.text = self._node_to_string(nodeid)
        self._root().insert(2 if self._models_written else 1, aliases_el)

    async def _add_ref_els(self, parent_el: Et.Element, obj: Node) -> None:
        refs = await obj.get_references()
        refs_el = Et.SubElement(parent_el, "References")
        for ref in refs:
            if ref.ReferenceTypeId.NamespaceIndex == 0 and ref.ReferenceTypeId.Identifier in o_ids.ObjectIdNames:
                ref_name = o_ids.ObjectIdNames[ref.ReferenceTypeId.Identifier]
            else:
                ref_name = self._node_to_string(ref.ReferenceTypeId)
            ref_el = Et.SubElement(refs_el, "Reference")
            ref_el.attrib["ReferenceType"] = ref_name
            if not ref.IsForward:
                ref_el.attrib["IsForward"] = "false"
            ref_el.text = self._node_to_string(ref.NodeId)

            if ref.ReferenceTypeId.NamespaceIndex == 0 and ref.ReferenceTypeId.Identifier in o_ids.ObjectIdNames:
                self.aliases[ref.ReferenceTypeId] = ref_name

    async def member_to_etree(self, el: Et.Element, name: str, dtype: ua.NodeId, val: Any) -> None:
        """Write one field of a structure value as an element of ``el``."""
        member_el = Et.SubElement(el, "uax:" + name)
        if isinstance(val, list | tuple):
            for v in val:
                try:
                    type_name = ua.ObjectIdNames[cast(int, dtype.Identifier)]
                except KeyError:
                    dtype_node = self.server.get_node(dtype)
                    enc_node = (
                        await dtype_node.get_referenced_nodes(ua.ObjectIds.HasEncoding, ua.BrowseDirection.Forward)
                    )[0]
                    encoded_class = self.server.types.class_for_encoding(enc_node.nodeid)
                    if encoded_class is None:
                        raise UaError(f"No class is registered for the encoding {enc_node.nodeid}")
                    type_name = encoded_class.__name__

                await self._value_to_etree(member_el, type_name, dtype, v)
        else:
            await self._val_to_etree(member_el, dtype, val)

    async def _val_to_etree(self, el: Et.Element, dtype: ua.NodeId, val: Any) -> None:
        if dtype == ua.NodeId(ua.ObjectIds.NodeId) or dtype == ua.NodeId(ua.ObjectIds.ExpandedNodeId):
            id_el = Et.SubElement(el, "uax:Identifier")
            if val.NamespaceIndex in self._addr_idx_to_xml_idx:
                xml_idx = self._addr_idx_to_xml_idx[val.NamespaceIndex]
                if isinstance(val, ua.ExpandedNodeId):
                    val = ua.ExpandedNodeId(
                        val.Identifier, xml_idx, NamespaceUri=val.NamespaceUri, ServerIndex=val.ServerIndex
                    )
                else:
                    val = ua.NodeId(val.Identifier, NamespaceIndex=xml_idx)
            id_el.text = val.to_string()
        elif dtype == ua.NodeId(ua.ObjectIds.Guid):
            id_el = Et.SubElement(el, "uax:String")
            id_el.text = str(val)
        elif dtype == ua.NodeId(ua.ObjectIds.Boolean):
            el.text = "true" if val else "false"
        elif dtype == ua.NodeId(ua.ObjectIds.XmlElement):
            el.text = val.Value or ""
        elif dtype == ua.NodeId(ua.ObjectIds.ByteString):
            if val is None:
                val = b""
            data = base64.b64encode(val)
            el.text = data.decode("utf-8")
        elif dtype == ua.NodeId(ua.ObjectIds.QualifiedName):
            if val.Name is not None:
                name_el = Et.SubElement(el, "uax:Name")
                name_el.text = val.Name
            if val.NamespaceIndex != 0:
                ns = Et.SubElement(el, "uax:NamespaceIndex")
                ns.text = str(val.NamespaceIndex)
        elif dtype == ua.NodeId(ua.ObjectIds.StatusCode):
            code_el = Et.SubElement(el, "uax:Code")
            code_el.text = str(val.value)
        elif not is_dataclass(val):
            if isinstance(val, bytes):
                el.text = val.decode("utf-8")
            elif isinstance(val, Enum):
                el.text = str(val.value)
            else:
                if val is not None:
                    el.text = str(val)
        else:
            await self._all_fields_to_etree(el, val)

    async def value_to_etree(self, el: Et.Element, dtype_name: str, dtype: ua.NodeId, node: Node) -> None:
        """Read the value of ``node`` and write it as the Value element of ``el``."""
        var = await node.read_data_value(raise_on_bad_status=False)
        if var.Value is not None and var.Value.Value is not None:
            val_el = Et.SubElement(el, "Value")
            await self._value_to_etree(val_el, dtype_name, dtype, var.Value.Value)

    async def _value_to_etree(self, el: Et.Element, type_name: str, dtype: ua.NodeId, val: Any) -> None:
        if val is None:
            return

        if isinstance(val, list | tuple):
            if not isinstance(dtype.Identifier, int):
                raise UaInvalidParameterError(f"Expected int, got {type(dtype.Identifier)}")
            if dtype.NamespaceIndex == 0 and dtype.Identifier <= 21:
                elname = "uax:ListOf" + type_name
            else:
                elname = "uax:ListOfExtensionObject"

            list_el = Et.SubElement(el, elname)
            for nval in val:
                await self._value_to_etree(list_el, type_name, dtype, nval)
        else:
            dtype_base: ua.NodeId = (await get_base_data_type(self.server.get_node(dtype))).nodeid
            if dtype_base == ua.NodeId(ua.ObjectIds.Enumeration):
                dtype_base = ua.NodeId(ua.ObjectIds.Int32)
            base_id = dtype_base.Identifier
            if dtype_base.NamespaceIndex == 0 and isinstance(base_id, int) and base_id <= 21:
                type_name = ua.ObjectIdNames[base_id]
                val_el = Et.SubElement(el, "uax:" + type_name)
                await self._val_to_etree(val_el, dtype_base, val)
            else:
                await self._extobj_to_etree(el, type_name, dtype, val)

    async def _extobj_to_etree(self, val_el: Et.Element, name: str, dtype: ua.NodeId, val: Any) -> None:
        if "=" in name:
            registered = self.server.types.find(dtype)
            if registered is not None:
                name = registered.__name__
            else:
                node: Node = self.server.get_node(dtype)
                browse_name = await node.read_browse_name()
                name = browse_name.Name
        obj_el = Et.SubElement(val_el, "uax:ExtensionObject")
        type_el = Et.SubElement(obj_el, "uax:TypeId")
        id_el = Et.SubElement(type_el, "uax:Identifier")
        id_el.text = self._node_to_string(dtype)
        body_el = Et.SubElement(obj_el, "uax:Body")
        struct_el = Et.SubElement(body_el, "uax:" + name)
        await self._all_fields_to_etree(struct_el, val)

    async def _all_fields_to_etree(self, struct_el: Et.Element, val: Any) -> None:
        globalns: dict[str, Any] = {"ua": ua, **vars(ua)}
        resolved_fields = fields_with_resolved_types(val, globalns=globalns)
        for field in resolved_fields:
            if field.name == "Encoding":
                continue
            type_name = type_string_from_type(field.type)
            try:
                dtype = ua.NodeId(getattr(ua.ObjectIds, type_name))
            except AttributeError:
                try:
                    cls = self.server.types.by_name(type_name) if type_name not in dir(ua) else getattr(ua, type_name)
                    enc_node: Node = self.server.get_node(self.server.types.encoding_id_of(cls))
                    dtype_node = (
                        await enc_node.get_referenced_nodes(ua.ObjectIds.HasEncoding, ua.BrowseDirection.Inverse)
                    )[0]
                    dtype = dtype_node.nodeid
                except (AttributeError, KeyError):
                    self.logger.debug("could not find field type %s in registered types", field.type)
                    continue
            await self.member_to_etree(struct_el, field.name, dtype, getattr(val, field.name))


def indent(elem: Et.Element, level: int = 0) -> None:
    """Indent ``elem`` and its children with two spaces per level, starting at ``level``."""
    Et.indent(elem, space="  ", level=level)

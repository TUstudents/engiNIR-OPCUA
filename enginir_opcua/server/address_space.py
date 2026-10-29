from __future__ import annotations

import asyncio
import collections.abc
import dataclasses
import inspect
import logging
import pickle
import shelve
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator

    from enginir_opcua.ua.uaprotocol_auto import (
        DataTypeAttributes,
        ObjectAttributes,
        ObjectTypeAttributes,
        ReferenceTypeAttributes,
        VariableAttributes,
        VariableTypeAttributes,
    )

    __TYPE_ATTRIBUTES = (
        DataTypeAttributes
        | ReferenceTypeAttributes
        | VariableTypeAttributes
        | VariableAttributes
        | ObjectTypeAttributes
        | ObjectAttributes
    )  # FIXME Check, if there are missing attribute types.

from enginir_opcua import ua
from enginir_opcua.ua.numeric_range import IndexRange

from .continuation_points import BrowseCursor, ContinuationPoints
from .datatype_check import BASE_DATA_TYPE, DataTypeChecker, check_variant
from .model_change import NODE_ADDED, NODE_DELETED, REFERENCE_ADDED, REFERENCE_DELETED, record_change

ALL_ELEMENTS_PROCESSED = 0xFFFFFFFF
HIERARCHICAL_REFERENCES = ua.NodeId(ua.ObjectIds.HierarchicalReferences)
HAS_ENCODING = ua.NodeId(ua.ObjectIds.HasEncoding)
NODE_ATTRIBUTES_OF_CLASS: dict[int, type] = {
    ua.NodeClass.Object: ua.uaprotocol_auto.ObjectAttributes,
    ua.NodeClass.Variable: ua.uaprotocol_auto.VariableAttributes,
    ua.NodeClass.Method: ua.uaprotocol_auto.MethodAttributes,
    ua.NodeClass.ObjectType: ua.uaprotocol_auto.ObjectTypeAttributes,
    ua.NodeClass.VariableType: ua.uaprotocol_auto.VariableTypeAttributes,
    ua.NodeClass.ReferenceType: ua.uaprotocol_auto.ReferenceTypeAttributes,
    ua.NodeClass.DataType: ua.uaprotocol_auto.DataTypeAttributes,
    ua.NodeClass.View: ua.uaprotocol_auto.ViewAttributes,
}
HAS_SUBTYPE = ua.NodeId(ua.ObjectIds.HasSubtype)
HAS_COMPONENT = ua.NodeId(ua.ObjectIds.HasComponent)
HAS_PROPERTY = ua.NodeId(ua.ObjectIds.HasProperty)
HAS_TYPE_DEFINITION = ua.NodeId(ua.ObjectIds.HasTypeDefinition)
HAS_MODELLING_RULE = ua.NodeId(ua.ObjectIds.HasModellingRule)
HAS_OPTIONAL_INPUT_ARGUMENT_DESCRIPTION = ua.NodeId(ua.ObjectIds.HasOptionalInputArgumentDescription)
MAX_TYPE_DEPTH = 64

_logger = logging.getLogger(__name__)

VALID_TIMESTAMPS_TO_RETURN = (
    ua.TimestampsToReturn.Source,
    ua.TimestampsToReturn.Server,
    ua.TimestampsToReturn.Both,
    ua.TimestampsToReturn.Neither,
)


ATTRIBUTE_TYPES: dict[ua.AttributeIds, tuple[ua.VariantType, bool]] = {
    ua.AttributeIds.BrowseName: (ua.VariantType.QualifiedName, False),
    ua.AttributeIds.DisplayName: (ua.VariantType.LocalizedText, False),
    ua.AttributeIds.Description: (ua.VariantType.LocalizedText, False),
    ua.AttributeIds.WriteMask: (ua.VariantType.UInt32, False),
    ua.AttributeIds.UserWriteMask: (ua.VariantType.UInt32, False),
    ua.AttributeIds.IsAbstract: (ua.VariantType.Boolean, False),
    ua.AttributeIds.Symmetric: (ua.VariantType.Boolean, False),
    ua.AttributeIds.InverseName: (ua.VariantType.LocalizedText, False),
    ua.AttributeIds.ContainsNoLoops: (ua.VariantType.Boolean, False),
    ua.AttributeIds.EventNotifier: (ua.VariantType.Byte, False),
    ua.AttributeIds.DataType: (ua.VariantType.NodeId, False),
    ua.AttributeIds.ValueRank: (ua.VariantType.Int32, False),
    ua.AttributeIds.ArrayDimensions: (ua.VariantType.UInt32, True),
    ua.AttributeIds.AccessLevel: (ua.VariantType.Byte, False),
    ua.AttributeIds.UserAccessLevel: (ua.VariantType.Byte, False),
    ua.AttributeIds.MinimumSamplingInterval: (ua.VariantType.Double, False),
    ua.AttributeIds.Historizing: (ua.VariantType.Boolean, False),
    ua.AttributeIds.Executable: (ua.VariantType.Boolean, False),
    ua.AttributeIds.UserExecutable: (ua.VariantType.Boolean, False),
    ua.AttributeIds.DataTypeDefinition: (ua.VariantType.ExtensionObject, False),
    ua.AttributeIds.RolePermissions: (ua.VariantType.ExtensionObject, True),
    ua.AttributeIds.AccessRestrictions: (ua.VariantType.UInt16, False),
    ua.AttributeIds.AccessLevelEx: (ua.VariantType.UInt32, False),
}


def status_of_error(error: Exception) -> ua.StatusCode:
    if isinstance(error, ua.uaerrors.UaStatusCodeError) and isinstance(error.code, int):
        return ua.StatusCode(error.code)
    return ua.StatusCode(ua.StatusCodes.BadInternalError)


def has_no_value(dv: ua.DataValue) -> bool:
    return (
        (dv.Value is None or dv.Value.VariantType == ua.VariantType.Null)
        and (dv.StatusCode is None or dv.StatusCode.is_good())
        and dv.SourceTimestamp is None
        and dv.ServerTimestamp is None
    )


class AttributeValue:
    """
    The class holds the value(s) of an attribute and callbacks.
    """

    def __init__(self, value: ua.DataValue) -> None:
        self.value: "ua.DataValue | None" = value
        self.value_callback: "Callable[[ua.NodeId, ua.AttributeIds], ua.DataValue] | None" = None
        self.value_setter: "Callable[[NodeData, ua.AttributeIds, ua.DataValue], Any] | None" = None
        self.datachange_callbacks: dict[int, "Callable[..., Any]"] = {}

    def __str__(self) -> str:
        return f"AttributeValue({self.value})" if not self.value_callback else f"AttributeValue({self.value_callback})"

    __repr__ = __str__


class NodeData:
    """
    The class is internal to enginir_opcua and holds all the information about a Node.
    """

    reference_version: int = 0

    def __init__(self, nodeid: ua.NodeId) -> None:
        self.nodeid: "ua.NodeId" = nodeid
        self.attributes: "dict[ua.AttributeIds, AttributeValue]" = {}
        self.references: "list[ua.ReferenceDescription]" = []
        self.call: "Callable[..., Any] | None" = None

    def __str__(self) -> str:
        return f"NodeData(id:{self.nodeid}, attrs:{self.attributes}, refs:{self.references})"

    __repr__ = __str__


class AttributeService:
    """
    This class implements the attribute service set defined in the opc ua standard.
    OPC 10000-4 v1.05, 5.11.1
    """

    def __init__(self, aspace: AddressSpace) -> None:
        self.logger = logging.getLogger(__name__)
        self._aspace: AddressSpace = aspace

    def read(self, params: ua.ReadParameters, trusted: bool = False) -> list[ua.DataValue]:
        if params.MaxAge < 0:
            raise ua.uaerrors.BadMaxAgeInvalid()
        if params.TimestampsToReturn not in VALID_TIMESTAMPS_TO_RETURN:
            raise ua.uaerrors.BadTimestampsToReturnInvalid()
        return [
            self._aspace.read_attribute(
                item.NodeId,
                item.AttributeId,
                trusted=trusted,
                index_range=item.IndexRange,
                timestamps=params.TimestampsToReturn,
            )
            for item in params.NodesToRead
        ]

    async def write(self, params: ua.WriteParameters, trusted: bool = False) -> list[ua.StatusCode]:
        return [
            await self._aspace.write_attribute(
                item.NodeId, item.AttributeId, item.Value, trusted=trusted, index_range=item.IndexRange
            )
            for item in params.NodesToWrite
        ]


class BrowseLimits(Protocol):
    max_browse_references_per_node: int
    max_translate_matches: int


@dataclasses.dataclass
class DefaultBrowseLimits:
    max_browse_references_per_node: int = 10_000
    max_translate_matches: int = 1_000


class ViewService:
    """
    This class implements the view service set defined in the opc ua standard.
    OPC 10000-4 v1.05, 5.9.1
    """

    def __init__(self, aspace: AddressSpace, limits: BrowseLimits | None = None) -> None:
        self.logger = logging.getLogger(__name__)
        self._aspace: AddressSpace = aspace
        self._limits: BrowseLimits = limits if limits is not None else DefaultBrowseLimits()

    def browse(
        self, params: ua.BrowseParameters, points: ContinuationPoints[BrowseCursor] | None = None
    ) -> list[ua.BrowseResult]:
        if params.View is not None and not params.View.ViewId.is_null():
            raise ua.uaerrors.BadViewIdUnknown()
        points = points if points is not None else ContinuationPoints[BrowseCursor](lambda: 0)
        limit = self._page_limit(params.RequestedMaxReferencesPerNode)
        created: set[bytes] = set()
        return [self._browse_checked(desc, limit, points, created) for desc in params.NodesToBrowse]

    def _page_limit(self, requested: int) -> int:
        cap = self._limits.max_browse_references_per_node
        return min(requested, cap) if requested else cap

    def _browse_checked(
        self, desc: ua.BrowseDescription, limit: int, points: ContinuationPoints[BrowseCursor], created: set[bytes]
    ) -> ua.BrowseResult:
        try:
            node = self._aspace.node_for_service(desc.NodeId)
            if desc.BrowseDirection not in (
                ua.BrowseDirection.Forward,
                ua.BrowseDirection.Inverse,
                ua.BrowseDirection.Both,
            ):
                raise ua.uaerrors.BadBrowseDirectionInvalid()
            if not desc.ReferenceTypeId.is_null() and not self._aspace.is_reference_type(desc.ReferenceTypeId):
                raise ua.uaerrors.BadReferenceTypeIdInvalid()
            cursor = BrowseCursor(
                node.nodeid,
                desc.BrowseDirection,
                desc.ReferenceTypeId,
                desc.IncludeSubtypes,
                desc.NodeClassMask,
                desc.ResultMask,
                limit,
                0,
                node.reference_version,
            )
            return self._page(node, cursor, points, created, None)
        except ua.uaerrors.UaStatusCodeError as error:
            return ua.BrowseResult(StatusCode=status_of_error(error))

    def _page(
        self,
        node: NodeData,
        cursor: BrowseCursor,
        points: ContinuationPoints[BrowseCursor],
        created: set[bytes],
        token: bytes | None,
    ) -> ua.BrowseResult:
        allowed_types = self._allowed_reference_types(cursor)
        result = ua.BrowseResult()
        next_position: int | None = None
        for index in range(cursor.position, len(node.references)):
            description = self._describe(node.references[index], cursor, allowed_types)
            if description is None:
                continue
            if len(result.References) == cursor.page_limit:
                next_position = index
                break
            result.References.append(description)
        if next_position is None:
            if token is not None:
                points.take(token)
            return result
        cursor.position = next_position
        if token is not None:
            result.ContinuationPoint = points.renew(token)
            return result
        if not points.has_room():
            points.release_oldest(created)
        if not points.has_room():
            return ua.BrowseResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadNoContinuationPoints))
        result.ContinuationPoint = points.add(cursor)
        created.add(result.ContinuationPoint)
        return result

    def _allowed_reference_types(self, cursor: BrowseCursor) -> set[ua.NodeId] | None:
        if cursor.reference_type.is_null():
            return None
        allowed = {cursor.reference_type}
        if cursor.include_subtypes:
            allowed.update(self._get_sub_ref(cursor.reference_type))
        return allowed

    def _describe(
        self, ref: ua.ReferenceDescription, cursor: BrowseCursor, allowed_types: set[ua.NodeId] | None
    ) -> ua.ReferenceDescription | None:
        symmetric = self._aspace.is_symmetric(ref.ReferenceTypeId)
        is_forward = ref.IsForward or symmetric
        if cursor.direction == ua.BrowseDirection.Forward and not is_forward:
            return None
        if cursor.direction == ua.BrowseDirection.Inverse and (ref.IsForward or symmetric):
            return None
        if allowed_types is not None and ref.ReferenceTypeId not in allowed_types:
            return None
        target = self._aspace.get(ref.NodeId)
        if target is None:
            return None
        node_class = self._aspace.node_class_of(target) or ua.NodeClass.Unspecified
        if cursor.node_class_mask and not cursor.node_class_mask & node_class:
            return None
        mask = cursor.result_mask
        description = ua.ReferenceDescription(NodeId=ref.NodeId)
        if mask & ua.BrowseResultMask.ReferenceTypeId:
            description.ReferenceTypeId = ref.ReferenceTypeId
        if mask & ua.BrowseResultMask.IsForward:
            description.IsForward = is_forward
        if mask & ua.BrowseResultMask.NodeClass:
            description.NodeClass = ua.NodeClass(node_class)
        if mask & ua.BrowseResultMask.BrowseName:
            description.BrowseName = self._aspace.browse_name_of(target)
        if mask & ua.BrowseResultMask.DisplayName:
            description.DisplayName = self._aspace.display_name_of(target)
        if mask & ua.BrowseResultMask.TypeDefinition and node_class in (ua.NodeClass.Object, ua.NodeClass.Variable):
            description.TypeDefinition = self._aspace.type_definition_of(target)
        return description

    def browse_next(
        self, params: ua.BrowseNextParameters, points: ContinuationPoints[BrowseCursor]
    ) -> list[ua.BrowseResult]:
        if params.ReleaseContinuationPoints:
            for token in params.ContinuationPoints:
                points.take(token)
            return []
        return [self._continue(token, points) for token in params.ContinuationPoints]

    def _continue(self, token: bytes, points: ContinuationPoints[BrowseCursor]) -> ua.BrowseResult:
        cursor = points.get(token)
        if cursor is None:
            return ua.BrowseResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadContinuationPointInvalid))
        node = self._aspace.get(cursor.node_id)
        if node is None or node.reference_version != cursor.version:
            points.take(token)
            return ua.BrowseResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadContinuationPointInvalid))
        return self._page(node, cursor, points, set(), token)

    def _get_sub_ref(self, ref: ua.NodeId) -> Generator[ua.NodeId, None, None]:
        nodedata = self._aspace.get(ref)
        if nodedata is not None:
            for ref_desc in nodedata.references:
                if ref_desc.ReferenceTypeId == HAS_SUBTYPE and ref_desc.IsForward:
                    yield ref_desc.NodeId
                    yield from self._get_sub_ref(ref_desc.NodeId)

    def translate_browsepaths_to_nodeids(self, browsepaths: list[ua.BrowsePath]) -> list[ua.BrowsePathResult]:
        return [self._translate_checked(path) for path in browsepaths]

    def _translate_checked(self, path: ua.BrowsePath) -> ua.BrowsePathResult:
        try:
            return self._translate_browsepath_to_nodeid(path)
        except ua.uaerrors.UaStatusCodeError as error:
            return ua.BrowsePathResult(StatusCode=status_of_error(error))

    def _translate_browsepath_to_nodeid(self, path: ua.BrowsePath) -> ua.BrowsePathResult:
        self._aspace.node_for_service(path.StartingNode)
        elements = path.RelativePath.Elements
        if not elements:
            raise ua.uaerrors.BadNothingToDo()
        if any(not element.TargetName or not element.TargetName.Name for element in elements):
            raise ua.uaerrors.BadBrowseNameInvalid()
        target_nodeids = self._navigate(path.StartingNode, elements)
        if not target_nodeids:
            raise ua.uaerrors.BadNoMatch()
        res = ua.BrowsePathResult()
        for nodeid in target_nodeids:
            res.Targets.append(ua.BrowsePathTarget(TargetId=nodeid, RemainingPathIndex=ALL_ELEMENTS_PROCESSED))
        return res

    def _navigate(self, start_nodeid: ua.NodeId, elements: list[ua.RelativePathElement]) -> list[ua.NodeId]:
        current_nodeids = [start_nodeid]
        for el in elements:
            new_currents: list[ua.NodeId] = []
            for nodeid in current_nodeids:
                for found in self._find_elements_in_node(el, nodeid):
                    if found not in new_currents:
                        new_currents.append(found)
            if len(new_currents) > self._limits.max_translate_matches:
                raise ua.uaerrors.BadTooManyMatches()
            if not new_currents:
                return []
            current_nodeids = new_currents
        return current_nodeids

    def _find_elements_in_node(self, el: ua.RelativePathElement, nodeid: ua.NodeId) -> list[ua.NodeId]:
        nodedata = self._aspace[nodeid]
        allowed = None
        if not el.ReferenceTypeId.is_null():
            allowed = {el.ReferenceTypeId}
            if el.IncludeSubtypes:
                allowed.update(self._get_sub_ref(el.ReferenceTypeId))
        nodeids: list[ua.NodeId] = []
        for ref in nodedata.references:
            if ref.IsForward == el.IsInverse:
                continue
            if allowed is not None and ref.ReferenceTypeId not in allowed:
                continue
            target = self._aspace.get(ref.NodeId)
            if target is not None and self._aspace.browse_name_of(target) == el.TargetName:
                nodeids.append(ref.NodeId)
        return nodeids


class NodeManagementService:
    """
    This class implements the node management service set defined in the opc ua standard.
    OPC 10000-4 v1.05, 5.8.1
    """

    def __init__(self, aspace: AddressSpace) -> None:
        self.logger = logging.getLogger(__name__)
        self._aspace: AddressSpace = aspace
        self._adding: ua.NodeId | None = None

    def add_nodes(self, addnodeitems: list[ua.AddNodesItem], trusted: bool = True) -> list[ua.AddNodesResult]:
        return [self._add_node(item, trusted) for item in addnodeitems]

    def try_add_nodes(
        self, addnodeitems: list[ua.AddNodesItem], trusted: bool = True, check: bool = True
    ) -> "Generator[ua.AddNodesItem, None, None]":
        for item in addnodeitems:
            ret = self._add_node(item, trusted, check=check)
            if not ret.StatusCode.is_good():
                yield item

    def _type_for_change(self, node_id: ua.NodeId) -> ua.NodeId:
        node = self._aspace.get(node_id)
        if node is None or self._aspace.node_class_of(node) not in (ua.NodeClass.Object, ua.NodeClass.Variable):
            return ua.NodeId()
        return self._aspace.type_definition_of(node)

    def _record(self, node_id: ua.NodeId, verb: int) -> None:
        record_change(node_id, verb, lambda: self._type_for_change(node_id))  # J: model change events (SRV-96)

    def _add_node(self, item: ua.AddNodesItem, trusted: bool, check: bool = True) -> ua.AddNodesResult:
        try:
            return ua.AddNodesResult(AddedNodeId=self._add_node_checked(item, trusted, check))
        except ua.uaerrors.UaStatusCodeError as error:
            return ua.AddNodesResult(StatusCode=status_of_error(error))

    def _add_node_checked(self, item: ua.AddNodesItem, trusted: bool, check: bool) -> ua.NodeId:
        aspace = self._aspace
        requested = item.RequestedNewNodeId
        if getattr(requested, "ServerIndex", 0) or (not trusted and requested.NamespaceIndex == 0):
            raise ua.uaerrors.BadNodeIdRejected()
        if requested.has_null_identifier():
            item.RequestedNewNodeId = aspace.generate_nodeid(requested.NamespaceIndex)
        elif requested in aspace:
            self.logger.warning("AddNodesItem: Requested NodeId %s already exists", requested)
            raise ua.uaerrors.BadNodeIdExists()
        if check:
            self._check_node_class_and_attributes(item)
        if item.ParentNodeId.is_null() and check:
            raise ua.uaerrors.BadParentNodeIdInvalid()
        parentdata = aspace.get(item.ParentNodeId)
        if parentdata is None and not item.ParentNodeId.is_null():
            self.logger.info(
                "add_node: while adding node %s, requested parent node %s does not exists",
                item.RequestedNewNodeId,
                item.ParentNodeId,
            )
            raise ua.uaerrors.BadParentNodeIdInvalid()
        if check and parentdata is not None:
            self._check_parent_reference(item, parentdata, trusted)
        type_definition = self._checked_type_definition(item, trusted, check)
        nodedata = NodeData(item.RequestedNewNodeId)
        self._add_node_attributes(nodedata, item, add_timestamps=check)
        if check:
            self._complete_attributes(nodedata, item, type_definition)
        aspace[nodedata.nodeid] = nodedata
        self._adding = nodedata.nodeid
        try:
            if parentdata is not None:
                self._add_ref_from_parent(nodedata, item, parentdata)
                self._add_ref_to_parent(nodedata, item, parentdata)
            if not type_definition.is_null():
                item.TypeDefinition = type_definition
                self._add_type_definition(nodedata, item)
        except Exception:
            self._remove_added_node(nodedata, parentdata)
            raise
        finally:
            self._adding = None
        self._record(nodedata.nodeid, NODE_ADDED)
        return nodedata.nodeid

    def _remove_added_node(self, nodedata: NodeData, parentdata: NodeData | None) -> None:
        if parentdata is not None:
            parentdata.references[:] = [ref for ref in parentdata.references if ref.NodeId != nodedata.nodeid]
            parentdata.reference_version += 1
        del self._aspace[nodedata.nodeid]

    def _check_node_class_and_attributes(self, item: ua.AddNodesItem) -> None:
        if item.NodeClass not in NODE_ATTRIBUTES_OF_CLASS:
            raise ua.uaerrors.BadNodeClassInvalid()
        if not isinstance(item.NodeAttributes, NODE_ATTRIBUTES_OF_CLASS[item.NodeClass]):
            raise ua.uaerrors.BadNodeAttributesInvalid()
        if not item.BrowseName or not item.BrowseName.Name:
            raise ua.uaerrors.BadBrowseNameInvalid()

    def _check_parent_reference(self, item: ua.AddNodesItem, parentdata: NodeData, trusted: bool) -> None:
        aspace = self._aspace
        if not trusted:
            reference_type = aspace.get(item.ReferenceTypeId)
            if reference_type is None or not aspace.is_reference_type(item.ReferenceTypeId):
                raise ua.uaerrors.BadReferenceTypeIdInvalid()
            checker = DataTypeChecker(aspace)
            allowed = checker.is_subtype(item.ReferenceTypeId, HIERARCHICAL_REFERENCES) or checker.is_subtype(
                item.ReferenceTypeId, HAS_ENCODING
            )
            if aspace.bool_attribute(reference_type, ua.AttributeIds.IsAbstract) or not allowed:
                raise ua.uaerrors.BadReferenceNotAllowed()
        if trusted and item.ReferenceTypeId != HAS_PROPERTY:
            return
        for ref in parentdata.references:
            if ref.IsForward and ref.ReferenceTypeId == item.ReferenceTypeId:
                target = aspace.get(ref.NodeId)
                if target is not None and aspace.browse_name_of(target) == item.BrowseName:
                    self.logger.warning(
                        "AddNodesItem: Requested Browsename %s already exists in Parent Node. ParentID:%s --- ItemId:%s",
                        item.BrowseName.Name,
                        item.ParentNodeId,
                        item.RequestedNewNodeId,
                    )
                    raise ua.uaerrors.BadBrowseNameDuplicated()

    def _checked_type_definition(self, item: ua.AddNodesItem, trusted: bool, check: bool) -> ua.NodeId:
        aspace = self._aspace
        definition = item.TypeDefinition
        if not check:
            if not definition.is_null() and definition not in aspace:
                raise ua.uaerrors.BadTypeDefinitionInvalid()
            return definition
        wanted = {
            ua.NodeClass.Object: ua.NodeClass.ObjectType,
            ua.NodeClass.Variable: ua.NodeClass.VariableType,
        }.get(item.NodeClass)
        if definition.is_null():
            if wanted is None or trusted:
                return definition
            return ua.NodeId(
                ua.ObjectIds.BaseObjectType if wanted == ua.NodeClass.ObjectType else ua.ObjectIds.BaseDataVariableType
            )
        type_node = aspace.get(definition)
        if wanted is None or type_node is None or aspace.node_class_of(type_node) != wanted:
            raise ua.uaerrors.BadTypeDefinitionInvalid()
        if (
            not trusted
            and wanted == ua.NodeClass.ObjectType
            and aspace.bool_attribute(type_node, ua.AttributeIds.IsAbstract)
            and not self._is_inside_type(item.ParentNodeId)
        ):
            raise ua.uaerrors.BadTypeDefinitionInvalid()
        return definition

    def _is_inside_type(self, nodeid: ua.NodeId) -> bool:
        """InstanceDeclarations below a type may have an abstract TypeDefinition (OPC 10000-3 v1.05, 6.2.1)."""
        aspace = self._aspace
        for _ in range(32):
            node = aspace.get(nodeid)
            if node is None:
                return False
            if aspace.node_class_of(node) in (ua.NodeClass.ObjectType, ua.NodeClass.VariableType):
                return True
            parents = [
                ref.NodeId
                for ref in node.references
                if not ref.IsForward and ref.ReferenceTypeId in (HAS_COMPONENT, HAS_PROPERTY)
            ]
            if not parents:
                return False
            nodeid = parents[0]
        return False

    def _complete_attributes(self, nodedata: NodeData, item: ua.AddNodesItem, type_definition: ua.NodeId) -> None:
        defaults: dict[ua.AttributeIds, tuple[Any, ua.VariantType]] = {
            ua.AttributeIds.DisplayName: (ua.LocalizedText(item.BrowseName.Name), ua.VariantType.LocalizedText)
        }
        if item.NodeClass in (ua.NodeClass.Variable, ua.NodeClass.VariableType):
            defaults[ua.AttributeIds.ValueRank] = (ua.ValueRank.Any, ua.VariantType.Int32)
            defaults[ua.AttributeIds.DataType] = (self._default_data_type(type_definition), ua.VariantType.NodeId)
        if item.NodeClass == ua.NodeClass.Variable:
            defaults[ua.AttributeIds.AccessLevel] = (ua.AccessLevel.CurrentRead.mask, ua.VariantType.Byte)
            defaults[ua.AttributeIds.UserAccessLevel] = (ua.AccessLevel.CurrentRead.mask, ua.VariantType.Byte)
            defaults[ua.AttributeIds.Historizing] = (False, ua.VariantType.Boolean)
            defaults[ua.AttributeIds.MinimumSamplingInterval] = (-1.0, ua.VariantType.Double)
        elif item.NodeClass in (ua.NodeClass.Object, ua.NodeClass.View):
            defaults[ua.AttributeIds.EventNotifier] = (0, ua.VariantType.Byte)
        elif item.NodeClass == ua.NodeClass.Method:
            defaults[ua.AttributeIds.Executable] = (True, ua.VariantType.Boolean)
            defaults[ua.AttributeIds.UserExecutable] = (True, ua.VariantType.Boolean)
        if item.NodeClass in (
            ua.NodeClass.ObjectType,
            ua.NodeClass.VariableType,
            ua.NodeClass.ReferenceType,
            ua.NodeClass.DataType,
        ):
            defaults[ua.AttributeIds.IsAbstract] = (False, ua.VariantType.Boolean)
        if item.NodeClass == ua.NodeClass.ReferenceType:
            defaults[ua.AttributeIds.Symmetric] = (False, ua.VariantType.Boolean)
        if item.NodeClass == ua.NodeClass.View:
            defaults[ua.AttributeIds.ContainsNoLoops] = (False, ua.VariantType.Boolean)
        for attribute, (value, vtype) in defaults.items():
            if attribute not in nodedata.attributes:
                nodedata.attributes[attribute] = AttributeValue(ua.DataValue(ua.Variant(value, vtype)))
        if item.NodeClass in (ua.NodeClass.Variable, ua.NodeClass.VariableType):
            if ua.AttributeIds.Value not in nodedata.attributes:
                nodedata.attributes[ua.AttributeIds.Value] = AttributeValue(
                    ua.DataValue(ua.Variant(None, ua.VariantType.Null))
                )

    def _default_data_type(self, type_definition: ua.NodeId) -> ua.NodeId:
        type_node = self._aspace.get(type_definition)
        declared = self._aspace.node_id_attribute(type_node, ua.AttributeIds.DataType) if type_node else None
        return declared if declared is not None else BASE_DATA_TYPE

    def _add_node_attributes(self, nodedata: NodeData, item: ua.AddNodesItem, add_timestamps: bool) -> None:
        # add common attrs
        nodedata.attributes[ua.AttributeIds.NodeId] = AttributeValue(
            ua.DataValue(ua.Variant(nodedata.nodeid, ua.VariantType.NodeId))
        )
        nodedata.attributes[ua.AttributeIds.BrowseName] = AttributeValue(
            ua.DataValue(ua.Variant(item.BrowseName, ua.VariantType.QualifiedName))
        )
        nodedata.attributes[ua.AttributeIds.NodeClass] = AttributeValue(
            ua.DataValue(ua.Variant(item.NodeClass, ua.VariantType.Int32))
        )
        # add requested attrs
        self._add_nodeattributes(item.NodeAttributes, nodedata, add_timestamps)
        if item.NodeClass == ua.NodeClass.DataType and ua.AttributeIds.DataTypeDefinition not in nodedata.attributes:
            nodedata.attributes[ua.AttributeIds.DataTypeDefinition] = AttributeValue(
                ua.DataValue(ua.Variant(None, ua.VariantType.Null))
            )

    def _add_unique_reference(
        self, nodedata: NodeData, desc: ua.ReferenceDescription, strict: bool = False
    ) -> ua.StatusCode:
        for r in nodedata.references:
            if r.ReferenceTypeId == desc.ReferenceTypeId and r.NodeId == desc.NodeId:
                if r.IsForward != desc.IsForward:
                    self.logger.error("Cannot add conflicting reference %s ", str(desc))
                    return ua.StatusCode(ua.StatusCodes.BadReferenceNotAllowed)
                if strict:
                    return ua.StatusCode(ua.StatusCodes.BadDuplicateReferenceNotAllowed)
                return ua.StatusCode()
        nodedata.references.append(desc)
        nodedata.reference_version += 1
        self._aspace.reference_added(nodedata.nodeid, desc.NodeId)
        if nodedata.nodeid != self._adding:
            self._record(nodedata.nodeid, REFERENCE_ADDED)
        return ua.StatusCode()

    def _add_ref_from_parent(self, nodedata: NodeData, item: ua.AddNodesItem, parentdata: NodeData) -> None:
        desc = ua.ReferenceDescription()
        desc.ReferenceTypeId = item.ReferenceTypeId
        desc.NodeId = nodedata.nodeid
        desc.NodeClass = item.NodeClass
        desc.BrowseName = item.BrowseName
        desc.DisplayName = item.NodeAttributes.DisplayName
        desc.TypeDefinition = item.TypeDefinition
        desc.IsForward = True
        self._add_unique_reference(parentdata, desc).check()

    def _add_ref_to_parent(self, nodedata: NodeData, item: ua.AddNodesItem, parentdata: NodeData) -> None:
        addref = ua.AddReferencesItem()
        addref.ReferenceTypeId = item.ReferenceTypeId
        addref.SourceNodeId = nodedata.nodeid
        addref.TargetNodeId = item.ParentNodeId
        nodeclass_attr = parentdata.attributes[ua.AttributeIds.NodeClass].value
        if nodeclass_attr is None or nodeclass_attr.Value is None:
            return
        addref.TargetNodeClass = nodeclass_attr.Value.Value
        addref.IsForward = False
        self._add_reference_no_check(nodedata, addref).check()

    def _add_type_definition(self, nodedata: NodeData, item: ua.AddNodesItem) -> None:
        addref = ua.AddReferencesItem()
        addref.SourceNodeId = nodedata.nodeid
        addref.IsForward = True
        addref.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasTypeDefinition)
        addref.TargetNodeId = item.TypeDefinition
        addref.TargetNodeClass = ua.NodeClass.Unspecified
        self._add_reference_no_check(nodedata, addref).check()

    async def delete_nodes(
        self, deletenodeitems: ua.DeleteNodesParameters, trusted: bool = True
    ) -> list[ua.StatusCode]:
        return [await self._delete_node(item, trusted) for item in deletenodeitems.NodesToDelete]

    async def _delete_node(self, item: ua.DeleteNodesItem, trusted: bool) -> ua.StatusCode:
        if item.NodeId is None or item.NodeId.is_null():
            return ua.StatusCode(ua.StatusCodes.BadNodeIdInvalid)
        if item.NodeId not in self._aspace:
            self.logger.warning("DeleteNodesItem: NodeId %s does not exists", item.NodeId)
            return ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)
        if not trusted and item.NodeId.NamespaceIndex == 0:
            return ua.StatusCode(ua.StatusCodes.BadNoDeleteRights)

        self._record(item.NodeId, NODE_DELETED)
        if item.DeleteTargetReferences:
            for source in self._aspace.referencing_nodes(item.NodeId):
                sourcedata = self._aspace.get(source)
                if sourcedata is None:
                    continue
                sourcedata.references[:] = [ref for ref in sourcedata.references if ref.NodeId != item.NodeId]
                sourcedata.reference_version += 1
                self._aspace.reference_removed(source, item.NodeId)
                self._record(source, REFERENCE_DELETED)

        await self._delete_node_callbacks(self._aspace[item.NodeId])

        del self._aspace[item.NodeId]

        return ua.StatusCode()

    async def _delete_node_callbacks(self, nodedata: NodeData) -> None:
        for attribute, attval in nodedata.attributes.items():
            for handle, callback in list(attval.datachange_callbacks.items()):
                try:
                    await callback(handle, None, ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown))
                    self._aspace.delete_datachange_callback(handle)
                except Exception as ex:
                    self.logger.exception(
                        "Error calling delete node callback callback %s, %s, %s", nodedata, attribute, ex
                    )

    def add_references(self, refs: list[ua.AddReferencesItem], trusted: bool = True) -> list[ua.StatusCode]:
        return [self._add_reference(ref, trusted) for ref in refs]

    def try_add_references(
        self, refs: list[ua.AddReferencesItem], trusted: bool = True
    ) -> "Generator[ua.AddReferencesItem, None, None]":
        for ref in refs:
            status = self._add_reference(ref, trusted)
            if status.is_bad() and status.value != ua.StatusCodes.BadDuplicateReferenceNotAllowed:
                yield ref

    def _add_reference(self, addref: ua.AddReferencesItem, trusted: bool) -> ua.StatusCode:
        aspace = self._aspace
        sourcedata = aspace.get(addref.SourceNodeId)
        if sourcedata is None:
            return ua.StatusCode(ua.StatusCodes.BadSourceNodeIdInvalid)
        reference_type = aspace.get(addref.ReferenceTypeId)
        if (
            reference_type is None
            or not aspace.is_reference_type(addref.ReferenceTypeId)
            or aspace.bool_attribute(reference_type, ua.AttributeIds.IsAbstract)
        ):
            return ua.StatusCode(ua.StatusCodes.BadReferenceTypeIdInvalid)
        if addref.TargetServerUri or getattr(addref.TargetNodeId, "ServerIndex", 0):
            return ua.StatusCode(ua.StatusCodes.BadServerUriInvalid)
        targetdata = aspace.get(addref.TargetNodeId)
        if targetdata is None:
            return ua.StatusCode(ua.StatusCodes.BadTargetNodeIdInvalid)
        actual_class = aspace.node_class_of(targetdata)
        if addref.TargetNodeClass not in (ua.NodeClass.Unspecified, actual_class):
            return ua.StatusCode(ua.StatusCodes.BadNodeClassInvalid)
        if not trusted and addref.SourceNodeId.NamespaceIndex == 0 and addref.TargetNodeId.NamespaceIndex == 0:
            return ua.StatusCode(ua.StatusCodes.BadReferenceNotAllowed)
        if addref.SourceNodeId == addref.TargetNodeId and DataTypeChecker(aspace).is_subtype(
            addref.ReferenceTypeId, HIERARCHICAL_REFERENCES
        ):
            return ua.StatusCode(ua.StatusCodes.BadInvalidSelfReference)
        return self._add_reference_no_check(sourcedata, addref, strict=not trusted)

    def _add_reference_no_check(
        self, sourcedata: NodeData, addref: ua.AddReferencesItem, strict: bool = False
    ) -> ua.StatusCode:
        rdesc = ua.ReferenceDescription()
        rdesc.ReferenceTypeId = addref.ReferenceTypeId
        rdesc.IsForward = addref.IsForward
        rdesc.NodeId = addref.TargetNodeId
        if addref.TargetNodeClass == ua.NodeClass.Unspecified:
            nodeclass_dv = self._aspace.read_attribute_value(addref.TargetNodeId, ua.AttributeIds.NodeClass)
            if nodeclass_dv.Value is not None:
                rdesc.NodeClass = nodeclass_dv.Value.Value
        else:
            rdesc.NodeClass = addref.TargetNodeClass
        bname_dv = self._aspace.read_attribute_value(addref.TargetNodeId, ua.AttributeIds.BrowseName)
        bname = bname_dv.Value.Value if bname_dv.Value is not None else None
        if bname:
            rdesc.BrowseName = bname
        dname_dv = self._aspace.read_attribute_value(addref.TargetNodeId, ua.AttributeIds.DisplayName)
        dname = dname_dv.Value.Value if dname_dv.Value is not None else None
        if dname:
            rdesc.DisplayName = dname
        if rdesc.NodeClass in (ua.NodeClass.Object, ua.NodeClass.Variable):
            targetdata = self._aspace.get(addref.TargetNodeId)
            if targetdata is not None:
                for target_ref in targetdata.references:
                    if target_ref.IsForward and target_ref.ReferenceTypeId == ua.NodeId(ua.ObjectIds.HasTypeDefinition):
                        rdesc.TypeDefinition = target_ref.NodeId
                        break
        return self._add_unique_reference(sourcedata, rdesc, strict)

    def delete_references(self, refs: list[ua.DeleteReferencesItem], trusted: bool = True) -> list[ua.StatusCode]:
        return [self._delete_reference(ref, trusted) for ref in refs]

    def _delete_unique_reference(self, item: ua.DeleteReferencesItem, invert: bool = False) -> ua.StatusCode:
        if invert:
            source, target, forward = item.TargetNodeId, item.SourceNodeId, not item.IsForward
        else:
            source, target, forward = item.SourceNodeId, item.TargetNodeId, item.IsForward
        for rdesc in self._aspace[source].references:
            if rdesc.NodeId == target and rdesc.ReferenceTypeId == item.ReferenceTypeId:
                if rdesc.IsForward == forward:
                    self._aspace[source].references.remove(rdesc)
                    self._aspace[source].reference_version += 1
                    self._aspace.reference_removed(source, target)
                    self._record(source, REFERENCE_DELETED)
                    return ua.StatusCode()
        return ua.StatusCode(ua.StatusCodes.BadNotFound)

    def _delete_reference(self, item: ua.DeleteReferencesItem, trusted: bool) -> ua.StatusCode:
        aspace = self._aspace
        if item.SourceNodeId not in aspace:
            return ua.StatusCode(ua.StatusCodes.BadSourceNodeIdInvalid)
        if not aspace.is_reference_type(item.ReferenceTypeId):
            return ua.StatusCode(ua.StatusCodes.BadReferenceTypeIdInvalid)
        if getattr(item.TargetNodeId, "ServerIndex", 0):
            return ua.StatusCode(ua.StatusCodes.BadServerIndexInvalid)
        if item.TargetNodeId not in aspace:
            return ua.StatusCode(ua.StatusCodes.BadTargetNodeIdInvalid)
        if not trusted and item.SourceNodeId.NamespaceIndex == 0 and item.TargetNodeId.NamespaceIndex == 0:
            return ua.StatusCode(ua.StatusCodes.BadNoDeleteRights)

        if item.DeleteBidirectional:
            self._delete_unique_reference(item, True)
        return self._delete_unique_reference(item)

    def _add_node_attr(
        self,
        attributes: "__TYPE_ATTRIBUTES",
        nodedata: NodeData,
        name: str,
        vtype: ua.VariantType | None = None,
        add_timestamps: bool = False,
        is_array: bool = False,
    ) -> None:
        if attributes.SpecifiedAttributes & getattr(ua.NodeAttributesMask, name):
            value = getattr(attributes, name)
            if name == "DataTypeDefinition" and not isinstance(value, ua.DataTypeDefinition):
                variant = ua.Variant(None, ua.VariantType.Null)
            else:
                variant = ua.Variant(value, vtype, is_array=is_array)
            dv = ua.DataValue(
                variant,
                SourceTimestamp=datetime.now(UTC) if add_timestamps else None,
                ServerTimestamp=datetime.now(UTC) if add_timestamps and self._aspace.force_server_timestamp else None,
            )
            nodedata.attributes[getattr(ua.AttributeIds, name)] = AttributeValue(dv)

    def _add_nodeattributes(
        self, node_attributes: "__TYPE_ATTRIBUTES", nodedata: NodeData, add_timestamps: bool
    ) -> None:
        self._add_node_attr(node_attributes, nodedata, "AccessLevel", ua.VariantType.Byte)
        self._add_node_attr(node_attributes, nodedata, "ArrayDimensions", ua.VariantType.UInt32, is_array=True)
        self._add_node_attr(node_attributes, nodedata, "BrowseName", ua.VariantType.QualifiedName)
        self._add_node_attr(node_attributes, nodedata, "ContainsNoLoops", ua.VariantType.Boolean)
        self._add_node_attr(node_attributes, nodedata, "DataType", ua.VariantType.NodeId)
        self._add_node_attr(node_attributes, nodedata, "Description", ua.VariantType.LocalizedText)
        self._add_node_attr(node_attributes, nodedata, "DisplayName", ua.VariantType.LocalizedText)
        self._add_node_attr(node_attributes, nodedata, "EventNotifier", ua.VariantType.Byte)
        self._add_node_attr(node_attributes, nodedata, "Executable", ua.VariantType.Boolean)
        self._add_node_attr(node_attributes, nodedata, "Historizing", ua.VariantType.Boolean)
        self._add_node_attr(node_attributes, nodedata, "InverseName", ua.VariantType.LocalizedText)
        self._add_node_attr(node_attributes, nodedata, "IsAbstract", ua.VariantType.Boolean)
        self._add_node_attr(node_attributes, nodedata, "MinimumSamplingInterval", ua.VariantType.Double)
        self._add_node_attr(node_attributes, nodedata, "NodeClass", ua.VariantType.Int32)
        self._add_node_attr(node_attributes, nodedata, "NodeId", ua.VariantType.NodeId)
        self._add_node_attr(node_attributes, nodedata, "Symmetric", ua.VariantType.Boolean)
        self._add_node_attr(node_attributes, nodedata, "UserAccessLevel", ua.VariantType.Byte)
        self._add_node_attr(node_attributes, nodedata, "UserExecutable", ua.VariantType.Boolean)
        self._add_node_attr(node_attributes, nodedata, "UserWriteMask", ua.VariantType.Byte)
        self._add_node_attr(node_attributes, nodedata, "ValueRank", ua.VariantType.Int32)
        self._add_node_attr(node_attributes, nodedata, "WriteMask", ua.VariantType.UInt32)
        self._add_node_attr(node_attributes, nodedata, "UserWriteMask", ua.VariantType.UInt32)
        self._add_node_attr(node_attributes, nodedata, "DataTypeDefinition", ua.VariantType.ExtensionObject)
        self._add_node_attr(node_attributes, nodedata, "Value", add_timestamps=add_timestamps)


class MethodService:
    """
    This class implements the method service set defined in the opc ua standard.
    OPC 10000-4 v1.05, 5.12.1
    """

    def __init__(self, aspace: AddressSpace) -> None:
        self.logger = logging.getLogger(__name__)
        self._aspace: AddressSpace = aspace
        self._pool: ThreadPoolExecutor | None = None

    def stop(self) -> None:
        if self._pool is not None:
            self._pool.shutdown()
            self._pool = None

    async def call(self, methods: list[ua.CallMethodRequest], trusted: bool = False) -> list[ua.CallMethodResult]:
        return [await self._call(method, trusted) for method in methods]

    async def _call(self, method: ua.CallMethodRequest, trusted: bool) -> ua.CallMethodResult:
        try:
            return await self._call_checked(method, trusted)
        except ua.uaerrors.UaStatusCodeError as error:
            return ua.CallMethodResult(StatusCode=status_of_error(error))

    async def _call_checked(self, request: ua.CallMethodRequest, trusted: bool) -> ua.CallMethodResult:
        aspace = self._aspace
        object_node = aspace.node_for_service(request.ObjectId)
        if aspace.node_class_of(object_node) not in (ua.NodeClass.Object, ua.NodeClass.ObjectType):
            raise ua.uaerrors.BadNodeIdInvalid()
        method_node = aspace.node_for_service(request.MethodId)
        if aspace.node_class_of(method_node) != ua.NodeClass.Method:
            raise ua.uaerrors.BadMethodInvalid()
        if not self._owns(object_node, method_node):
            raise ua.uaerrors.BadMethodInvalid()
        if not trusted:
            self._check_executable(method_node)
        if method_node.call is None:
            raise ua.uaerrors.BadNotSupported()
        arguments = list(request.InputArguments) if request.InputArguments else []
        results = self._check_arguments(method_node, arguments)
        if any(result.is_bad() for result in results):
            return ua.CallMethodResult(
                StatusCode=ua.StatusCode(ua.StatusCodes.BadInvalidArgument), InputArgumentResults=results
            )
        try:
            outcome = await self._run_method(method_node.call, request.ObjectId, *arguments)
        except ua.uaerrors.UaStatusCodeError as error:
            return ua.CallMethodResult(StatusCode=status_of_error(error))
        except Exception:
            self.logger.exception("Error executing method call %s, an exception was raised: ", request)
            return ua.CallMethodResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadUnexpectedError))
        return self._result_of(outcome)

    @staticmethod
    def _result_of(outcome: Any) -> ua.CallMethodResult:
        if isinstance(outcome, ua.CallMethodResult):
            result = outcome
        elif isinstance(outcome, ua.StatusCode):
            result = ua.CallMethodResult(StatusCode=outcome)
        else:
            result = ua.CallMethodResult(OutputArguments=outcome if outcome is not None else [])
        if result.StatusCode.is_bad():
            result.OutputArguments = []
        else:
            result.StatusCode = ua.StatusCode(ua.StatusCodes.Good)
        return result

    def _owns(self, object_node: NodeData, method_node: NodeData) -> bool:
        aspace = self._aspace
        checker = DataTypeChecker(aspace)
        is_type = aspace.node_class_of(object_node) == ua.NodeClass.ObjectType
        sources = [object_node]
        if not is_type:
            definition = next(
                (
                    ref.NodeId
                    for ref in object_node.references
                    if ref.IsForward and ref.ReferenceTypeId == HAS_TYPE_DEFINITION
                ),
                None,
            )
            while definition is not None and len(sources) < MAX_TYPE_DEPTH:
                type_node = aspace.get(definition)
                if type_node is None:
                    break
                sources.append(type_node)
                definition = checker.parent_of(definition)
        for source in sources:
            for ref in source.references:
                if (
                    ref.IsForward
                    and ref.NodeId == method_node.nodeid
                    and checker.is_subtype(ref.ReferenceTypeId, HAS_COMPONENT)
                ):
                    return not (is_type and self._has_modelling_rule(method_node))
        return False

    @staticmethod
    def _has_modelling_rule(node: NodeData) -> bool:
        return any(ref.IsForward and ref.ReferenceTypeId == HAS_MODELLING_RULE for ref in node.references)

    def _check_executable(self, method_node: NodeData) -> None:
        executable = self._aspace.bool_attribute(method_node, ua.AttributeIds.Executable)
        if not executable:
            raise ua.uaerrors.BadNotExecutable()
        user_executable = self._aspace.bool_attribute(method_node, ua.AttributeIds.UserExecutable)
        if user_executable is False:
            raise ua.uaerrors.BadUserAccessDenied()

    def _property_value(self, node: NodeData, name: str) -> Any:
        for ref in node.references:
            if ref.IsForward and ref.ReferenceTypeId == HAS_PROPERTY and self._aspace.has_browse_name(ref.NodeId, name):
                value = self._aspace.read_attribute_value(ref.NodeId, ua.AttributeIds.Value)
                return value.Value.Value if value.Value is not None else None
        return None

    def _check_arguments(self, method_node: NodeData, arguments: list[ua.Variant]) -> list[ua.StatusCode]:
        expected = self._property_value(method_node, "InputArguments") or []
        if len(arguments) > len(expected):
            raise ua.uaerrors.BadTooManyArguments()
        optional = {
            name
            for ref in method_node.references
            if ref.IsForward and ref.ReferenceTypeId == HAS_OPTIONAL_INPUT_ARGUMENT_DESCRIPTION
            for name in [self._aspace.browse_name_text(ref.NodeId)]
        }
        if any(argument.Name not in optional for argument in expected[len(arguments) :]):
            raise ua.uaerrors.BadArgumentsMissing()
        checker = DataTypeChecker(self._aspace)
        results = [
            ua.StatusCode()
            if check_variant(
                checker,
                variant,
                argument.DataType,
                argument.ValueRank,
                list(argument.ArrayDimensions or []),
                argument.Name in optional,
            )
            else ua.StatusCode(ua.StatusCodes.BadTypeMismatch)
            for variant, argument in zip(arguments, expected)
        ]
        return results if any(result.is_bad() for result in results) else []

    async def _run_method(self, func: "Callable[..., Any]", parent: ua.NodeId, *args: Any) -> Any:
        if inspect.iscoroutinefunction(func):
            return await func(parent, *args)
        if self._pool is None:
            self._pool = ThreadPoolExecutor()
        p = partial(func, parent, *args)
        res = await asyncio.get_event_loop().run_in_executor(self._pool, p)
        return res


class AddressSpace:
    """
    The address space object stores all the nodes of the OPC-UA server and helper methods.
    The methods are thread safe

    OPC 10000-3 v1.05
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.force_server_timestamp: bool = True
        self._nodes: dict[ua.NodeId, NodeData] = {}
        self._datachange_callback_counter = 200
        self._handle_to_attribute_map: dict[int, tuple[ua.NodeId, ua.AttributeIds]] = {}
        self._default_idx = 2
        self._nodeid_counter = {0: 20000, 1: 2000}
        self._referenced_by: dict[ua.NodeId, set[ua.NodeId]] | None = None

    def __getitem__(self, nodeid: ua.NodeId) -> NodeData:
        return self._nodes.__getitem__(nodeid)

    def get(self, nodeid: ua.NodeId) -> NodeData | None:
        return self._nodes.get(
            nodeid, None
        )  # Fixme This is another behaviour than __getitem__ where an KeyError exception is thrown, right?

    def __setitem__(self, nodeid: ua.NodeId, value: NodeData) -> None:
        if self._referenced_by is not None:
            previous = self._nodes.get(nodeid)
            if previous is not None:
                self._unindex_references(self._referenced_by, nodeid, previous)
            for ref in value.references:
                self._referenced_by.setdefault(ref.NodeId, set()).add(nodeid)
        return self._nodes.__setitem__(nodeid, value)

    def __contains__(self, nodeid: ua.NodeId) -> bool:
        return self._nodes.__contains__(nodeid)

    def __delitem__(self, nodeid: ua.NodeId) -> None:
        if self._referenced_by is not None:
            self._unindex_references(self._referenced_by, nodeid, self._nodes[nodeid])
            self._referenced_by.pop(nodeid, None)
        self._nodes.__delitem__(nodeid)

    def referencing_nodes(self, nodeid: ua.NodeId) -> set[ua.NodeId]:
        """
        Return the ids of the nodes holding a reference that targets nodeid
        """
        if self._referenced_by is None:
            self._referenced_by = {}
            for source, nodedata in self._nodes.items():
                for ref in nodedata.references:
                    self._referenced_by.setdefault(ref.NodeId, set()).add(source)
        candidates = set(self._referenced_by.get(nodeid, ()))
        nodedata = self._nodes.get(nodeid)
        if nodedata is not None:
            candidates.update(ref.NodeId for ref in nodedata.references)
        return candidates

    def reference_added(self, source: ua.NodeId, target: ua.NodeId) -> None:
        if self._referenced_by is not None:
            self._referenced_by.setdefault(target, set()).add(source)

    def reference_removed(self, source: ua.NodeId, target: ua.NodeId) -> None:
        if self._referenced_by is None:
            return
        sourcedata = self._nodes.get(source)
        if sourcedata is not None and any(ref.NodeId == target for ref in sourcedata.references):
            return
        sources = self._referenced_by.get(target)
        if sources is not None:
            sources.discard(source)

    @staticmethod
    def _unindex_references(
        referenced_by: dict[ua.NodeId, set[ua.NodeId]], nodeid: ua.NodeId, nodedata: NodeData
    ) -> None:
        for ref in nodedata.references:
            sources = referenced_by.get(ref.NodeId)
            if sources is not None:
                sources.discard(nodeid)

    def generate_nodeid(self, idx: int | None = None) -> ua.NodeId:
        if idx is None:
            idx = self._default_idx
        if idx in self._nodeid_counter:
            self._nodeid_counter[idx] += 1
        else:
            # get the biggest identifier number from the existed nodes in address space
            identifier_list = sorted(  # type: ignore
                [
                    nodeid.Identifier
                    for nodeid in self._nodes.keys()
                    if nodeid.NamespaceIndex == idx
                    and nodeid.NodeIdType in (ua.NodeIdType.Numeric, ua.NodeIdType.TwoByte, ua.NodeIdType.FourByte)
                ]
            )
            if identifier_list:
                self._nodeid_counter[idx] = identifier_list[-1]
            else:
                self._nodeid_counter[idx] = 1
        nodeid = ua.NodeId(self._nodeid_counter[idx], idx)
        while True:
            if nodeid in self._nodes:
                nodeid = self.generate_nodeid(idx)
            else:
                return nodeid

    def keys(self) -> Any:
        return self._nodes.keys()

    def clear(self) -> None:
        """Delete all nodes in address space"""
        self._nodes.clear()
        self._referenced_by = None

    def dump(self, path: str | Path) -> None:
        """
        Dump address space as binary to file; note that server must be stopped for this method to work
        DO NOT DUMP AN ADDRESS SPACE WHICH IS USING A SHELF (load_aspace_shelf), ONLY CACHED NODES WILL GET DUMPED!
        """
        self.__prepare_nodes_for_dump()

        with open(path, "wb") as f:
            pickle.dump(self._nodes, f, pickle.HIGHEST_PROTOCOL)

    def __prepare_nodes_for_dump(self) -> None:
        """
        Removes unserialisable data from nodes.
        * function calls
        """
        for nodeid, ndata in self._nodes.items():
            # if the node has a reference to a method call, remove it so the object can be serialized
            if ndata.call is not None:
                self._nodes[nodeid].call = None

    def load(self, path: str | Path) -> None:
        """
        Load address space from a binary file, overwriting everything in the current address space
        """
        with open(path, "rb") as f:
            self._nodes = pickle.load(f)
        self._referenced_by = None

    def make_aspace_shelf(self, path: Path) -> None:
        """
        Make a shelf for containing the nodes from the standard address space; this is typically only done on first
        start of the server. Subsequent server starts will load the shelf, nodes are then moved to a cache
        by the LazyLoadingDict class when they are accessed. Saving data back to the shelf
        is currently NOT supported, it is only used for the default OPC UA standard address space

        Note: Intended for slow devices, such as Raspberry Pi, to greatly improve start up time
        """
        with shelve.open(str(path), "n", protocol=pickle.HIGHEST_PROTOCOL) as s:
            for nodeid, ndata in self._nodes.items():
                s[nodeid.to_string()] = ndata

    def load_aspace_shelf(self, path: Path) -> None:
        """
        Load the standard address space nodes from a python shelve via LazyLoadingDict as needed.
        The dump() method can no longer be used if the address space is being loaded from a shelf

        Note: Intended for slow devices, such as Raspberry Pi, to greatly improve start up time
        """

        class LazyLoadingDict(collections.abc.MutableMapping):
            """
            Special dict that only loads nodes as they are accessed. If a node is accessed it gets copied from the
            shelf to the cache dict. All user nodes are saved in the cache ONLY. Saving data back to the shelf
            is currently NOT supported
            """

            def __init__(self, source: shelve.Shelf) -> None:
                self.source: shelve.Shelf = source
                self.cache: dict[ua.NodeId, NodeData] = {}

            def __getitem__(self, key: ua.NodeId) -> NodeData:
                try:
                    return self.cache[key]
                except KeyError:
                    node = self.cache[key] = self.source[key.to_string()]
                    return node

            def __setitem__(self, key: ua.NodeId, value: NodeData) -> None:
                self.cache[key] = value

            def __contains__(self, key: object) -> bool:  # type: ignore[override]
                return key in self.cache or (isinstance(key, ua.NodeId) and key.to_string() in self.source)

            def __delitem__(self, key: ua.NodeId) -> None:
                del self.cache[key]

            def __iter__(self) -> "Generator[ua.NodeId, None, None]":
                return iter(self.cache.keys())

            def __len__(self) -> int:
                return len(self.cache)

        self._nodes = LazyLoadingDict(shelve.open(str(path), "r"))
        self._referenced_by = None

    def read_attribute(
        self,
        nodeid: ua.NodeId,
        attr: int,
        *,
        trusted: bool = False,
        index_range: str | None = None,
        timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both,
    ) -> ua.DataValue:
        try:
            return self._read_attribute(nodeid, attr, trusted, index_range, timestamps)
        except Exception as error:
            status = status_of_error(error)
            if status.value == ua.StatusCodes.BadInternalError:
                _logger.exception("Error while reading attribute %s of %s", attr, nodeid)
            return ua.DataValue(StatusCode=status)

    def _read_attribute(
        self, nodeid: ua.NodeId, attr: int, trusted: bool, index_range: str | None, timestamps: ua.TimestampsToReturn
    ) -> ua.DataValue:
        node = self._node_for_service(nodeid)
        attval = node.attributes.get(attr)  # type: ignore[call-overload]
        if attval is None:
            raise ua.uaerrors.BadAttributeIdInvalid()
        is_value = attr == ua.AttributeIds.Value
        if is_value and not trusted:
            self._check_readable(node)
        parsed_range = IndexRange.parse(index_range)
        stored = attval.value_callback(nodeid, ua.AttributeIds(attr)) if attval.value_callback else attval.value
        if stored is None:
            raise ua.uaerrors.BadAttributeIdInvalid()
        if is_value and self._node_class(node) == ua.NodeClass.Variable and has_no_value(stored):
            raise ua.uaerrors.BadNoValue()
        result = dataclasses.replace(stored)
        if result.StatusCode is not None and result.StatusCode.is_bad():
            result.Value = ua.Variant(None, ua.VariantType.Null)
        elif parsed_range is not None:
            if result.Value is None:
                raise ua.uaerrors.BadIndexRangeNoData()
            result.Value = parsed_range.select(result.Value)
        return self._with_timestamps(result, is_value, timestamps)

    @staticmethod
    def _with_timestamps(dv: ua.DataValue, is_value: bool, timestamps: ua.TimestampsToReturn) -> ua.DataValue:
        want_source = is_value and timestamps in (ua.TimestampsToReturn.Source, ua.TimestampsToReturn.Both)
        want_server = timestamps in (ua.TimestampsToReturn.Server, ua.TimestampsToReturn.Both)
        if not want_source:
            dv.SourceTimestamp = None
            dv.SourcePicoseconds = None
        if not want_server:
            dv.ServerTimestamp = None
            dv.ServerPicoseconds = None
        elif dv.ServerTimestamp is None:
            dv.ServerTimestamp = datetime.now(UTC)
        return dv

    def _node_for_service(self, nodeid: ua.NodeId) -> NodeData:
        if nodeid is None or nodeid.is_null():
            raise ua.uaerrors.BadNodeIdInvalid()
        node = self._nodes.get(nodeid)
        if node is None:
            raise ua.uaerrors.BadNodeIdUnknown()
        return node

    def node_id_attribute(self, node: NodeData, attr: ua.AttributeIds) -> ua.NodeId | None:
        return self._node_id_attribute(node, attr)

    def node_for_service(self, nodeid: ua.NodeId) -> NodeData:
        return self._node_for_service(nodeid)

    def node_class_of(self, node: NodeData) -> int | None:
        return self._node_class(node)

    def is_reference_type(self, nodeid: ua.NodeId) -> bool:
        node = self._nodes.get(nodeid)
        return node is not None and self._node_class(node) == ua.NodeClass.ReferenceType

    def is_symmetric(self, reference_type: ua.NodeId) -> bool:
        node = self._nodes.get(reference_type)
        return node is not None and bool(self.bool_attribute(node, ua.AttributeIds.Symmetric))

    def browse_name_of(self, node: NodeData) -> ua.QualifiedName:
        attval = node.attributes.get(ua.AttributeIds.BrowseName)
        if attval is None or attval.value is None or attval.value.Value is None:
            return ua.QualifiedName()
        return attval.value.Value.Value

    def browse_name_text(self, nodeid: ua.NodeId) -> str:
        node = self._nodes.get(nodeid)
        return (self.browse_name_of(node).Name or "") if node is not None else ""

    def has_browse_name(self, nodeid: ua.NodeId, name: str) -> bool:
        return self.browse_name_text(nodeid) == name

    def display_name_of(self, node: NodeData) -> ua.LocalizedText:
        attval = node.attributes.get(ua.AttributeIds.DisplayName)
        if attval is None or attval.value is None or attval.value.Value is None:
            return ua.LocalizedText()
        return attval.value.Value.Value

    def type_definition_of(self, node: NodeData) -> ua.NodeId:
        for ref in node.references:
            if ref.IsForward and ref.ReferenceTypeId == HAS_TYPE_DEFINITION:
                return ref.NodeId
        return ua.NodeId()

    def bool_attribute(self, node: NodeData, attr: ua.AttributeIds) -> bool | None:
        attval = node.attributes.get(attr)
        if attval is None or attval.value is None or attval.value.Value is None:
            return None
        return bool(attval.value.Value.Value)

    @staticmethod
    def _node_class(node: NodeData) -> int | None:
        attval = node.attributes.get(ua.AttributeIds.NodeClass)
        if attval is None or attval.value is None or attval.value.Value is None:
            return None
        return int(attval.value.Value.Value)

    @staticmethod
    def _uint_attribute(node: NodeData, attr: ua.AttributeIds) -> int | None:
        attval = node.attributes.get(attr)
        if attval is None or attval.value is None or attval.value.Value is None:
            return None
        value = attval.value.Value.Value
        return int(value) if isinstance(value, int) else None

    def _check_readable(self, node: NodeData) -> None:
        if self._node_class(node) != ua.NodeClass.Variable:
            return
        access = self._uint_attribute(node, ua.AttributeIds.AccessLevel)
        if access is None:
            access = 1 << ua.AccessLevel.CurrentRead
        if not ua.ua_binary.is_bit_set(access, ua.AccessLevel.CurrentRead):
            raise ua.uaerrors.BadNotReadable()
        user_access = self._uint_attribute(node, ua.AttributeIds.UserAccessLevel)
        if user_access is None:
            user_access = access
        if not ua.ua_binary.is_bit_set(user_access, ua.AccessLevel.CurrentRead):
            raise ua.uaerrors.BadUserAccessDenied()

    def read_attribute_value(self, nodeid: ua.NodeId, attr: ua.AttributeIds) -> ua.DataValue:
        node = self._nodes.get(nodeid)
        if node is None:
            dv = ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown))
            return dv
        if attr not in node.attributes:
            dv = ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadAttributeIdInvalid))
            return dv
        attval = node.attributes[attr]
        # TODO: async support by using inspect.iscoroutinefunction()
        if attval.value_callback:
            return attval.value_callback(nodeid, attr)
        if attval.value is None:
            return ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadAttributeIdInvalid))
        return attval.value

    async def write_attribute_value(
        self, nodeid: ua.NodeId, attr: ua.AttributeIds, value: ua.DataValue
    ) -> ua.StatusCode:
        return await self.write_attribute(nodeid, attr, value, trusted=True)

    async def write_attribute(
        self,
        nodeid: ua.NodeId,
        attr: int,
        value: ua.DataValue,
        *,
        trusted: bool = False,
        index_range: str | None = None,
    ) -> ua.StatusCode:
        try:
            return await self._write_attribute(nodeid, attr, value, trusted, index_range)
        except Exception as error:
            status = status_of_error(error)
            if status.value == ua.StatusCodes.BadInternalError:
                _logger.exception("Error while writing attribute %s of %s", attr, nodeid)
            return status

    async def _write_attribute(
        self, nodeid: ua.NodeId, attr: int, value: ua.DataValue, trusted: bool, index_range: str | None
    ) -> ua.StatusCode:
        node = self._node_for_service(nodeid)
        attval = node.attributes.get(attr)  # type: ignore[call-overload]
        if attval is None:
            raise ua.uaerrors.BadAttributeIdInvalid()
        attribute = ua.AttributeIds(attr)
        if not trusted:
            self._check_write_access(node, attribute)
            if attval.value_callback is not None and attval.value_setter is None:
                raise ua.uaerrors.BadNotWritable()
        parsed_range = IndexRange.parse(index_range)
        if attribute == ua.AttributeIds.Value:
            value = self._value_to_store(node, value, trusted)
        is_bad = value.StatusCode is not None and value.StatusCode.is_bad()
        if not is_bad:
            value = self._checked_variant(node, attribute, attval, value, parsed_range)
        result = ua.StatusCode()
        if attval.value_setter is not None:
            outcome = attval.value_setter(node, attribute, value)
            if inspect.isawaitable(outcome):
                outcome = await outcome
            if isinstance(outcome, ua.StatusCode):
                if outcome.is_bad():
                    return outcome
                result = outcome
        else:
            attval.value = value
            if trusted:
                attval.value_callback = None
        for handle, callback in list(attval.datachange_callbacks.items()):
            try:
                await callback(handle, value)
            except Exception:
                _logger.exception("Error calling datachange callback %s, %s", handle, callback)
        return result

    def _check_write_access(self, node: NodeData, attribute: ua.AttributeIds) -> None:
        if attribute == ua.AttributeIds.Value and self._node_class(node) == ua.NodeClass.Variable:
            access = self._uint_attribute(node, ua.AttributeIds.AccessLevel)
            if access is None or not ua.ua_binary.is_bit_set(access, ua.AccessLevel.CurrentWrite):
                raise ua.uaerrors.BadNotWritable()
            user_access = self._uint_attribute(node, ua.AttributeIds.UserAccessLevel)
            if user_access is None:
                user_access = access
            if not ua.ua_binary.is_bit_set(user_access, ua.AccessLevel.CurrentWrite):
                raise ua.uaerrors.BadUserAccessDenied()
            return
        if attribute in (ua.AttributeIds.NodeId, ua.AttributeIds.NodeClass):
            raise ua.uaerrors.BadNotWritable()
        bit_name = "ValueForVariableType" if attribute == ua.AttributeIds.Value else attribute.name
        bit = ua.WriteMask.__members__.get(bit_name)
        mask = self._uint_attribute(node, ua.AttributeIds.WriteMask)
        if bit is None or mask is None or not ua.ua_binary.is_bit_set(mask, bit):
            raise ua.uaerrors.BadNotWritable()
        user_mask = self._uint_attribute(node, ua.AttributeIds.UserWriteMask)
        if user_mask is None:
            user_mask = mask
        if not ua.ua_binary.is_bit_set(user_mask, bit):
            raise ua.uaerrors.BadUserAccessDenied()

    def _value_to_store(self, node: NodeData, value: ua.DataValue, trusted: bool) -> ua.DataValue:
        stored = dataclasses.replace(value)
        if not trusted:
            access = self._uint_attribute(node, ua.AttributeIds.AccessLevel) or 0
            if stored.StatusCode is not None and not stored.StatusCode.is_good():
                if not ua.ua_binary.is_bit_set(access, ua.AccessLevel.StatusWrite):
                    raise ua.uaerrors.BadWriteNotSupported()
            if stored.SourceTimestamp is not None or stored.ServerTimestamp is not None:
                if not ua.ua_binary.is_bit_set(access, ua.AccessLevel.TimestampWrite):
                    raise ua.uaerrors.BadWriteNotSupported()
        now = datetime.now(UTC)
        if stored.ServerTimestamp is None and self.force_server_timestamp:
            stored.ServerTimestamp = now
            stored.ServerPicoseconds = None
        if stored.SourceTimestamp is None:
            stored.SourceTimestamp = now
            stored.SourcePicoseconds = None
        if stored.StatusCode is not None and stored.StatusCode.is_bad():
            stored.Value = ua.Variant(None, ua.VariantType.Null)
        return stored

    def _checked_variant(
        self,
        node: NodeData,
        attribute: ua.AttributeIds,
        attval: AttributeValue,
        value: ua.DataValue,
        parsed_range: IndexRange | None,
    ) -> ua.DataValue:
        variant = value.Value
        if variant is None:
            raise ua.uaerrors.BadTypeMismatch()
        if parsed_range is None:
            self._check_variant_type(node, attribute, variant, whole=True)
            return value
        if attribute == ua.AttributeIds.Value:
            self._check_variant_type(node, attribute, variant, whole=False)
        current = attval.value.Value if attval.value is not None else None
        if current is None:
            raise ua.uaerrors.BadIndexRangeNoData()
        composed = parsed_range.compose(current, variant)
        if attribute != ua.AttributeIds.Value:
            self._check_variant_type(node, attribute, composed, whole=True)
        return dataclasses.replace(value, Value=composed)

    def _check_variant_type(self, node: NodeData, attribute: ua.AttributeIds, variant: ua.Variant, whole: bool) -> None:
        if attribute != ua.AttributeIds.Value:
            expected = ATTRIBUTE_TYPES.get(attribute)
            if expected is not None and (variant.VariantType, bool(variant.is_array)) != expected:
                raise ua.uaerrors.BadTypeMismatch()
            return
        datatype = self._node_id_attribute(node, ua.AttributeIds.DataType) or BASE_DATA_TYPE
        value_rank = self._int_attribute(node, ua.AttributeIds.ValueRank, ua.ValueRank.Any)
        array_dimensions = self._array_attribute(node, ua.AttributeIds.ArrayDimensions) if whole else []
        ok = check_variant(
            DataTypeChecker(self._nodes),
            variant,
            datatype,
            value_rank if whole else ua.ValueRank.Any,
            array_dimensions,
            self._allows_nulls(node),
        )
        if not ok:
            _logger.warning("Write refused: %s does not match data type %s of %s", variant, datatype, node.nodeid)
            raise ua.uaerrors.BadTypeMismatch()

    def _node_id_attribute(self, node: NodeData, attr: ua.AttributeIds) -> ua.NodeId | None:
        attval = node.attributes.get(attr)
        if attval is None or attval.value is None or attval.value.Value is None:
            return None
        value = attval.value.Value.Value
        return value if isinstance(value, ua.NodeId) else None

    def _int_attribute(self, node: NodeData, attr: ua.AttributeIds, default: int) -> int:
        value = self._uint_attribute(node, attr)
        return default if value is None else value

    def _array_attribute(self, node: NodeData, attr: ua.AttributeIds) -> list[int]:
        attval = node.attributes.get(attr)
        if attval is None or attval.value is None or attval.value.Value is None:
            return []
        value = attval.value.Value.Value
        return [int(v) for v in value] if isinstance(value, list | tuple) else []

    def _allows_nulls(self, node: NodeData) -> bool:
        for ref in node.references:
            if ref.ReferenceTypeId == HAS_PROPERTY and self.has_browse_name(ref.NodeId, "AllowNulls"):
                value = self.read_attribute_value(ref.NodeId, ua.AttributeIds.Value)
                return bool(value.Value is not None and value.Value.Value)
        return False

    def set_attribute_value_callback(
        self,
        nodeid: ua.NodeId,
        attr: ua.AttributeIds,
        callback: Callable[[ua.NodeId, ua.AttributeIds], ua.DataValue],
    ) -> ua.StatusCode:
        node = self._nodes.get(nodeid, None)
        if node is None:
            return ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)
        attval = node.attributes.get(attr, None)
        if attval is None:
            return ua.StatusCode(ua.StatusCodes.BadAttributeIdInvalid)

        attval.value = None
        attval.value_callback = callback

        # Note: It does not trigger the datachange_callbacks unlike write_attribute_value.

        return ua.StatusCode()

    def set_attribute_value_setter(
        self,
        nodeid: ua.NodeId,
        attr: ua.AttributeIds,
        setter: Callable[[NodeData, ua.AttributeIds, ua.DataValue], ua.StatusCode | Awaitable[Any] | None],
    ) -> ua.StatusCode:
        node = self._nodes.get(nodeid, None)
        if node is None:
            return ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)
        attval = node.attributes.get(attr, None)
        if attval is None:
            return ua.StatusCode(ua.StatusCodes.BadAttributeIdInvalid)
        attval.value_setter = setter
        return ua.StatusCode()

    def add_datachange_callback(
        self, nodeid: ua.NodeId, attr: ua.AttributeIds, callback: Callable
    ) -> tuple[ua.StatusCode, int]:
        # self.logger.debug("set attr callback: %s %s %s", nodeid, attr, callback)
        if nodeid not in self._nodes:
            return ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown), 0
        node = self._nodes[nodeid]
        if attr not in node.attributes:
            return ua.StatusCode(ua.StatusCodes.BadAttributeIdInvalid), 0
        attval = node.attributes[attr]
        self._datachange_callback_counter += 1
        handle = self._datachange_callback_counter
        attval.datachange_callbacks[handle] = callback
        self._handle_to_attribute_map[handle] = (nodeid, attr)
        return ua.StatusCode(), handle

    def delete_datachange_callback(self, handle: int) -> None:
        if handle in self._handle_to_attribute_map:
            nodeid, attr = self._handle_to_attribute_map.pop(handle)
            self._nodes[nodeid].attributes[attr].datachange_callbacks.pop(handle)

    def add_method_callback(self, methodid: ua.NodeId, callback: "Callable[..., Any]") -> ua.StatusCode:
        node = self._nodes[methodid]
        node.call = callback
        return ua.StatusCode()

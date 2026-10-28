"""
High level node object, to access node attribute
and browse address space
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, overload

from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession
from enginir_opcua.ua.uaerrors import UaInvalidParameterError

from .events import Event, get_filter_from_event_type
from .manage_nodes import (
    create_data_type,
    create_folder,
    create_method,
    create_object,
    create_object_type,
    create_property,
    create_reference_type,
    create_variable,
    create_variable_type,
    delete_nodes,
)
from .methods import call_method
from .ua_utils import data_type_to_variant_type, value_to_datavalue

_logger = logging.getLogger(__name__)


def _check_results(results: list[ua.StatusCode], reqlen: int = 1) -> None:
    if not len(results) == reqlen:
        raise ValueError(results)
    for r in results:
        r.check()


def _to_nodeid(nodeid: Node | ua.NodeId | str | int) -> ua.NodeId:
    if isinstance(nodeid, int):
        return ua.NodeId(nodeid)
    if isinstance(nodeid, Node):
        return nodeid.nodeid
    if isinstance(nodeid, ua.NodeId):
        return nodeid
    if isinstance(nodeid, str):
        return ua.NodeId.from_string(nodeid)
    raise ua.UaError(f"Could not resolve '{nodeid}' to a type id")


_ALL_ELEMENTS_PROCESSED = 0xFFFFFFFF
_EARLIEST_SPECIFIED_TIME = ua.get_win_epoch() + timedelta(microseconds=1)


def _history_time_domain(
    starttime: datetime | None, endtime: datetime | None, numvalues: int
) -> tuple[datetime, datetime]:
    start = starttime or ua.get_win_epoch()
    end = endtime or ua.get_win_epoch()
    given = sum((starttime is not None, endtime is not None, numvalues > 0))
    if given < 2 and endtime is None:
        end = datetime.now(UTC)
        given += 1
    if given < 2:
        start = _EARLIEST_SPECIFIED_TIME
    return start, end


class Node:
    """
    High level node object, to access node attribute,
    browse and populate address space.
    Node objects are useful as-is but they do not expose the entire
    OPC-UA protocol. Feel free to look at the code of this class and call
    directly UA services methods to optimize your code
    """

    def __init__(self, session: AbstractSession, nodeid: Node | ua.NodeId | str | int) -> None:
        self.session: AbstractSession = session
        self.nodeid: ua.NodeId
        self.basenodeid: ua.NodeId | None = None
        if isinstance(nodeid, Node):
            self.nodeid = nodeid.nodeid
        elif isinstance(nodeid, ua.NodeId):
            self.nodeid = nodeid
        elif isinstance(nodeid, str):
            self.nodeid = ua.NodeId.from_string(nodeid)
        elif isinstance(nodeid, int):
            self.nodeid = ua.NodeId(nodeid, 0)
        else:
            raise ua.UaError(
                f"argument to node must be a NodeId object or a string"
                f" defining a nodeid found {nodeid} of type {type(nodeid)}"
            )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Node) and self.nodeid == other.nodeid:
            return True
        return False

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __str__(self) -> str:
        return self.nodeid.to_string()

    def __repr__(self) -> str:
        return f"Node({self.nodeid})"

    def __hash__(self) -> int:
        return self.nodeid.__hash__()

    async def read_browse_name(self) -> ua.QualifiedName:
        """
        Get browse name of a node. A browse name is a QualifiedName object
        composed of a string(name) and a namespace index.
        """
        result = await self.read_attribute(ua.AttributeIds.BrowseName)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return result.Value.Value

    async def read_display_name(self) -> ua.LocalizedText:
        """
        get DisplayName attribute of node
        """
        result = await self.read_attribute(ua.AttributeIds.DisplayName)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return result.Value.Value

    async def read_data_type(self) -> ua.NodeId:
        """
        get data type of node as NodeId
        """
        result = await self.read_attribute(ua.AttributeIds.DataType)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return result.Value.Value

    async def read_data_type_as_variant_type(self) -> ua.VariantType:
        """
        get data type of node as VariantType
        This only works if node is a variable, otherwise type
        may not be convertible to VariantType
        """
        result = await self.read_attribute(ua.AttributeIds.DataType)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return await data_type_to_variant_type(Node(self.session, result.Value.Value))

    async def get_access_level(self) -> set[ua.AccessLevel]:
        """
        Get the access level attribute of the node as a set of AccessLevel enum values.
        """
        result = await self.read_attribute(ua.AttributeIds.AccessLevel)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return ua.AccessLevel.parse_bitfield(result.Value.Value)

    async def get_user_access_level(self) -> set[ua.AccessLevel]:
        """
        Get the user access level attribute of the node as a set of AccessLevel enum values.
        """
        result = await self.read_attribute(ua.AttributeIds.UserAccessLevel)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return ua.AccessLevel.parse_bitfield(result.Value.Value)

    async def read_event_notifier(self) -> set[ua.EventNotifier]:
        """
        Get the event notifier attribute of the node as a set of EventNotifier enum values.
        """
        result = await self.read_attribute(ua.AttributeIds.EventNotifier)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return ua.EventNotifier.parse_bitfield(result.Value.Value)

    async def set_event_notifier(self, values: Iterable[ua.EventNotifier]) -> None:
        """
        Set the event notifier attribute.

        :param values: an iterable of EventNotifier enum values.
        """
        event_notifier_bitfield = ua.EventNotifier.to_bitfield(values)
        await self.write_attribute(
            ua.AttributeIds.EventNotifier, ua.DataValue(ua.Variant(event_notifier_bitfield, ua.VariantType.Byte))
        )

    async def read_node_class(self) -> ua.NodeClass:
        """
        get node class attribute of node
        """
        result = await self.read_attribute(ua.AttributeIds.NodeClass)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return ua.NodeClass(result.Value.Value)

    async def read_data_type_definition(self) -> ua.DataTypeDefinition:
        """
        read data type definition attribute of node
        only DataType nodes following spec >= 1.04 have that attribute
        """
        result = await self.read_attribute(ua.AttributeIds.DataTypeDefinition)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return result.Value.Value

    async def write_data_type_definition(self, sdef: ua.DataTypeDefinition) -> None:
        """
        write data type definition attribute of node
        only DataType nodes following spec >= 1.04 have that attribute
        """
        v = ua.Variant(sdef, ua.VariantType.ExtensionObject)
        await self.write_attribute(ua.AttributeIds.DataTypeDefinition, ua.DataValue(v))

    async def read_description(self) -> ua.LocalizedText:
        """
        get description attribute class of node
        """
        result = await self.read_attribute(ua.AttributeIds.Description)
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return result.Value.Value

    async def read_value(self) -> Any:
        """
        Get value of a node as a python type. Only variables ( and properties) have values.
        An exception will be generated for other node types.
        WARNING: on server side, this function returns a ref to object in ua database.
        Do not modify it if it is a mutable object unless you know what you are doing
        """
        result = await self.read_data_value()
        if result.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return result.Value.Value

    get_value = read_value  # legacy compatibility

    async def read_data_value(self, raise_on_bad_status: bool = True) -> ua.DataValue:
        """
        Get value of a node as a DataValue object. Only variables (and properties) have values.
        An exception will be generated for other node types.
        DataValue contain a variable value as a variant as well as server and source timestamps
        """
        return await self.read_attribute(ua.AttributeIds.Value, None, raise_on_bad_status)

    async def write_array_dimensions(self, value: int | Iterable[int]) -> None:
        """
        Set attribute ArrayDimensions of node: the maximum length of each dimension, 0 when unknown.
        A single integer is the one-dimensional case.
        """
        dimensions = [value] if isinstance(value, int) else list(value)
        v = ua.Variant(dimensions, ua.VariantType.UInt32)
        await self.write_attribute(ua.AttributeIds.ArrayDimensions, ua.DataValue(v))

    async def read_array_dimensions(self) -> list[int]:
        """
        Read and return ArrayDimensions attribute of node
        """
        res = await self.read_attribute(ua.AttributeIds.ArrayDimensions)
        if res.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        return res.Value.Value

    async def write_value_rank(self, value: int) -> None:
        """
        Set attribute ValueRank of node
        """
        v = ua.Variant(value, ua.VariantType.Int32)
        await self.write_attribute(ua.AttributeIds.ValueRank, ua.DataValue(v))

    async def read_value_rank(self) -> int:
        """
        Read and return the ValueRank attribute of the node.
        The result is a ua.ValueRank member when there is one, else the plain integer (more than four dimensions).
        """
        res = await self.read_attribute(ua.AttributeIds.ValueRank)
        if res.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        rank = res.Value.Value
        try:
            return ua.ValueRank(rank)
        except ValueError:
            return int(rank)

    async def write_value(self, value: Any, varianttype: ua.VariantType | None = None) -> None:
        """
        Write value of a node. Only variables(properties) have values.
        An exception will be generated for other node types.
        value argument is either:
        * a python built-in type, converted to opc-ua
        optionally using the variantype argument.
        * a ua.Variant, varianttype is then ignored
        * a ua.DataValue, you then have full control over data send to server
        WARNING: On server side, ref to object is directly saved in our UA db, if this is a mutable object
        and you modify it afterward, then the object in db will be modified without any
        data change event generated
        """
        dv = value_to_datavalue(value, varianttype)
        await self.write_attribute(ua.AttributeIds.Value, dv)

    set_data_value = write_value  # legacy compatibility
    set_value = write_value  # legacy compatibility

    async def set_writable(self, writable: bool = True) -> None:
        """
        Set node as writable by clients.
        A node is always writable on server side.
        """
        if writable:
            await self.set_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.CurrentWrite)
            await self.set_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.CurrentWrite)
        else:
            await self.unset_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.CurrentWrite)
            await self.unset_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.CurrentWrite)

    async def set_attr_bit(self, attr: ua.AttributeIds, bit: ua.AccessLevel | int) -> None:
        dv = await self.read_attribute(attr)
        if dv.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        val = ua.ua_binary.set_bit(dv.Value.Value, bit)
        await self.write_attribute(attr, ua.DataValue(ua.Variant(val, dv.Value.VariantType)))

    async def unset_attr_bit(self, attr: ua.AttributeIds, bit: ua.AccessLevel | int) -> None:
        dv = await self.read_attribute(attr)
        if dv.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        val = ua.ua_binary.unset_bit(dv.Value.Value, bit)
        await self.write_attribute(attr, ua.DataValue(ua.Variant(val, dv.Value.VariantType)))

    async def set_read_only(self) -> None:
        """
        Set a node as read-only for clients.
        A node is always writable on server side.
        """
        return await self.set_writable(False)

    async def write_attribute(
        self, attributeid: ua.AttributeIds, datavalue: ua.DataValue, indexrange: str | None = None
    ) -> None:
        """
        Set an attribute of a node
        attributeid is a member of ua.AttributeIds
        datavalue is a ua.DataValue object
        indexrange is a NumericRange (a string; e.g. "1" or "1:3".
            See OPC 10000-4 v1.05, 7.27)
        """
        attr = ua.WriteValue()
        attr.NodeId = self.nodeid
        attr.AttributeId = attributeid
        attr.Value = datavalue
        attr.IndexRange = indexrange
        params = ua.WriteParameters()
        params.NodesToWrite = [attr]
        result = await self.session.write(params)
        result[0].check()

    async def write_params(self, params: ua.WriteParameters) -> list[ua.StatusCode]:
        result = await self.session.write(params)
        return result

    async def read_attribute(
        self, attr: ua.AttributeIds, indexrange: str | None = None, raise_on_bad_status: bool = True
    ) -> ua.DataValue:
        """
        Read one attribute of a node
        attributeid is a member of ua.AttributeIds
        indexrange is a NumericRange (a string; e.g. "1" or "1:3".
        result code from server is checked and an exception is raised in case of error
        """
        rv = ua.ReadValueId()
        rv.NodeId = self.nodeid
        rv.AttributeId = attr
        rv.IndexRange = indexrange
        params = ua.ReadParameters()
        params.NodesToRead.append(rv)
        result = await self.session.read(params)
        res = result[0]
        if res.StatusCode is None:
            raise ua.UaError("No status code received")
        if raise_on_bad_status:
            res.StatusCode.check()
        return res

    async def read_attributes(self, attrs: Iterable[ua.AttributeIds]) -> list[ua.DataValue]:
        """
        Read several attributes of a node
        list of DataValue is returned
        """
        params = ua.ReadParameters()
        for attr in attrs:
            rv = ua.ReadValueId()
            rv.NodeId = self.nodeid
            rv.AttributeId = attr
            params.NodesToRead.append(rv)

        results = await self.session.read(params)
        return results

    async def read_params(self, params: ua.ReadParameters) -> list[ua.DataValue]:
        result = await self.session.read(params)
        return result

    async def get_children(
        self,
        refs: Node | ua.NodeId | str | int = ua.ObjectIds.HierarchicalReferences,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
    ) -> list[Node]:
        """
        Get all children of a node. By default hierarchical references and all node classes are returned.
        Other reference types may be given:
        References = 31
        NonHierarchicalReferences = 32
        HierarchicalReferences = 33
        HasChild = 34
        Organizes = 35
        HasEventSource = 36
        HasModellingRule = 37
        HasEncoding = 38
        HasDescription = 39
        HasTypeDefinition = 40
        GeneratesEvent = 41
        Aggregates = 44
        HasSubtype = 45
        HasProperty = 46
        HasComponent = 47
        HasNotifier = 48
        HasOrderedComponent = 49
        """
        return await self.get_referenced_nodes(refs, ua.BrowseDirection.Forward, nodeclassmask)

    async def get_properties(self) -> list[Node]:
        """
        return properties of node.
        properties are child nodes with a reference of type HasProperty and a NodeClass of Variable
        COROUTINE
        """
        return await self.get_children(refs=ua.ObjectIds.HasProperty, nodeclassmask=ua.NodeClass.Variable)

    async def get_variables(self) -> list[Node]:
        """
        return variables of node.
        variables are child nodes with a reference of type HasComponent and a NodeClass of Variable
        """
        return await self.get_children(refs=ua.ObjectIds.HasComponent, nodeclassmask=ua.NodeClass.Variable)

    async def get_methods(self) -> list[Node]:
        """
        return methods of node.
        methods are child nodes with a reference of type HasComponent and a NodeClass of Method
        """
        return await self.get_children(refs=ua.ObjectIds.HasComponent, nodeclassmask=ua.NodeClass.Method)

    async def get_children_descriptions(
        self,
        refs: int = ua.ObjectIds.HierarchicalReferences,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
        result_mask: ua.BrowseResultMask = ua.BrowseResultMask.All,
    ) -> list[ua.ReferenceDescription]:
        return await self.get_references(refs, ua.BrowseDirection.Forward, nodeclassmask, includesubtypes, result_mask)

    async def get_encoding_refs(self) -> list[Node]:
        return await self.get_referenced_nodes(ua.ObjectIds.HasEncoding, ua.BrowseDirection.Forward)

    async def get_description_refs(self) -> list[Node]:
        return await self.get_referenced_nodes(ua.ObjectIds.HasDescription, ua.BrowseDirection.Forward)

    async def get_references(
        self,
        refs: Node | ua.NodeId | str | int = ua.ObjectIds.References,
        direction: ua.BrowseDirection = ua.BrowseDirection.Both,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
        result_mask: ua.BrowseResultMask = ua.BrowseResultMask.All,
    ) -> list[ua.ReferenceDescription]:
        """
        returns references of the node based on specific filter defined with:

        refs = ObjectId of the Reference
        direction = Browse direction for references
        nodeclassmask = filter nodes based on specific class
        includesubtypes = If true subtypes of the reference (ref) are also included
        result_mask = define what results information are requested
        """
        desc = ua.BrowseDescription()
        desc.BrowseDirection = direction
        desc.ReferenceTypeId = _to_nodeid(refs)
        desc.IncludeSubtypes = includesubtypes
        desc.NodeClassMask = nodeclassmask
        desc.ResultMask = result_mask
        desc.NodeId = self.nodeid
        params = ua.BrowseParameters()
        params.View.Timestamp = ua.get_win_epoch()
        params.NodesToBrowse.append(desc)
        params.RequestedMaxReferencesPerNode = 0
        results = await self.session.browse(params)
        references = await self._browse_next(results)
        return references

    async def _browse_next(self, results: list[ua.BrowseResult]) -> list[ua.ReferenceDescription]:
        if not results:
            raise ua.UaError("The server returned no BrowseResult")
        result = results[0]
        result.StatusCode.check()
        references = list(result.References)
        point = result.ContinuationPoint
        while point:
            try:
                params = ua.BrowseNextParameters()
                params.ContinuationPoints = [point]
                params.ReleaseContinuationPoints = False
                next_results = await self.session.browse_next(params)
                if not next_results:
                    raise ua.UaError("The server returned no BrowseResult for BrowseNext")
                result = next_results[0]
                result.StatusCode.check()
            except BaseException:
                await self._release_browse_point(point)
                raise
            references.extend(result.References)
            if result.ContinuationPoint == point and not result.References:
                await self._release_browse_point(point)
                break
            point = result.ContinuationPoint
        return references

    async def _release_browse_point(self, point: bytes) -> None:
        params = ua.BrowseNextParameters()
        params.ContinuationPoints = [point]
        params.ReleaseContinuationPoints = True
        try:
            await self.session.browse_next(params)
        except Exception:
            _logger.debug("Could not release the browse continuation point", exc_info=True)

    async def get_referenced_nodes(
        self,
        refs: Node | ua.NodeId | str | int = ua.ObjectIds.References,
        direction: ua.BrowseDirection = ua.BrowseDirection.Both,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
    ) -> list[Node]:
        """
        returns referenced nodes based on specific filter
        Parameters are the same as for get_references

        """
        references = await self.get_references(refs, direction, nodeclassmask, includesubtypes)
        nodes = []
        for desc in references:
            node = Node(self.session, desc.NodeId)
            nodes.append(node)
        return nodes

    async def read_type_definition(self) -> ua.NodeId | None:
        """
        returns type definition of the node.
        """
        references = await self.get_references(
            refs=ua.ObjectIds.HasTypeDefinition, direction=ua.BrowseDirection.Forward
        )
        if len(references) == 0:
            return None
        return references[0].NodeId

    @overload
    async def get_path(self, max_length: int = 20, as_string: Literal[False] = False) -> list[Node]: ...

    @overload
    async def get_path(self, max_length: int = 20, as_string: Literal[True] = True) -> list[str]: ...

    async def get_path(self, max_length: int = 20, as_string: bool = False) -> list[Node] | list[str]:
        """
        Find one path from the Root to this node and return it as a list of Nodes, the Root side first and
        this node last, so the list is never empty. The walk follows the first inverse hierarchical reference
        of each node, so the path starts at the Root only if every node on the way has such a reference.
        Since the address space may have circular references, a max length is specified.
        """
        path = await self._get_path(max_length)
        nodes = [Node(self.session, ref.NodeId) for ref in path]
        nodes.append(self)
        if as_string:
            return [(await el.read_browse_name()).to_string() for el in nodes]
        return nodes

    async def _get_path(self, max_length: int = 20) -> list[ua.ReferenceDescription]:
        """
        References of the walk from the farthest ancestor to the parent of this node, see get_path.
        """
        path = []
        node = self
        while True:
            refs = await node.get_references(
                refs=ua.ObjectIds.HierarchicalReferences, direction=ua.BrowseDirection.Inverse
            )
            if len(refs) > 0:
                path.insert(0, refs[0])
                node = Node(self.session, refs[0].NodeId)
                if len(path) >= (max_length - 1):
                    return path
            else:
                return path

    async def get_parent(self) -> Node | None:
        """
        returns parent of the node.
        A Node may have several parents, the first found is returned.
        This method uses reverse references, a node might be missing such a link,
        thus we will not find its parent.
        """
        refs = await self.get_references(refs=ua.ObjectIds.HierarchicalReferences, direction=ua.BrowseDirection.Inverse)
        if len(refs) > 0:
            return Node(self.session, refs[0].NodeId)
        return None

    @overload
    async def get_child(
        self,
        path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str],
        return_all: Literal[False] = False,
    ) -> Node: ...

    @overload
    async def get_child(
        self,
        path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str],
        return_all: Literal[True] = True,
    ) -> list[Node]: ...

    async def get_child(
        self, path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str], return_all: bool = False
    ) -> Node | list[Node]:
        """
        get a child specified by its path from this node.
        A path might be:
        * a string representing a relative path as per UA spec
        * a qualified name
        * a list of string representing browsenames (legacy)
        * a list of qualified names
        """
        if isinstance(path, str):
            rpath = ua.RelativePath.from_string(path)
        else:
            if isinstance(path, ua.QualifiedName):
                path = [path]
            rpath = self._make_relative_path(path)
        bpath = ua.BrowsePath()
        bpath.StartingNode = self.nodeid
        bpath.RelativePath = rpath
        results = await self.session.translate_browsepaths_to_nodeids([bpath])
        result = results[0]
        targets = self._complete_targets(result)
        if not targets:
            ua.StatusCode(ua.StatusCodes.BadNoMatch).check()
        if return_all:
            return [Node(self.session, target.TargetId) for target in targets]
        return Node(self.session, targets[0].TargetId)

    @staticmethod
    def _complete_targets(result: ua.BrowsePathResult) -> list[ua.BrowsePathTarget]:
        result.StatusCode.check()
        return [target for target in result.Targets if target.RemainingPathIndex == _ALL_ELEMENTS_PROCESSED]

    async def get_children_by_path(
        self,
        paths: Iterable[ua.QualifiedName | str | Iterable[ua.QualifiedName | str]],
        raise_on_partial_error: bool = True,
    ) -> list[list[Node] | None]:
        """
        get children specified by their paths from this node.
        A path that does not resolve completely gives None at its position, or raises UaStatusCodeErrors.
        A path might be:
        * a string representing a relative path as per UA spec
        * a qualified name
        * a list of string representing browsenames (legacy)
        * a list of qualified names
        """
        bpaths: list[ua.BrowsePath] = []
        for path in paths:
            if isinstance(path, str):
                rpath = ua.RelativePath.from_string(path)
            else:
                if isinstance(path, ua.QualifiedName | str):
                    path = [path]
                rpath = self._make_relative_path(path)
            bpath = ua.BrowsePath()
            bpath.StartingNode = self.nodeid
            bpath.RelativePath = rpath
            bpaths.append(bpath)

        results = await self.session.translate_browsepaths_to_nodeids(bpaths)
        found: list[list[Node] | None] = []
        codes: list[int] = []
        for result in results:
            if result.StatusCode.is_good():
                targets = [t for t in result.Targets if t.RemainingPathIndex == _ALL_ELEMENTS_PROCESSED]
            else:
                targets = []
            if targets:
                found.append([Node(self.session, target.TargetId) for target in targets])
                codes.append(ua.StatusCodes.Good)
            else:
                found.append(None)
                codes.append(ua.StatusCodes.BadNoMatch if result.StatusCode.is_good() else result.StatusCode.value)
        if raise_on_partial_error and any(code != ua.StatusCodes.Good for code in codes):
            raise ua.UaStatusCodeErrors(codes)
        return found

    def _make_relative_path(self, path: Iterable[ua.QualifiedName | str]) -> ua.RelativePath:
        rpath = ua.RelativePath()
        for item in path:
            el = ua.RelativePathElement()
            el.ReferenceTypeId = ua.TwoByteNodeId(ua.ObjectIds.HierarchicalReferences)
            el.IsInverse = False
            el.IncludeSubtypes = True
            if isinstance(item, ua.QualifiedName):
                el.TargetName = item
            else:
                el.TargetName = ua.QualifiedName.from_string(item)
            rpath.Elements.append(el)
        return rpath

    async def read_raw_history(
        self,
        starttime: datetime | None = None,
        endtime: datetime | None = None,
        numvalues: int = 0,
        return_bounds: bool = False,
    ) -> list[ua.DataValue]:
        """
        Read raw history of a node, following the continuation points until the server has no more values.
        The result code of every response is checked and an exception is raised in case of error.
        numvalues is the most values returned in total, 0 means all. A continuation point still open
        when the read stops is released.
        """
        details = ua.ReadRawModifiedDetails()
        details.IsReadModified = False
        details.StartTime, details.EndTime = _history_time_domain(starttime, endtime, numvalues)
        details.NumValuesPerNode = numvalues
        details.ReturnBounds = return_bounds
        history: list[ua.DataValue] = []

        def collect(result: ua.HistoryReadResult) -> int:
            values = result.HistoryData.DataValues  # type: ignore[attr-defined]
            history.extend(values)
            return len(history)

        await self._read_history_pages(self.history_read, details, collect, numvalues)
        return history[:numvalues] if numvalues > 0 else history

    async def _read_history_pages(self, read: Any, details: Any, collect: Any, numvalues: int) -> None:
        point: bytes | None = None
        try:
            while True:
                result = await read(details, point)
                result.StatusCode.check()
                previous = point
                point = result.ContinuationPoint or None
                count = collect(result)
                if point is None or point == previous or (numvalues > 0 and count >= numvalues):
                    break
        except BaseException:
            if point is not None:
                await self._release_history_point(read, details, point)
            raise
        if point is not None:
            await self._release_history_point(read, details, point)

    async def _release_history_point(self, read: Any, details: Any, point: bytes) -> None:
        try:
            await read(details, point, True)
        except Exception:
            _logger.debug("Could not release the history continuation point", exc_info=True)

    async def history_read(
        self,
        details: ua.ReadRawModifiedDetails,
        continuation_point: bytes | None = None,
        release_continuation_point: bool = False,
    ) -> ua.HistoryReadResult:
        """
        Read raw history of a node, low-level function: one HistoryRead request.
        The result is returned as it is; the caller checks its StatusCode.
        With release_continuation_point the given continuation point is freed in the server.
        """
        valueid = ua.HistoryReadValueId()
        valueid.NodeId = self.nodeid
        valueid.IndexRange = ""
        valueid.ContinuationPoint = continuation_point
        params = ua.HistoryReadParameters()
        params.HistoryReadDetails = details
        params.TimestampsToReturn = ua.TimestampsToReturn.Both
        params.ReleaseContinuationPoints = release_continuation_point
        params.NodesToRead.append(valueid)
        return (await self.session.history_read(params))[0]

    async def history_update(self, details: ua.HistoryUpdateDetails) -> ua.HistoryUpdateResult:
        """
        Update history of a node, low-level function.
        An exception is raised for a Bad StatusCode of the result or of any of its operation results.
        """
        params = ua.HistoryUpdateParameters()
        params.HistoryUpdateDetails.append(details)
        result = (await self.session.history_update(params))[0]
        result.StatusCode.check()
        for operation_result in result.OperationResults or []:
            operation_result.check()
        return result

    async def read_event_history(
        self,
        starttime: datetime | None = None,
        endtime: datetime | None = None,
        numvalues: int = 0,
        evtypes: Node | ua.NodeId | str | int | Iterable[Node | ua.NodeId | str | int] = ua.ObjectIds.BaseEventType,
    ) -> list[Event]:
        """
        Read event history of a source node, following the continuation points until the server has no more events.
        The result code of every response is checked and an exception is raised in case of error.
        numvalues is the most events returned in total, 0 means all. A continuation point still open
        when the read stops is released.
        """
        details = ua.ReadEventDetails()
        details.StartTime, details.EndTime = _history_time_domain(starttime, endtime, numvalues)
        details.NumValuesPerNode = numvalues
        if isinstance(evtypes, Node | ua.NodeId | str | int):
            evtypes = [evtypes]
        evtype_nodes = [Node(self.session, evtype) for evtype in evtypes]
        evfilter = await get_filter_from_event_type(evtype_nodes)
        details.Filter = evfilter
        event_res: list[Event] = []

        def collect(result: ua.HistoryReadResult) -> int:
            for res in result.HistoryData.Events:  # type: ignore[attr-defined]
                event_res.append(Event.from_event_fields(evfilter.SelectClauses, res.EventFields))
            return len(event_res)

        await self._read_history_pages(self.history_read_events, details, collect, numvalues)
        return event_res[:numvalues] if numvalues > 0 else event_res

    async def history_read_events(
        self,
        details: ua.ReadEventDetails,
        continuation_point: bytes | None = None,
        release_continuation_point: bool = False,
    ) -> ua.HistoryReadResult:
        """
        Read event history of a node, low-level function: one HistoryRead request.
        The result is returned as it is; the caller checks its StatusCode.
        """
        return await self.history_read(details, continuation_point, release_continuation_point)  # type: ignore[arg-type]

    async def delete(self, delete_references: bool = True, recursive: bool = False) -> list[Node]:
        """
        Delete node from address space
        """
        nodes, results = await delete_nodes(self.session, [self], recursive, delete_references)
        for r in results:
            r.check()
        return nodes

    def _fill_delete_reference_item(
        self, rdesc: ua.ReferenceDescription, bidirectional: bool = False
    ) -> ua.DeleteReferencesItem:
        ditem = ua.DeleteReferencesItem()
        ditem.SourceNodeId = self.nodeid
        ditem.TargetNodeId = rdesc.NodeId
        ditem.ReferenceTypeId = rdesc.ReferenceTypeId
        ditem.IsForward = rdesc.IsForward
        ditem.DeleteBidirectional = bidirectional
        return ditem

    async def delete_reference(
        self,
        target: Node | ua.NodeId | str | int,
        reftype: Node | ua.NodeId | str | int,
        forward: bool = True,
        bidirectional: bool = True,
    ) -> None:
        """
        Delete given node's references from address space
        """
        known_refs = await self.get_references(reftype, includesubtypes=False)
        targetid = _to_nodeid(target)
        for r in known_refs:
            if r.NodeId == targetid and r.IsForward == forward:
                rdesc = r
                break
        else:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadNotFound)
        ditem = self._fill_delete_reference_item(rdesc, bidirectional)
        (await self.session.delete_references([ditem]))[0].check()

    async def add_reference(
        self,
        target: Node | ua.NodeId | str | int,
        reftype: Node | ua.NodeId | str | int,
        forward: bool = True,
        bidirectional: bool = True,
        target_class: ua.NodeClass | None = None,
    ) -> None:
        """
        Add reference to node. The NodeClass of the target is part of the request;
        it is read from the target when not given, and left unspecified if it cannot be read.
        """
        aitem = ua.AddReferencesItem()
        aitem.SourceNodeId = self.nodeid
        aitem.TargetNodeId = _to_nodeid(target)
        aitem.ReferenceTypeId = _to_nodeid(reftype)
        aitem.IsForward = forward
        if target_class is None:
            try:
                target_class = await Node(self.session, aitem.TargetNodeId).read_node_class()
            except (ua.UaError, ValueError):
                target_class = ua.NodeClass.Unspecified
        aitem.TargetNodeClass = target_class
        params = [aitem]
        if bidirectional:
            aitem2 = ua.AddReferencesItem()
            aitem2.SourceNodeId = aitem.TargetNodeId
            aitem2.TargetNodeId = aitem.SourceNodeId
            aitem2.ReferenceTypeId = aitem.ReferenceTypeId
            aitem2.IsForward = not forward
            aitem2.TargetNodeClass = await self._own_node_class()
            params.append(aitem2)
        results = await self.session.add_references(params)
        _check_results(results, len(params))

    async def _own_node_class(self) -> ua.NodeClass:
        try:
            return await self.read_node_class()
        except (ua.UaError, ValueError):
            return ua.NodeClass.Unspecified

    async def set_modelling_rule(self, mandatory: bool | None) -> None:
        """
        Add a modelling rule reference to Node.
        When creating a new object type, its variable and child nodes will not
        be instantiated if they do not have modelling rule
        if mandatory is None, the modelling rule is removed
        """
        # remove all existing modelling rule
        rules = await self.get_references(ua.ObjectIds.HasModellingRule)
        if rules:
            results = await self.session.delete_references(list(map(self._fill_delete_reference_item, rules)))
            for result in results:
                result.check()
        # add new modelling rule as requested
        if mandatory is not None:
            rule = ua.ObjectIds.ModellingRule_Mandatory if mandatory else ua.ObjectIds.ModellingRule_Optional
            await self.add_reference(rule, ua.ObjectIds.HasModellingRule, True, False, ua.NodeClass.Object)

    async def add_folder(self, nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str) -> Node:
        return await create_folder(self, nodeid, bname)

    async def add_object(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        objecttype: ua.NodeId | int | None = None,
        instantiate_optional: bool = True,
    ) -> Node:
        return await create_object(self, nodeid, bname, objecttype, instantiate_optional)

    async def add_variable(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        val: Any,
        varianttype: ua.VariantType | None = None,
        datatype: ua.NodeId | int | None = None,
    ) -> Node:
        return await create_variable(self, nodeid, bname, val, varianttype, datatype)

    async def add_object_type(
        self, nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str, is_abstract: bool = False
    ) -> Node:
        return await create_object_type(self, nodeid, bname, is_abstract)

    async def add_variable_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        datatype: ua.NodeId | int,
        is_abstract: bool = False,
    ) -> Node:
        return await create_variable_type(self, nodeid, bname, datatype, is_abstract)

    async def add_data_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        description: str | None = None,
        is_abstract: bool = False,
    ) -> Node:
        return await create_data_type(self, nodeid, bname, description=description, is_abstract=is_abstract)

    async def add_property(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        val: Any,
        varianttype: ua.VariantType | None = None,
        datatype: ua.NodeId | int | None = None,
    ) -> Node:
        return await create_property(self, nodeid, bname, val, varianttype, datatype)

    async def add_method(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        callback: Callable[..., Any] | None = None,
        inputs: list[Any] | None = None,
        outputs: list[Any] | None = None,
    ) -> Node:
        return await create_method(self, nodeid, bname, callback, inputs, outputs)

    async def add_reference_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        symmetric: bool = True,
        inversename: str | None = None,
    ) -> Node:
        return await create_reference_type(self, nodeid, bname, symmetric, inversename)

    async def call_method(
        self, methodid: ua.NodeId | ua.QualifiedName | str, *args: Any, timeout: float | None = None
    ) -> Any:
        return await call_method(self, methodid, *args, timeout=timeout)

    async def register(self) -> None:
        """
        Register node for faster read and write access (if supported by server)
        Rmw: This call modifies the nodeid of the node, the original nodeid is
        available as node.basenodeid
        """
        nodeid = (await self.session.register_nodes([self.nodeid]))[0]
        self.basenodeid = self.nodeid
        self.nodeid = nodeid

    async def unregister(self) -> None:
        if self.basenodeid is None:
            return
        await self.session.unregister_nodes([self.nodeid])
        self.nodeid = self.basenodeid
        self.basenodeid = None

    @staticmethod
    def new_node(session: AbstractSession, nodeid: ua.NodeId) -> Node:
        """
        Helper function to init nodes with out importing Node
        """
        return Node(session, nodeid)

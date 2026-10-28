"""
Links PubSub received DataSets to the AddressSpace (OPC 10000-14 v1.05, 6.2.10, 6.2.11.1)
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import replace
from typing import TYPE_CHECKING

from ..common.node import Node
from ..ua import SubscribedDataSetMirrorDataType, TargetVariablesDataType
from ..ua.attribute_ids import AttributeIds
from ..ua.numeric_range import IndexRange
from ..ua.status_codes import StatusCodes
from ..ua.ua_binary import is_bit_set
from ..ua.uaerrors import UaError
from ..ua.uaprotocol_auto import (
    AccessLevel,
    FieldMetaData,
    FieldTargetDataType,
    OverrideValueHandling,
    PubSubState,
)
from ..ua.uatypes import (
    DataValue,
    Int16,
    Int32,
    NodeId,
    StatusCode,
    UInt32,
    Variant,
    VariantType,
)
from .dataset import DataSetField, DataSetMeta, DataSetValue

if TYPE_CHECKING:
    from .. import Server

logger = logging.getLogger(__name__)


class SubscribedDataSetMirror:
    """Mirrors the fields of a DataSet as Variables below a parent node (Part 14, 6.2.10.3): the Variables are
    created once, the first time the reader is Operational, and are updated with every DataSetMessage"""

    def __init__(self, cfg: SubscribedDataSetMirrorDataType, node: Node | None):
        self._cfg = cfg
        self._parent = node
        self._node: Node | None = None
        self._nodes: dict[object, Node] = {}
        self._warned = False

    async def _create_and_set_node(self, f: FieldMetaData) -> Node:
        if self._node is None:
            raise RuntimeError("SubscribedDataSetMirror._node is not initialized")
        n = await self._node.add_variable(
            NodeId(NamespaceIndex=Int16(1)), "1:" + str(f.Name), Variant(), datatype=f.DataType
        )
        await n.write_attribute(AttributeIds.Description, DataValue(Variant(f.Description, VariantType.LocalizedText)))
        await n.write_attribute(AttributeIds.ValueRank, DataValue(Variant(Int32(f.ValueRank), VariantType.Int32)))
        if f.ArrayDimensions:
            await n.write_attribute(
                AttributeIds.ArrayDimensions,
                DataValue(Variant([UInt32(d) for d in f.ArrayDimensions], VariantType.UInt32, is_array=True)),
            )
        return n

    async def _create_nodes(self, meta: DataSetMeta) -> bool:
        if self._parent is None:
            if not self._warned:
                self._warned = True
                logger.warning("SubscribedDataSetMirror has no parent node, the address space isn't mirrored")
            return False
        if self._node is None:
            self._node = await self._parent.add_object(
                NodeId(NamespaceIndex=Int16(1)),
                bname="1:" + str(self._cfg.ParentNodeName),
            )
        for f in meta.get_config().Fields:
            if f.DataSetFieldId not in self._nodes:
                self._nodes[f.DataSetFieldId] = await self._create_and_set_node(f)
        return True

    async def on_state_change(self, meta: DataSetMeta, state: PubSubState) -> None:
        """Called when a DataSet state changes"""
        if state == PubSubState.Operational:
            await self._create_nodes(meta)

    async def on_dataset_received(self, meta: DataSetMeta, fields: list[DataSetValue]) -> None:
        """Called when a published dataset received an update"""
        if not await self._create_nodes(meta):
            return
        for field in fields:
            node = self._nodes.get(field.Meta.DataSetFieldId)
            if node is not None:
                await node.write_attribute(AttributeIds.Value, field.Value)

    def get_subscribed_dataset(self) -> SubscribedDataSetMirrorDataType:
        return self._cfg


class FieldTargets:
    def __init__(self, cfg: FieldTargetDataType):
        self._cfg = cfg

    @classmethod
    def createTarget(
        cls,
        field: DataSetField,
        nodeid: NodeId,
        override_handling: OverrideValueHandling = OverrideValueHandling.Disabled,
        override_value: Variant | None = None,
    ):
        """
        Helper to create a target from a DataSetField and an NodeId
        """
        cfg = FieldTargetDataType(
            DataSetFieldId=field.DataSetFieldId,
            TargetNodeId=nodeid,
            AttributeId=AttributeIds.Value,
            OverrideValueHandling=override_handling,
        )
        if override_value is not None:
            cfg.OverrideValue = override_value
        return cls(cfg)


class SubScribedTargetVariables:
    """Maps the values to targeted variables in the AddressSpace"""

    def __init__(self, server: Server, cfg: TargetVariablesDataType | list[FieldTargets]):
        if isinstance(cfg, TargetVariablesDataType):
            self._cfg = cfg
            self._fields = [FieldTargets(f) for f in cfg.TargetVariables]
        else:
            self._cfg = TargetVariablesDataType([f._cfg for f in cfg])
            self._fields = cfg
        self.server = server
        self.nodes: dict[object, tuple[Node, FieldTargets]] = {}
        self.counters: Counter[str] = Counter()
        self._warned: set[str] = set()
        self._build_nodes()

    def _build_nodes(self) -> None:
        self.nodes = {f._cfg.DataSetFieldId: (self.server.get_node(f._cfg.TargetNodeId), f) for f in self._fields}

    def _warn_once(self, key: str, message: str, *args: object) -> None:
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(message, *args)

    async def _writable(self, node: Node) -> bool:
        """Part 4, 5.10.4: whether the AccessLevel of the target allows writing the value"""
        access = await node.read_attribute(AttributeIds.AccessLevel, raise_on_bad_status=False)
        level = access.Value.Value if access.Value is not None else None
        return isinstance(level, int) and is_bit_set(level, AccessLevel.CurrentWrite)

    async def _write(self, node: Node, target: FieldTargets, value: DataValue) -> None:
        attribute = AttributeIds(target._cfg.AttributeId or AttributeIds.Value)
        if attribute == AttributeIds.Value:
            if not await self._writable(node):
                self.counters["refused writes"] += 1
                self._warn_once(
                    f"refused {node.nodeid}",
                    "Not writing to %s: its AccessLevel doesn't allow writing the value",
                    node.nodeid,
                )
                return
            await node.write_attribute(attribute, value, indexrange=target._cfg.WriteIndexRange or None)
            return
        await node.write_attribute(attribute, DataValue(value.Value))

    async def _last_value(self, node: Node) -> Variant:
        current = await node.read_data_value(raise_on_bad_status=False)
        return current.Value if current.Value is not None else Variant()

    async def _substitute(self, node: Node, target: FieldTargets, status: StatusCode) -> DataValue:
        """The value and status the target gets for a Bad field or for a reader that has no data (Table 80)"""
        handling = target._cfg.OverrideValueHandling
        if handling == OverrideValueHandling.OverrideValue:
            return DataValue(target._cfg.OverrideValue, StatusCode(UInt32(StatusCodes.GoodLocalOverride)))
        if handling == OverrideValueHandling.LastUsableValue:
            return DataValue(await self._last_value(node), StatusCode(UInt32(StatusCodes.UncertainLastUsableValue)))
        return DataValue(Variant(), status)

    async def on_dataset_received(self, meta: DataSetMeta, fields: list[DataSetValue]) -> None:
        """Called when a published dataset received an update"""
        for field in fields:
            entry = self.nodes.get(field.Meta.DataSetFieldId)
            if entry is None:
                self.counters["unmapped fields"] += 1
                self._warn_once(
                    f"unmapped {field.Name}", "DataSet field %s has no target, its values are dropped", field.Name
                )
                continue
            node, target = entry
            try:
                status = field.Value.StatusCode
                if status is not None and status.is_bad():
                    logger.info("Error field %s value with %s", field.Name, field.Value)
                    await self._write(node, target, await self._substitute(node, target, status))
                    continue
                value = field.Value
                receiver_range = IndexRange.parse(target._cfg.ReceiverIndexRange)
                if receiver_range is not None and value.Value is not None:
                    value = replace(value, Value=receiver_range.select(value.Value))
                await self._write(node, target, value)
            except UaError as error:
                self.counters["write errors"] += 1
                logger.warning("Field %s was not written to its target: %s", field.Name, error)

    async def on_state_change(self, meta: DataSetMeta, state: PubSubState) -> None:
        """Called when a DataSet state changes; leaving Operational updates the targets once (Table 80)"""
        if state == PubSubState.Operational:
            self._build_nodes()
            return
        if state == PubSubState.Error:
            status = StatusCode(UInt32(StatusCodes.BadNoCommunication))
        elif state in (PubSubState.Disabled, PubSubState.Paused):
            status = StatusCode(UInt32(StatusCodes.BadOutOfService))
        else:
            return
        for node, target in self.nodes.values():
            try:
                await self._write(node, target, await self._substitute(node, target, status))
            except Exception:
                logger.debug("Couldn't update the target %s for the state %s", node.nodeid, state.name, exc_info=True)

    def get_subscribed_dataset(self) -> TargetVariablesDataType:
        return self._cfg

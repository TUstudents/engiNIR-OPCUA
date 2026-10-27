from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Any

from ..common.methods import uamethod
from ..common.node import Node
from ..ua.status_codes import StatusCodes
from ..ua.uaerrors import UaStatusCodeError
from ..ua.uaprotocol_auto import PubSubState
from ..ua.uatypes import DataValue, QualifiedName, String, Variant, VariantType

if TYPE_CHECKING:
    from ..server import Server


async def write_typed(node: Node, value: Any) -> None:
    """Writes a value as the DataType the node declares, so a plain Python number or enum is stored with its UA type"""
    variant = value.Value if isinstance(value, DataValue) else value
    if not isinstance(variant, Variant):
        variant = Variant(variant)
    if variant.VariantType != VariantType.Null:
        declared = await node.read_data_type_as_variant_type()
        if declared not in (VariantType.ExtensionObject, VariantType.Null) and variant.VariantType != declared:
            if variant.is_array:
                items = [int(item) if isinstance(item, IntEnum) else item for item in variant.Value]
            else:
                items = int(variant.Value) if isinstance(variant.Value, IntEnum) else variant.Value
            variant = Variant(items, declared, is_array=variant.is_array)
    await node.write_value(DataValue(variant))


class PubSubInformationModel:
    """
    Wraps some helper for PubSubObjects in the AddressSpace.
    If used without node it provides fallbacks.
    Also the class handles the state of the  pubsub component (PubSubState)
    """

    def __init__(self, has_state: bool = True) -> None:
        self._node = None
        self._state_node = None
        self.__state_fallback = PubSubState.Disabled
        self._has_state = has_state

    def model_is_init(self) -> bool:
        return self._node is not None

    @uamethod
    async def enable(self) -> StatusCodes:
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)

    @uamethod
    async def disable(self) -> StatusCodes:
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)

    async def _init_node(self, node: Node, server: Server | None) -> None:
        """
        links a node to the pubsub internals
        and prepares common nodes
        """
        self._node = node
        self._server = server
        if self._has_state:
            try:
                self._state_node = await node.get_child(["0:Status", "0:State"])
            except UaStatusCodeError:
                pass
            # @TODO fill methods
            # en = await self._node.get_child(["0:Status", "0:Enable"])
            # den = await self._node.get_child(["0:Status", "0:Disable"])

    async def set_node_value(
        self,
        path: str | QualifiedName | list[str] | list[QualifiedName],
        value: Variant,
    ) -> None:
        """
        Sets the value of the child node
        """
        if self._node is not None:
            n = await self._node.get_child(path)
            await write_typed(n, value)

    async def get_node_value(self, path: str | QualifiedName | list[str] | list[QualifiedName]) -> Variant | None:
        """
        Get value of child node value returns `None` if no information model is used
        """
        if self._node is not None:
            n = await self._node.get_child(path)
            return n.read_value()
        return None

    async def _set_state(self, state: PubSubState) -> None:
        """
        Internal sets the state of the information model
        """
        if self._state_node is not None:
            await write_typed(self._state_node, state)
        else:
            self.__state_fallback = state

    async def get_state(self) -> PubSubState:
        """
        Internal gets the state of the information model
        """
        if self._state_node is not None:
            return await self._state_node.read_value()
        return self.__state_fallback

    async def _get_node_name(self) -> String:
        if self._node is None:
            raise ValueError("Information model is not initialized")
        name = await self._node.read_browse_name()
        return name.Name

"""
Fill an address space with the nodes of namespace 0, generated from the OPC UA NodeSet.
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING

from enginir_opcua import ua

from .standard_address_space_services import create_standard_address_space_Services

if TYPE_CHECKING:
    from ..address_space import NodeManagementService


class PostponeReferences:
    """
    Adds the generated nodes and references, keeping those that fail (their target does not exist yet) and adding
    them again when the block ends; what still fails then raises RuntimeError.
    """

    def __init__(self, server: NodeManagementService) -> None:
        self.server = server
        self.postponed_refs: list[ua.AddReferencesItem] = []
        self.postponed_nodes: list[ua.AddNodesItem] = []

    def add_nodes(self, nodes: list[ua.AddNodesItem]) -> None:
        self.postponed_nodes.extend(self.server.try_add_nodes(nodes, check=False))

    def add_references(self, refs: list[ua.AddReferencesItem]) -> None:
        self.postponed_refs.extend(self.server.try_add_references(refs))

    def __enter__(self) -> PostponeReferences:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None
    ) -> None:
        if exc_type is None and exc_val is None:
            remaining_nodes = list(self.server.try_add_nodes(self.postponed_nodes, check=False))
            if remaining_nodes:
                raise RuntimeError(f"There are remaining nodes: {remaining_nodes!r}")
            remaining_refs = list(self.server.try_add_references(self.postponed_refs))
            if remaining_refs:
                raise RuntimeError(f"There are remaining refs: {remaining_refs!r}")


def fill_address_space(nodeservice: NodeManagementService) -> None:
    """Add the standard nodes of namespace 0 to the address space of nodeservice."""
    with PostponeReferences(nodeservice) as server:
        create_standard_address_space_Services(server)

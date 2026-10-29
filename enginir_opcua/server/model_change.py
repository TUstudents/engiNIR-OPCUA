"""
ModelChangeEvents (OPC 10000-3 v1.05, 9.32; OPC 10000-5 v1.05, 6.4.31, 6.4.32 and 12.16).

The node management service records each change in the change set of the request that is running. The request
(or a `model_change()` block around several of them) raises one GeneralModelChangeEvent from the Server Object when
it ends.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator, Callable
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua

from ..common import event_objects

if TYPE_CHECKING:
    from .internal_server import InternalServer

_logger = logging.getLogger(__name__)

NODE_ADDED = 1
NODE_DELETED = 2
REFERENCE_ADDED = 4
REFERENCE_DELETED = 8

_VERB_TEXT = (
    (NODE_ADDED, "Nodes added"),
    (NODE_DELETED, "Nodes deleted"),
    (REFERENCE_ADDED, "References added"),
    (REFERENCE_DELETED, "References deleted"),
)


class ChangeSet:
    """The Nodes changed by one request or one block, in the order of their first change, with the OR of the verbs."""

    def __init__(self, discard: bool = False) -> None:
        self.entries: dict[ua.NodeId, list[object]] = {}
        self.discard = discard

    def add(self, node_id: ua.NodeId, verb: int, type_definition: ua.NodeId) -> None:
        entry = self.entries.get(node_id)
        if entry is None:
            self.entries[node_id] = [type_definition, verb]
        else:
            entry[1] = int(entry[1]) | verb  # type: ignore[call-overload]
            if verb & NODE_DELETED:
                entry[0] = type_definition if not type_definition.is_null() else entry[0]


_current: ContextVar[ChangeSet | None] = ContextVar("model_change_set", default=None)


def record_change(node_id: ua.NodeId, verb: int, type_definition: Callable[[], ua.NodeId]) -> None:
    """Called by the node management service for every change that happened (SRV-96)."""
    changes = _current.get()
    if changes is not None and not changes.discard:
        changes.add(node_id, verb, type_definition())


class ModelChangeNotifier:
    """Owned by the internal server: collects the changes of a request and raises the event."""

    def __init__(self, iserver: InternalServer) -> None:
        self.iserver = iserver
        self.enabled = False
        self.max_changes = 10_000
        self._version = 0

    @contextlib.asynccontextmanager
    async def request(self) -> AsyncIterator[None]:
        if not self.enabled or _current.get() is not None:
            yield
            return
        changes = ChangeSet()
        token = _current.set(changes)
        try:
            yield
        finally:
            _current.reset(token)
            if changes.entries:
                try:
                    await self._emit(changes)
                except Exception:
                    _logger.exception("Raising the model change event failed")

    def _node_version_of(self, node_id: ua.NodeId) -> ua.NodeId | None:
        node = self.iserver.aspace.get(node_id)
        if node is None:
            return None
        for ref in node.references:
            if (
                ref.IsForward
                and ref.ReferenceTypeId == ua.NodeId(ua.ObjectIds.HasProperty)
                and ref.BrowseName.Name == "NodeVersion"
            ):
                return ref.NodeId
        return None

    async def _bump_versions(self, node_ids: list[ua.NodeId]) -> set[ua.NodeId]:
        versioned: set[ua.NodeId] = set()
        for node_id in node_ids:
            version_node = self._node_version_of(node_id)
            if version_node is None:
                continue
            self._version += 1
            await self.iserver.write_attribute_value(
                version_node, ua.DataValue(ua.Variant(str(self._version), ua.VariantType.String))
            )
            versioned.add(node_id)
        return versioned

    async def _emit(self, changes: ChangeSet) -> None:
        token = _current.set(ChangeSet(discard=True))
        try:
            entries = list(changes.entries.items())
            versioned = await self._bump_versions([node_id for node_id, _ in entries])
            if self.iserver.model_change_events == "versioned":
                entries = [(node_id, entry) for node_id, entry in entries if node_id in versioned]
                if not entries:
                    return
            verbs = 0
            for _, entry in entries:
                verbs |= int(entry[1])  # type: ignore[call-overload]
            message = ", ".join(text for bit, text in _VERB_TEXT if verbs & bit)
            event: Any
            if len(entries) > self.max_changes:
                event = event_objects.BaseModelChangeEvent()
            else:
                event = event_objects.GeneralModelChangeEvent()
                event.Changes = [
                    ua.ModelChangeStructureDataType(Affected=node_id, AffectedType=entry[0], Verb=entry[1])
                    for node_id, entry in entries
                ]
            from .event_generator import EventGenerator

            generator = EventGenerator(self.iserver.isession)
            await generator.init(event, ua.ObjectIds.Server, add_generates_event=False)
            await generator.trigger(message=message)
        finally:
            _current.reset(token)

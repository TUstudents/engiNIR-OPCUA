"""
Walks over the references of the address space for events: type hierarchies and the notifier chain of a source.
"""

from __future__ import annotations

from enginir_opcua import ua

from .address_space import AddressSpace

HAS_SUBTYPE = ua.NodeId(ua.ObjectIds.HasSubtype)
HAS_EVENT_SOURCE = ua.NodeId(ua.ObjectIds.HasEventSource)
SERVER_OBJECT = ua.NodeId(ua.ObjectIds.Server)


def is_subtype(aspace: AddressSpace, nodeid: ua.NodeId, ancestor: ua.NodeId) -> bool:
    """Whether the type nodeid is ancestor or one of its subtypes, along inverse HasSubtype references."""
    seen: set[ua.NodeId] = set()
    pending = [nodeid]
    while pending:
        current = pending.pop()
        if current == ancestor:
            return True
        if current in seen:
            continue
        seen.add(current)
        data = aspace.get(current)
        if data is None:
            continue
        pending.extend(
            ref.NodeId for ref in data.references if not ref.IsForward and ref.ReferenceTypeId == HAS_SUBTYPE
        )
    return False


def notifiers_of(aspace: AddressSpace, source: ua.NodeId) -> list[ua.NodeId]:
    """
    The nodes an Event of source is reported by: source and every node above it along inverse HasEventSource
    references and their subtypes (HasNotifier), and always the Server Object (OPC 10000-3 v1.05, 7.17 and 7.18).
    """
    known: dict[ua.NodeId, bool] = {}

    def propagates(reference_type: ua.NodeId) -> bool:
        if reference_type not in known:
            known[reference_type] = is_subtype(aspace, reference_type, HAS_EVENT_SOURCE)
        return known[reference_type]

    found = [source]
    seen = {source}
    for current in found:
        data = aspace.get(current)
        if data is None:
            continue
        for ref in data.references:
            if not ref.IsForward and ref.NodeId not in seen and propagates(ref.ReferenceTypeId):
                seen.add(ref.NodeId)
                found.append(ref.NodeId)
    if SERVER_OBJECT not in seen:
        found.append(SERVER_OBJECT)
    return found

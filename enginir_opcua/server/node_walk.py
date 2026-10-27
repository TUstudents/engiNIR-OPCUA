from __future__ import annotations

from enginir_opcua import ua

from .address_space import AddressSpace

HAS_SUBTYPE = ua.NodeId(ua.ObjectIds.HasSubtype)


def is_subtype(aspace: AddressSpace, nodeid: ua.NodeId, ancestor: ua.NodeId) -> bool:
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

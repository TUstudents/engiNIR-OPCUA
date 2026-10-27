from dataclasses import dataclass
from enum import Enum
from typing import Any

from enginir_opcua import ua


class UserRole(Enum):
    """
    User Roles
    """

    Admin = 0
    Anonymous = 1
    User = 3


ROLE_RANK: dict[UserRole, int] = {UserRole.Anonymous: 0, UserRole.User: 1, UserRole.Admin: 2}


def _type_id(request_type: str) -> ua.NodeId:
    return ua.NodeId(getattr(ua.ObjectIds, f"{request_type}Request_Encoding_DefaultBinary"))


def _rows(role: UserRole, *request_types: str) -> dict[ua.NodeId, UserRole]:
    return {_type_id(request_type): role for request_type in request_types}


DEFAULT_MINIMUM_ROLES: dict[ua.NodeId, UserRole] = {
    **_rows(
        UserRole.Anonymous,
        "Read",
        "Browse",
        "BrowseNext",
        "TranslateBrowsePathsToNodeIds",
        "RegisterNodes",
        "UnregisterNodes",
        "QueryFirst",
        "QueryNext",
        "HistoryRead",
        "CreateSubscription",
        "ModifySubscription",
        "SetPublishingMode",
        "DeleteSubscriptions",
        "Republish",
        "TransferSubscriptions",
        "Publish",
        "SetTriggering",
        "CreateMonitoredItems",
        "ModifyMonitoredItems",
        "SetMonitoringMode",
        "DeleteMonitoredItems",
        "Cancel",
    ),
    **_rows(UserRole.User, "Write", "Call", "HistoryUpdate"),
    **_rows(UserRole.Admin, "AddNodes", "DeleteNodes", "AddReferences", "DeleteReferences"),
}


@dataclass
class User:
    role: UserRole = UserRole.Anonymous
    name: str | None = None


class PermissionRuleset:
    """
    Base class for permission ruleset
    """

    def check_validity(self, user: User, action_type_id: ua.NodeId, body: Any) -> bool:
        raise NotImplementedError


class SimpleRoleRuleset(PermissionRuleset):
    """
    Standard simple role-based ruleset: a map from request type to the lowest role that may send it.
    Anonymous users can read, browse, subscribe and read history, users can also write and call methods,
    and only admins change the address space. A request type without a row, and a user without a known role, is denied.
    """

    def __init__(self, minimum_roles: dict[ua.NodeId, UserRole] | None = None) -> None:
        self._minimum_roles = dict(DEFAULT_MINIMUM_ROLES if minimum_roles is None else minimum_roles)

    def check_validity(self, user: User, action_type_id: ua.NodeId, body: Any) -> bool:
        minimum = self._minimum_roles.get(action_type_id)
        if minimum is None or user.role not in ROLE_RANK:
            return False
        return ROLE_RANK[user.role] >= ROLE_RANK[minimum]

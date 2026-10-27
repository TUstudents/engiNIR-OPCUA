import pytest

from enginir_opcua import ua
from enginir_opcua.crypto.permission_rules import ROLE_RANK, SimpleRoleRuleset, User, UserRole
from enginir_opcua.server.service_dispatch import Permission
from enginir_opcua.server.service_handlers import build_service_table


def _type_id(request_type: str) -> ua.NodeId:
    return ua.NodeId(getattr(ua.ObjectIds, f"{request_type}Request_Encoding_DefaultBinary"))


def _allows(role: UserRole, request_type: str) -> bool:
    return SimpleRoleRuleset().check_validity(User(role=role), _type_id(request_type), None)


READ_ONLY_SERVICES = [
    "Read",
    "Browse",
    "BrowseNext",
    "TranslateBrowsePathsToNodeIds",
    "RegisterNodes",
    "UnregisterNodes",
    "HistoryRead",
    "CreateSubscription",
    "ModifySubscription",
    "SetPublishingMode",
    "DeleteSubscriptions",
    "Republish",
    "TransferSubscriptions",
    "Publish",
    "CreateMonitoredItems",
    "ModifyMonitoredItems",
    "SetMonitoringMode",
    "DeleteMonitoredItems",
    "Cancel",
]
USER_SERVICES = ["Write", "Call", "HistoryUpdate"]
ADMIN_SERVICES = ["AddNodes", "DeleteNodes", "AddReferences", "DeleteReferences"]
SERVICES_WITHOUT_A_ROW = [
    "CreateSession",
    "ActivateSession",
    "CloseSession",
    "GetEndpoints",
    "FindServers",
    "CloseSecureChannel",
    "RegisterServer",
    "RegisterServer2",
]


@pytest.mark.parametrize("request_type", READ_ONLY_SERVICES)
def test_cry12_anonymous_may_read_browse_subscribe(request_type: str) -> None:
    """Part 4, 5.7.3.1 and the service sets of Part 4: Anonymous is the read-only role."""
    assert _allows(UserRole.Anonymous, request_type)


@pytest.mark.parametrize("request_type", USER_SERVICES + ADMIN_SERVICES)
def test_cry12_anonymous_may_not_write_call_or_add_nodes(request_type: str) -> None:
    """Part 4, 5.7.3.1: Anonymous cannot change values, call methods or change the address space."""
    assert not _allows(UserRole.Anonymous, request_type)


@pytest.mark.parametrize("request_type", ADMIN_SERVICES)
def test_cry12_user_may_not_add_nodes(request_type: str) -> None:
    """Part 4, 5.7.3.1: only Admin changes the address space."""
    assert not _allows(UserRole.User, request_type)
    assert _allows(UserRole.Admin, request_type)


@pytest.mark.parametrize("request_type", USER_SERVICES)
def test_cry12_user_may_write_and_call(request_type: str) -> None:
    """Part 4, 5.7.3.1: User may change values and call methods."""
    assert _allows(UserRole.User, request_type)


@pytest.mark.parametrize("role", list(UserRole))
@pytest.mark.parametrize("request_type", SERVICES_WITHOUT_A_ROW)
def test_cry12_services_the_dispatcher_handles_itself_have_no_row(role: UserRole, request_type: str) -> None:
    """Part 4, 5.3: a service without a row is denied; Session and discovery services never reach the ruleset."""
    assert not _allows(role, request_type)


def test_cry12_unknown_role_and_unknown_service_are_denied() -> None:
    """Part 4, 5.3: neither an unknown role nor an unknown request type is allowed."""
    ruleset = SimpleRoleRuleset()
    assert not ruleset.check_validity(User(role="Operator"), _type_id("Read"), None)  # type: ignore[arg-type]
    assert not ruleset.check_validity(User(role=UserRole.Admin), ua.NodeId(1, 99), None)


def test_cry12_every_dispatch_entry_has_a_permission_class() -> None:
    """Part 4, 5.3: each service in the dispatch table states who may call it, and the ruleset agrees."""
    ruleset = SimpleRoleRuleset()
    classes = {
        Permission.Anonymous: UserRole.Anonymous,
        Permission.User: UserRole.User,
        Permission.Admin: UserRole.Admin,
    }
    for service in build_service_table():
        if service.permission is Permission.Unchecked:
            assert not ruleset.check_validity(User(role=UserRole.Admin), service.type_id, None), service.name
            continue
        lowest = classes[service.permission]
        for role in UserRole:
            expected = ROLE_RANK[role] >= ROLE_RANK[lowest]
            assert ruleset.check_validity(User(role=role), service.type_id, None) is expected, (service.name, role)

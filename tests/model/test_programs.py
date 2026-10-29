"""The Program state machine (OPC 10000-10 v1.05, 5.2; OPC 10000-16 v1.05, 4.4)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.node import Node
from enginir_opcua.common.programs import NO_LIMIT, TRANSITIONS, ProgramHandlers, ProgramStateMachine
from enginir_opcua.server.user_managers import PermissiveUserManager
from tests.conftest import find_free_port
from tests.monitoring import create_items, item_request, open_subscription, publish

SERVER_OBJECT = ua.NodeId(ua.ObjectIds.Server)
STATE_IDS = {"Halted": 2406, "Ready": 2400, "Running": 2402, "Suspended": 2404}
METHODS = ("Start", "Suspend", "Resume", "Halt", "Reset")


@pytest.fixture(scope="module", name="rig")
async def make_rig() -> AsyncIterator[tuple[Server, Client]]:
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    await server.init()
    port = find_free_port()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await server.start()
    client = Client(f"opc.tcp://admin@127.0.0.1:{port}", timeout=5)
    await client.connect()
    yield server, client
    await client.disconnect()
    await server.stop()


@pytest.fixture(name="server")
async def make_server(rig: tuple[Server, Client]) -> Server:
    return rig[0]


@pytest.fixture(name="client")
async def make_client(rig: tuple[Server, Client]) -> Client:
    return rig[1]


calls: list[str] = []


async def ok(program: ProgramStateMachine, *args: Any) -> None:
    calls.append("ok")


def all_handlers() -> ProgramHandlers:
    return ProgramHandlers(start=ok, suspend=ok, resume=ok, halt=ok, reset=ok)


_counter = iter(range(1, 10_000))


async def make_program(server: Server, handlers: ProgramHandlers | None = None, **options: Any) -> ProgramStateMachine:
    parent = await server.nodes.objects.add_folder(2, f"Programs{next(_counter)}")
    program = ProgramStateMachine(server, parent, "Program", handlers or all_handlers(), **options)
    await program.install()
    return program


async def current_state_id(node: Node) -> ua.NodeId:
    current = await node.get_child("0:CurrentState")
    return await (await current.get_child("0:Id")).read_value()


async def test_com120_program_instance_uses_the_types_states_and_transitions(server: Server) -> None:
    """Part 10, 5.2.3 and Part 16, 4.4.19: States and Transitions are the type's own nodes."""
    program = await make_program(server, initial_state="Ready")
    names = [(await c.read_browse_name()).Name for c in await program.node.get_children()]
    assert "Ready" not in names and "ReadyToRunning" not in names
    assert await current_state_id(program.node) == ua.NodeId(STATE_IDS["Ready"])
    assert program.state == "Ready"
    current = await program.node.get_child("0:CurrentState")
    assert await (await current.get_child("0:Number")).read_value() == 12


async def test_com120_initial_state_is_halted_by_default_and_must_be_halted_or_ready(server: Server) -> None:
    """Part 10, 4.2.10.1: a Program is created Halted or Ready."""
    program = await make_program(server)
    assert program.state == "Halted"
    parent = await server.nodes.objects.add_folder(2, f"Bad{next(_counter)}")
    with pytest.raises(ValueError):
        ProgramStateMachine(server, parent, "P", all_handlers(), initial_state="Running")


async def test_com121_only_supplied_methods_exist(server: Server) -> None:
    """Part 10, 4.2.7: a Program that does not support a control Method omits it."""
    program = await make_program(server, ProgramHandlers(start=ok, halt=ok))
    names = {(await c.read_browse_name()).Name for c in await program.node.get_children()}
    assert {"Start", "Halt"} <= names
    assert not names & {"Suspend", "Resume", "Reset"}


async def executable(program: ProgramStateMachine, name: str) -> bool:
    value = await program._methods[name].read_attribute(ua.AttributeIds.Executable)
    assert value.Value is not None
    return bool(value.Value.Value)


STATE_METHODS = {
    "Halted": {"Reset"},
    "Ready": {"Start", "Halt"},
    "Running": {"Suspend", "Halt"},
    "Suspended": {"Resume", "Halt"},
}


async def test_com121_methods_are_executable_per_state(server: Server, client: Client) -> None:
    """Part 10, 5.2.4.2: Executable tells whether the current State allows the Method."""
    program = await make_program(server)
    node = client.get_node(program.node.nodeid)
    path = [
        ("Reset", "Ready"),
        ("Start", "Running"),
        ("Suspend", "Suspended"),
        ("Resume", "Running"),
        ("Halt", "Halted"),
    ]
    seen = {program.state}
    for method, expected in [(None, "Halted"), *path]:
        if method is not None:
            await node.call_method(f"0:{method}")
        assert program.state == expected
        seen.add(expected)
        for name in METHODS:
            assert await executable(program, name) == (name in STATE_METHODS[expected]), (expected, name)
    assert seen == set(STATE_METHODS)


async def test_com121_call_in_the_wrong_state_is_refused(server: Server, client: Client) -> None:
    """Part 10, 5.2.4: Start needs Ready; the Call service refuses a Method that is not executable."""
    program = await make_program(server)
    with pytest.raises(ua.UaStatusCodeError) as refused:
        await client.get_node(program.node.nodeid).call_method("0:Start")
    assert refused.value.code == ua.StatusCodes.BadNotExecutable
    result = await server.iserver.isession.call(
        [ua.CallMethodRequest(ObjectId=program.node.nodeid, MethodId=program._methods["Start"].nodeid)]
    )
    assert result[0].StatusCode.value == ua.StatusCodes.BadInvalidState
    assert program.state == "Halted"


async def test_com121_callback_failure_leaves_the_state(server: Server, client: Client) -> None:
    """Part 10, 4.2.7: the Call result says why the Method failed; no transition happened."""

    async def refuse(program: ProgramStateMachine, *args: Any) -> None:
        raise ua.uaerrors.BadResourceUnavailable()

    program = await make_program(server, ProgramHandlers(start=refuse, reset=ok), initial_state="Ready")
    with pytest.raises(ua.UaStatusCodeError) as failed:
        await client.get_node(program.node.nodeid).call_method("0:Start")
    assert failed.value.code == ua.StatusCodes.BadResourceUnavailable
    assert program.state == "Ready"


async def test_com121_two_concurrent_starts_give_one_transition(server: Server) -> None:
    """Part 10, 4.2.7: transitions are serialised, so the second Start sees Running."""
    gate = asyncio.Event()

    async def slow(program: ProgramStateMachine, *args: Any) -> None:
        await gate.wait()

    program = await make_program(server, ProgramHandlers(start=slow), initial_state="Ready")
    request = ua.CallMethodRequest(ObjectId=program.node.nodeid, MethodId=program._methods["Start"].nodeid)
    first = asyncio.create_task(server.iserver.isession.call([request]))
    second = asyncio.create_task(server.iserver.isession.call([request]))
    await asyncio.sleep(0.1)
    gate.set()
    results = [(await first)[0].StatusCode.value, (await second)[0].StatusCode.value]
    assert sorted(results) == sorted([ua.StatusCodes.Good, ua.StatusCodes.BadInvalidState])
    assert program.state == "Running"


async def test_com121_reset_counts_recycles_and_respects_the_maximum(server: Server, client: Client) -> None:
    """Part 10, 5.2.2: RecycleCount counts restarts from the starting point; MaxRecycleCount limits them."""
    program = await make_program(server, max_recycle_count=1)
    node = client.get_node(program.node.nodeid)
    await node.call_method("0:Reset")
    assert await (await program.node.get_child("0:RecycleCount")).read_value() == 1
    await node.call_method("0:Halt")
    result = await server.iserver.isession.call(
        [ua.CallMethodRequest(ObjectId=program.node.nodeid, MethodId=program._methods["Reset"].nodeid)]
    )
    assert result[0].StatusCode.value == ua.StatusCodes.BadInvalidState
    assert program.max_recycle_count != NO_LIMIT


async def test_com121_instance_count_and_maximum(server: Server) -> None:
    """Part 10, 5.2.2: InstanceCount counts the invocations of the type; MaxInstanceCount limits them."""
    fresh = Server()
    await fresh.init()
    parent = await fresh.nodes.objects.add_folder(2, "P")
    first = ProgramStateMachine(fresh, parent, "A", all_handlers(), max_instance_count=2)
    second = ProgramStateMachine(fresh, parent, "B", all_handlers(), max_instance_count=2)
    third = ProgramStateMachine(fresh, parent, "C", all_handlers(), max_instance_count=2)
    await first.install()
    await second.install()
    assert await (await first.node.get_child("0:InstanceCount")).read_value() == 2
    with pytest.raises(ua.UaStatusCodeError) as full:
        await third.install()
    assert full.value.code == ua.StatusCodes.BadResourceUnavailable
    await second.delete()
    assert await (await first.node.get_child("0:InstanceCount")).read_value() == 1


async def test_com121_delete_needs_halted_and_deletable(server: Server, client: Client) -> None:
    """Part 10, 4.2.10.1: a Client removes only a Deletable Program that is Halted."""
    fixed = await make_program(server)
    with pytest.raises(ua.UaStatusCodeError) as refused:
        await client.get_node(fixed.node.nodeid).delete()
    assert refused.value.code == ua.StatusCodes.BadNoDeleteRights
    removable = await make_program(server, deletable=True, initial_state="Ready")
    with pytest.raises(ua.UaStatusCodeError) as busy:
        await client.get_node(removable.node.nodeid).delete()
    assert busy.value.code == ua.StatusCodes.BadInvalidState
    await client.get_node(removable.node.nodeid).call_method("0:Halt")
    await client.get_node(removable.node.nodeid).delete()
    assert removable.node.nodeid not in server.iserver.aspace


async def test_com121_auto_delete_after_internal_halt(server: Server, client: Client) -> None:
    """Part 10, 5.2.2: an AutoDelete Program removes itself when its execution ends."""
    program = await make_program(server, auto_delete=True, initial_state="Ready")
    await client.get_node(program.node.nodeid).call_method("0:Start")
    assert program.node.nodeid in server.iserver.aspace
    await program.complete()
    assert program.node.nodeid not in server.iserver.aspace


async def test_com121_internal_transitions_complete_and_fail(server: Server, client: Client) -> None:
    """Part 10, 4.2.3: RunningToReady and RunningToHalted are internal."""
    program = await make_program(server, initial_state="Ready")
    node = client.get_node(program.node.nodeid)
    await node.call_method("0:Start")
    await program.complete(recycle=True)
    assert program.state == "Ready"
    await node.call_method("0:Start")
    await program.fail("broken")
    assert program.state == "Halted"
    with pytest.raises(ua.UaStatusCodeError):
        await program.complete()


def select() -> ua.EventFilter:
    names = ["Transition", "FromState", "ToState", "EventType", "SourceNode", "IntermediateResult"]
    return ua.EventFilter(
        SelectClauses=[
            ua.SimpleAttributeOperand(
                TypeDefinitionId=ua.NodeId(ua.ObjectIds.BaseEventType),
                BrowsePath=[ua.QualifiedName(n, 0)],
                AttributeId=ua.AttributeIds.Value,
            )
            for n in names
        ]
    )


async def test_com121_each_transition_raises_a_program_transition_event(server: Server, client: Client) -> None:
    """Part 10, 5.2.5: every Transition generates a ProgramTransitionEvent from the Program."""
    sub, wire = await open_subscription(server)
    [created] = await create_items(
        server, sub, item_request(SERVER_OBJECT, ua.AttributeIds.EventNotifier, queue=100, filter=select())
    )
    assert created.StatusCode.is_good()
    program = await make_program(server, initial_state="Ready")
    await publish(sub, wire)
    node = client.get_node(program.node.nodeid)
    await node.call_method("0:Start")
    await program.complete(result="done")
    events = await publish(sub, wire)
    assert [e.EventFields[0].Value.Text for e in events] == ["ReadyToRunning", "RunningToHalted"]
    first = events[0].EventFields
    assert (first[1].Value.Text, first[2].Value.Text) == ("Ready", "Running")
    assert first[3].Value == ua.NodeId(ua.ObjectIds.ProgramTransitionEventType)
    assert first[4].Value == program.node.nodeid
    assert events[1].EventFields[5].Value == "done"


async def test_com121_all_nine_transitions_exist_with_numbers(server: Server) -> None:
    """Part 10, Table 3: nine Transitions numbered 1 to 9 from a state to another."""
    assert sorted(v[1] for v in TRANSITIONS.values()) == list(range(1, 10))


async def test_com121_program_diagnostic_records_the_last_call_and_session(server: Server, client: Client) -> None:
    """Part 10, 5.2.8: ProgramDiagnostic keeps the last Method call and the Session that made it."""
    program = await make_program(server)
    await client.get_node(program.node.nodeid).call_method("0:Reset")
    diagnostic = await (await program.node.get_child("0:ProgramDiagnostic")).read_value()
    assert diagnostic.LastMethodCall == "Reset"
    assert (
        diagnostic.LastMethodSessionId
        == server.iserver.session_manager.sessions[client.uaclient.session.authentication_token].id
    )
    assert diagnostic.LastMethodReturnStatus.value == ua.StatusCodes.Good
    assert diagnostic.InvocationCreationTime is not None

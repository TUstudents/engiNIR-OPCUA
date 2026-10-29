"""A server with Alarms and Conditions and a client that collects their Events."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from itertools import count
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.node import Node
from enginir_opcua.server.user_managers import PermissiveUserManager
from tests.access_rig import free_port
from tests.waiting import wait_until

_numbers = count(1)


class Collector:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def event_notification(self, event: Any) -> None:
        self.events.append(event)

    def condition_events(self) -> list[Any]:
        return [event for event in self.events if getattr(event, "NodeId", None) is not None]

    def clear(self) -> None:
        self.events.clear()


@dataclass
class ConditionRig:
    server: Server
    admin: Client
    user: Client
    ns: int
    subscriptions: list[Any] = field(default_factory=list)

    def unique(self, base: str) -> str:
        return f"{base}{next(_numbers)}"

    async def source(self, base: str = "Source") -> Node:
        node = await self.server.nodes.objects.add_object(self.ns, self.unique(base))
        await node.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
        return node

    async def watch(
        self,
        source: Node | ua.NodeId,
        types: Any = ua.ObjectIds.ConditionType,
        client: Client | None = None,
        queue: int = 100,
    ) -> tuple[Collector, Any]:
        collector = Collector()
        owner = client or self.admin
        sub = await owner.create_subscription(50, collector)
        nodeid = source.nodeid if isinstance(source, Node) else source
        await sub.subscribe_events(owner.get_node(nodeid), types, queuesize=queue)
        self.subscriptions.append(sub)
        return collector, sub

    async def count(self, collector: Collector, expected: int) -> list[Any]:
        await wait_until(lambda: len(collector.condition_events()) >= expected)
        await asyncio.sleep(0.15)
        found = collector.condition_events()
        assert len(found) == expected, [(e.Retain, e.BranchId) for e in found]
        return found


@pytest.fixture(scope="module", name="condition_rig")
async def make_condition_rig() -> AsyncIterator[ConditionRig]:
    port = free_port()
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    server.allow_plaintext_password = True
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    ns = await server.register_namespace("http://test.example/conditions")
    await server.start()
    admin = Client(f"opc.tcp://admin@127.0.0.1:{port}", timeout=10)
    user = Client(f"opc.tcp://someone@127.0.0.1:{port}", timeout=10)
    await admin.connect()
    await user.connect()
    yield ConditionRig(server, admin, user, ns)
    await user.disconnect()
    await admin.disconnect()
    await server.stop()

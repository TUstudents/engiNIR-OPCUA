"""
A limit alarm, and a client that acknowledges it.

Shows: Server.create_condition with an ExclusiveLevelAlarmType (limits for High and HighHigh), update_value to drive
the alarm from a measurement, a client that subscribes to the alarm events with condition_event_filter and
ConditionTracker (the current alarm list), and the Acknowledge method through enginir_opcua.common.conditions.
Calling methods needs the "user" role.

Run: python examples/12_alarms.py

Spec: OPC 10000-9 v1.05, 5.5.2 (ConditionType), 5.7 (Acknowledgeable Condition Model: Acknowledge), 5.8 (Alarm model),
5.8.18 and 5.8.19 (limit alarm types), 4.5 (Condition state synchronization) and 5.5.7 (ConditionRefresh).
"""

import asyncio
from typing import Any

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua
from enginir_opcua.common import conditions
from enginir_opcua.crypto.users_file import UserRecord, hash_password, write_users


async def wait_for(condition: Any, timeout: float = 10.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.02)


def acked(event: Any) -> bool:
    return bool(getattr(event, "AckedState/Id"))


def current(tracker: conditions.ConditionTracker) -> Any:
    return next(iter(tracker.entries.values()), None)


async def main() -> None:
    with workdir() as directory:
        users = directory / "users.toml"
        write_users(users, [UserRecord("operator", "user", hash_password("operator-secret"))])
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki", users=users)
        client = Client.quickstart(url, pki=directory / "client-pki", username="operator", password="operator-secret")
        await server.init()
        idx = await server.register_namespace("urn:enginir:example:alarms")

        tank = await server.nodes.objects.add_object(idx, "Tank")
        await tank.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
        alarm = await server.create_condition(
            tank,
            ua.NodeId(ua.ObjectIds.ExclusiveLevelAlarmType),
            "TankLevel",
            limits={"HighHigh": 90.0, "High": 70.0},
            severities={"HighHigh": 800, "High": 500},
        )
        await pair(directory / "server-pki", directory / "client-pki", client.application_uri)

        async with server, client:
            changes: list[tuple[Any, bool]] = []
            tracker = conditions.ConditionTracker(lambda event, retained: changes.append((event, retained)))
            event_filter = await conditions.condition_event_filter(client, ua.ObjectIds.AlarmConditionType)
            subscription = await client.create_subscription(50, tracker)
            await subscription.subscribe_events(client.get_node(tank.nodeid), evfilter=event_filter)

            await alarm.update_value(50.0)
            await alarm.update_value(75.0)
            await wait_for(lambda: current(tracker))
            event = current(tracker)
            print(f"alarm: {event.Message.Text}, severity {event.Severity}, acknowledged {acked(event)}")

            await conditions.acknowledge(client, alarm.condition_id, event.EventId, "seen by the operator")
            await wait_for(lambda: acked(current(tracker)))
            print("acknowledged:", acked(current(tracker)))

            await alarm.update_value(95.0)
            await wait_for(lambda: current(tracker).Severity == 800)
            print("escalated to severity", current(tracker).Severity)

            await alarm.update_value(40.0)
            await wait_for(lambda: not getattr(current(tracker), "ActiveState/Id"))
            print("back to normal; still listed until it is acknowledged, acknowledged", acked(current(tracker)))
            await conditions.acknowledge(client, alarm.condition_id, current(tracker).EventId, "level is normal")
            await wait_for(lambda: not tracker.entries)
            print("acknowledged; the alarm list is empty")
    print("OK 12_alarms")


if __name__ == "__main__":
    asyncio.run(main())

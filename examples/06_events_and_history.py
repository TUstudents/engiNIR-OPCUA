"""
Events and history.

Shows: a custom event type, an event generator on an object, a client that subscribes to those events, and history
of both kinds. A variable is historized (every change is stored) and so are the events of the object. The client
then reads the stored values and the stored events back. The default storage is in memory; HistorySQLite keeps the
history across restarts.

Run: python examples/06_events_and_history.py

Spec: OPC 10000-3 v1.05, 5.5.1 (Object NodeClass, EventNotifier) and 4.7 (Event model); OPC 10000-4 v1.05, 5.13 (event
filters in MonitoredItem services) and 5.11 (HistoryRead and HistoryUpdate); OPC 10000-11 v1.05, 4 (Historical Access).
"""

import asyncio
from datetime import timedelta
from typing import Any

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua


class Collector:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def event_notification(self, event: Any) -> None:
        print(f"event: {event.Message.Text} (severity {event.Severity})")
        self.events.append(event)


async def wait_for(condition: Any, timeout: float = 10.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.02)


async def main() -> None:
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki")
        client = Client.quickstart(url, pki=directory / "client-pki")
        await server.init()
        idx = await server.register_namespace("urn:enginir:example:events")

        reactor = await server.nodes.objects.add_object(idx, "Reactor")
        temperature = await reactor.add_variable(idx, "Temperature", 20.0)
        overheat = await server.create_custom_event_type(
            idx, "OverheatEventType", ua.ObjectIds.BaseEventType, [("Limit", ua.VariantType.Double)]
        )
        await server.historize_node_data_change(temperature, period=timedelta(hours=1))
        await server.historize_node_event(reactor, period=timedelta(hours=1))
        generator = await server.get_event_generator(overheat, reactor)
        await pair(directory / "server-pki", directory / "client-pki", client.application_uri)

        async with server, client:
            collector = Collector()
            subscription = await client.create_subscription(50, collector)
            await subscription.subscribe_events(client.get_node(reactor.nodeid), overheat)

            for degrees in (21.0, 25.5, 31.0):
                await temperature.write_value(degrees)
                if degrees > 30:
                    generator.event.Message = ua.LocalizedText(f"Reactor at {degrees} degrees")
                    generator.event.Severity = 700
                    generator.event.Limit = 30.0
                    await generator.trigger()
            await wait_for(lambda: collector.events)

            node = client.get_node(temperature.nodeid)
            async with asyncio.timeout(10):
                while True:
                    values = await node.read_raw_history()
                    if values and values[-1].Value.Value == 31.0:
                        break
                    await asyncio.sleep(0.05)
            print("stored values:", [dv.Value.Value for dv in values][-3:])
            events = await client.get_node(reactor.nodeid).read_event_history(evtypes=overheat)
            print("stored events:", [event.Message.Text for event in events])
            assert collector.events[0].Limit == 30.0
            assert len(events) == 1
    print("OK 06_events_and_history")


if __name__ == "__main__":
    asyncio.run(main())

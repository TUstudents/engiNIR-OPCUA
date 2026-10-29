"""
The synchronous API: a server and a client without async and await.

Shows: enginir_opcua.sync.Server.quickstart and enginir_opcua.sync.Client.quickstart, which have the same settings
as the asynchronous classes, blocking node calls, and a subscription whose handler runs on a handler thread. Each
object runs its own event-loop thread.

Run: python examples/11_sync.py

Spec: none; the synchronous wrapper is a convenience layer over the asynchronous API (OPC 10000-4 v1.05, 5.11 for
Read and Write and 5.13 and 5.14 for subscriptions).
"""

import queue
from typing import Any

from _common import free_port, pair_sync, workdir

from enginir_opcua import ua
from enginir_opcua.sync import Client, Server


class Handler:
    def __init__(self) -> None:
        self.values: queue.Queue[Any] = queue.Queue()

    def datachange_notification(self, node: Any, value: Any, data: ua.DataChangeNotification) -> None:
        self.values.put(value)


def main() -> None:
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki")
        client = Client.quickstart(url, pki=directory / "client-pki")
        pair_sync(directory / "server-pki", directory / "client-pki", client.application_uri)

        idx = server.register_namespace("urn:enginir:example:sync")
        level = server.nodes.objects.add_variable(idx, "Level", 1.0)
        server.start()
        try:
            with client:
                node = client.get_node(level.nodeid)
                print("level:", node.read_value())
                handler = Handler()
                subscription = client.create_subscription(100, handler)
                subscription.subscribe_data_change(node)
                print("first notification:", handler.values.get(timeout=5))
                level.write_value(2.5)
                while (value := handler.values.get(timeout=5)) != 2.5:
                    pass
                print("changed to:", value)
        finally:
            server.stop()
    print("OK 11_sync")


if __name__ == "__main__":
    main()

"""
A client for a redundant pair of servers.

Shows: two servers that report warm redundancy and a ServiceLevel, and an HaClient with security (a trust store over
the client's PKI directory) that keeps a subscription on the healthy one. When the first server reports a low
ServiceLevel the client fails over to the second, and the subscription continues there. Only the warm mode is
implemented; the servers must have identical NodeIds.

Run: python examples/09_ha_client.py

Spec: OPC 10000-4 v1.05, 6.6 (Redundancy: 6.6.2.4.2 ServiceLevel, 6.6.2.4.5 client failover behaviour); OPC 10000-5
v1.05, 6.3.7 (ServerRedundancyType) and 12.5 (RedundancySupport).
"""

import asyncio
from pathlib import Path
from typing import Any

from _common import free_port, pair, workdir

from enginir_opcua import Server, ua
from enginir_opcua.client.ha import HaClient, HaConfig, HaMode
from enginir_opcua.common.node import Node
from enginir_opcua.crypto import pki
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.crypto.uacrypto import CertProperties

CLIENT_URI = "urn:enginir:example:ha-client"


class Handler:
    def __init__(self) -> None:
        self.values: asyncio.Queue[Any] = asyncio.Queue()

    def datachange_notification(self, node: Node, value: Any, data: ua.DataChangeNotification) -> None:
        self.values.put_nowait(value)


async def make_server(directory: Path, name: str) -> tuple[Server, str, Node]:
    url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/{name}/"
    server = Server.quickstart(url, pki=directory / f"{name}-pki", application_uri=f"urn:enginir:example:ha:{name}")
    await server.init()
    idx = await server.register_namespace("urn:enginir:example:ha")
    counter = await server.nodes.objects.add_variable(ua.NodeId("Counter", idx), "Counter", 0)
    return server, url, counter


async def start_server(server: Server, level: int) -> None:
    await server.start()
    await set_service_level(server, level)
    redundancy = server.get_node(ua.NodeId(ua.ObjectIds.Server_ServerRedundancy_RedundancySupport))
    await redundancy.write_value(ua.Variant(ua.RedundancySupport.Warm, ua.VariantType.Int32))


async def set_service_level(server: Server, level: int) -> None:
    await server.get_node(ua.NodeId(ua.ObjectIds.Server_ServiceLevel)).write_value(
        ua.Variant(level, ua.VariantType.Byte)
    )


async def next_value(handler: Handler, counters: list[Node], value: int) -> int:
    async with asyncio.timeout(30):
        while True:
            for counter in counters:
                await counter.write_value(value)
            try:
                return int(await asyncio.wait_for(handler.values.get(), 0.5))
            except TimeoutError:
                continue


async def main() -> None:
    with workdir() as directory:
        first, first_url, first_counter = await make_server(directory, "first")
        second, second_url, second_counter = await make_server(directory, "second")
        client_pki = directory / "client-pki"
        await pair(directory / "first-pki", client_pki, CLIENT_URI)
        await pair(directory / "second-pki", client_pki, CLIENT_URI)
        await start_server(first, 255)
        await start_server(second, 200)

        config = HaConfig(
            HaMode.WARM,
            keepalive_timer=1,
            manager_timer=1,
            reconciliator_timer=1,
            min_active_seconds=1,
            urls=[first_url, second_url],
            session_name="ha-example",
        )
        ha = HaClient(config)
        for client in ha.get_clients():
            client.application_uri = CLIENT_URI
        ha.set_security(
            SecurityPolicyBasic256Sha256,
            CertProperties(client_pki / "own" / "certs" / pki.CERTIFICATE_NAME),
            CertProperties(client_pki / "own" / "private" / pki.KEY_NAME),
            trust_store=TrustStore.from_pki_directory(client_pki),
        )
        handler = Handler()
        await ha.start()
        try:
            subscription = await ha.create_subscription(100, handler)
            await ha.subscribe_data_change(subscription, [ua.NodeId("Counter", 2).to_string()])
            counters = [first_counter, second_counter]
            await next_value(handler, counters, 1)
            assert ha.active_client is not None
            print("active server:", ha.active_client.server_url.geturl())

            await set_service_level(first, 10)
            await next_value(handler, counters, 2)
            async with asyncio.timeout(30):
                while ha.active_client is None or ha.active_client.server_url.geturl() != second_url:
                    await next_value(handler, counters, 3)
            print("active server after the first reported ServiceLevel 10:", ha.active_client.server_url.geturl())
        finally:
            await ha.stop()
            await first.stop()
            await second.stop()
    print("OK 09_ha_client")


if __name__ == "__main__":
    asyncio.run(main())

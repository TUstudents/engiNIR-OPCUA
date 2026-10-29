"""
Server diagnostics: what a monitoring client can see.

Shows: the standard Part 5 diagnostics nodes below Server/ServerDiagnostics. The summary counters run all the time;
the per-session and per-subscription arrays are built when EnabledFlag is switched on, which needs the SecurityAdmin
role, as does reading the security diagnostics of the sessions (they show the channel's security mode and policy).
A user with the "user" role can read the summary and is refused the security array. The server side offers the same
numbers as Server.diagnostics.

Run: python examples/13_diagnostics.py

Spec: OPC 10000-5 v1.05, 6.3.3 (ServerDiagnosticsType), 6.3.4 (SessionsDiagnosticsSummaryType), 7.8 to 7.16
(diagnostics variable types) and 12.8 to 12.15 (diagnostics data types); OPC 10000-18 v1.05 (SecurityAdmin role).
"""

import asyncio
from typing import Any

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.users_file import UserRecord, hash_password, write_users

OBJECT_IDS = ua.ObjectIds
SUMMARY = ua.NodeId(OBJECT_IDS.Server_ServerDiagnostics_ServerDiagnosticsSummary)
ENABLED = ua.NodeId(OBJECT_IDS.Server_ServerDiagnostics_EnabledFlag)
SESSIONS = ua.NodeId(OBJECT_IDS.Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray)
SECURITY = ua.NodeId(OBJECT_IDS.Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray)
SUBSCRIPTIONS = ua.NodeId(OBJECT_IDS.Server_ServerDiagnostics_SubscriptionDiagnosticsArray)


class Ignore:
    def datachange_notification(self, node: Any, value: Any, data: Any) -> None:
        return None


async def read_status(client: Client, nodeid: ua.NodeId) -> Any:
    try:
        return await client.get_node(nodeid).read_value()
    except ua.UaStatusCodeError as error:
        return ua.StatusCode(error.code).name


async def main() -> None:
    with workdir() as directory:
        users = directory / "users.toml"
        write_users(
            users,
            [
                UserRecord("root", "security_admin", hash_password("root-secret-1")),
                UserRecord("alice", "user", hash_password("alice-secret-1")),
            ],
        )
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki", users=users)
        root = Client.quickstart(url, pki=directory / "client-pki", username="root", password="root-secret-1")
        alice = Client.quickstart(url, pki=directory / "client-pki", username="alice", password="alice-secret-1")
        await server.init()
        idx = await server.register_namespace("urn:enginir:example:diagnostics")
        counter = await server.nodes.objects.add_variable(idx, "Counter", 0)
        await pair(directory / "server-pki", directory / "client-pki", root.application_uri)

        async with server, root, alice:
            await root.get_node(ENABLED).write_value(True)
            subscription = await alice.create_subscription(200, Ignore())
            await subscription.subscribe_data_change(alice.get_node(counter.nodeid))
            async with asyncio.timeout(10):
                while not await root.get_node(SUBSCRIPTIONS).read_value():
                    await asyncio.sleep(0.05)

            summary = await root.get_node(SUMMARY).read_value()
            print(
                f"sessions: current {summary.CurrentSessionCount}, cumulated {summary.CumulatedSessionCount}; "
                f"subscriptions: current {summary.CurrentSubscriptionCount}"
            )
            sessions = await root.get_node(SESSIONS).read_value()
            print(
                "sessions in the array:",
                len(sessions),
                "; requests so far:",
                sum(s.TotalRequestCount.TotalCount for s in sessions),
            )
            security = await root.get_node(SECURITY).read_value()
            for entry in sorted(security, key=lambda s: s.ClientUserIdOfSession):
                policy = entry.SecurityPolicyUri.rsplit("#", 1)[-1]
                print(f"session of {entry.ClientUserIdOfSession}: {policy}, {entry.SecurityMode.name}")
            subscriptions = await root.get_node(SUBSCRIPTIONS).read_value()
            print("subscriptions:", [(s.PublishingInterval, s.MonitoredItemCount) for s in subscriptions])

            refused = await read_status(alice, SECURITY)
            print("alice reads the security diagnostics:", refused)
            assert isinstance(refused, str)
            assert server.diagnostics.summary().CurrentSessionCount == 2
    print("OK 13_diagnostics")


if __name__ == "__main__":
    asyncio.run(main())

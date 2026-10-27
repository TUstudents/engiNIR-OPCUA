import asyncio
import shutil
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from enginir_opcua import Server, ua, uamethod
from enginir_opcua.common.callback import CallbackType, ServerItemCallback
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.server.internal_server import InternalServer

from .support import NAMESPACE_URI, USER_NAME, USER_PASSWORD, SecurityCase

PLACEHOLDER_NAMESPACES = 4
SERVER_APPLICATION_URI = "urn:enginir:opcua:interop:server"


class SampleUsers:
    def get_user(
        self,
        iserver: InternalServer,
        username: str | None = None,
        password: str | None = None,
        certificate: object = None,
    ) -> User | None:
        if username is None:
            return User(role=UserRole.User)
        if username == USER_NAME and password == USER_PASSWORD:
            return User(role=UserRole.User, name=username)
        return None


@dataclass
class Observations:
    monitored_items: int = 0
    method_calls: list[tuple[float, int]] = field(default_factory=list)


@dataclass
class OurServer:
    server: Server
    url: str
    namespace: int
    observations: Observations


async def populate(server: Server, observations: Observations) -> tuple[int, asyncio.Task[None]]:
    namespace = await server.register_namespace(NAMESPACE_URI)
    for index in range(PLACEHOLDER_NAMESPACES):
        await server.register_namespace(f"urn:enginir:opcua:interop:placeholder:{index}")
    await server.register_namespace("http://test.org/UA/Alarms/")
    objects = server.nodes.objects
    scalars = {
        "Scalar_Static_Int32": ua.Variant(7, ua.VariantType.Int32),
        "Scalar_Static_Float": ua.Variant(1.5, ua.VariantType.Float),
        "Scalar_Static_String": ua.Variant("start", ua.VariantType.String),
        "Scalar_Simulation_Int32": ua.Variant(0, ua.VariantType.Int32),
        "Scalar_Simulation_Float": ua.Variant(0.0, ua.VariantType.Float),
        "Scalar_Simulation_String": ua.Variant("0", ua.VariantType.String),
    }
    for name, value in scalars.items():
        node = await objects.add_variable(ua.NodeId(name, namespace), ua.QualifiedName(name, namespace), value)
        await node.set_writable()

    @uamethod
    def add(parent: ua.NodeId, first: float, second: int) -> float:
        observations.method_calls.append((first, second))
        return first + second

    methods = await objects.add_object(ua.NodeId("Methods", namespace), ua.QualifiedName("Methods", namespace))
    await methods.add_method(
        ua.NodeId("Methods_Add", namespace),
        ua.QualifiedName("Methods_Add", namespace),
        add,
        [ua.VariantType.Float, ua.VariantType.UInt32],
        [ua.VariantType.Float],
    )

    async def simulate() -> None:
        counter = 0
        while True:
            counter += 1
            await server.get_node(ua.NodeId("Scalar_Simulation_Int32", namespace)).write_value(
                ua.Variant(counter, ua.VariantType.Int32)
            )
            await server.get_node(ua.NodeId("Scalar_Simulation_Float", namespace)).write_value(
                ua.Variant(counter / 2, ua.VariantType.Float)
            )
            await server.get_node(ua.NodeId("Scalar_Simulation_String", namespace)).write_value(
                ua.Variant(str(counter), ua.VariantType.String)
            )
            await asyncio.sleep(0.2)

    return namespace, asyncio.create_task(simulate())


@asynccontextmanager
async def serve(directory: Path, case: SecurityCase, trusted_clients: Path, port: int) -> AsyncIterator[OurServer]:
    observations = Observations()
    server = Server(user_manager=SampleUsers())
    server.allow_plaintext_password = case.policy is None
    await server.init()
    host = socket.gethostname()
    await server.set_application_uri(SERVER_APPLICATION_URI)
    url = f"opc.tcp://{host}:{port}/enginir-opcua/interop"
    server.set_endpoint(f"opc.tcp://0.0.0.0:{port}/enginir-opcua/interop")
    server.set_security_policy([case.server_policy])
    server.set_identity_tokens([ua.AnonymousIdentityToken, ua.UserNameIdentityToken])
    if case.policy is not None:
        await server.set_pki_directory(directory / "server-pki")
        shutil.copytree(trusted_clients, directory / "server-pki" / "trusted" / "certs", dirs_exist_ok=True)
    namespace, simulation = await populate(server, observations)

    def count_items(event: ServerItemCallback, *_: object) -> None:
        observations.monitored_items += len(event.request_params.ItemsToCreate)

    server.subscribe_server_callback(CallbackType.ItemSubscriptionCreated, count_items)
    async with server:
        try:
            yield OurServer(server, url, namespace, observations)
        finally:
            simulation.cancel()

"""
Custom enumerations and structures, defined at runtime and used by a client.

Shows: new_enum and new_struct to add DataTypes (with their definitions and encodings) to the address space,
Server.load_data_type_definitions to get Python classes for them, a variable that holds a structure, an array of
structures, and a client that reads the type definitions from the server and decodes the values.

The "Browsename collision" warnings that the built-in enumerations cause while the classes are generated are
silenced here; they are not about the types of this example.

Run: python examples/05_custom_types.py

Spec: OPC 10000-3 v1.05, 5.8 (DataType NodeClass), 8.48 (StructureDefinition) and 8.50 (EnumDefinition);
OPC 10000-6 v1.05, 5.2.4 (enumerations), 5.2.6 (structures) and 5.2.7 (structures with optional fields).
"""

import asyncio
import logging

from _common import free_port, pair, workdir

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.structures104 import new_enum, new_struct, new_struct_field


async def main() -> None:
    logging.getLogger("enginir_opcua.ua.uatypes").setLevel(logging.ERROR)
    with workdir() as directory:
        url = f"opc.tcp://127.0.0.1:{free_port()}/enginir-opcua/example/"
        server = Server.quickstart(url, pki=directory / "server-pki")
        client = Client.quickstart(url, pki=directory / "client-pki")
        await server.init()
        idx = await server.register_namespace("urn:enginir:example:types")

        state = await new_enum(server, idx, "ScanState", ["Idle", "Scanning", "Failed"])
        await new_struct(
            server,
            idx,
            "Scan",
            [
                new_struct_field("Id", ua.VariantType.UInt32),
                new_struct_field("Wavelengths", ua.VariantType.Double, array=True),
                new_struct_field("State", state),
                new_struct_field("Comment", ua.VariantType.String, optional=True),
            ],
        )
        await server.load_data_type_definitions()

        scan = ua.Scan(Id=1, Wavelengths=[1100.0, 1650.0, 2100.0], State=ua.ScanState.Scanning)
        last = await server.nodes.objects.add_variable(
            idx, "LastScan", ua.Variant(scan, ua.VariantType.ExtensionObject)
        )
        history = await server.nodes.objects.add_variable(
            idx,
            "Scans",
            [ua.Scan(Id=2, State=ua.ScanState.Idle, Comment="blank"), ua.Scan(Id=3, State=ua.ScanState.Failed)],
        )
        await pair(directory / "server-pki", directory / "client-pki", client.application_uri)

        async with server, client:
            await client.load_data_type_definitions()
            value = await client.get_node(last.nodeid).read_value()
            print("LastScan:", value.Id, value.State.name, list(value.Wavelengths))
            for item in await client.get_node(history.nodeid).read_value():
                print("Scans:", item.Id, item.State.name, item.Comment)
    print("OK 05_custom_types")


if __name__ == "__main__":
    asyncio.run(main())

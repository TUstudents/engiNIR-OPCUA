# engiNIR-OPCUA

[![PyPI][pypi-badge]][pypi]
[![Python][python-badge]][pypi]
[![CI][ci-badge]][ci]
[![Interoperability][interop-badge]][interop]
[![Documentation][docs-badge]][docs]
[![License: LGPL-3.0-or-later][license-badge]][copying]

**OPC UA for Python, from the lab bench to the plant floor: connect, serve and secure your devices in minutes.**

OPC UA is how machines, instruments and control systems share data. engiNIR-OPCUA lets you speak it from Python,
as a client that reads your PLC or as a server that puts your own device on the network, with the parts a real
project needs already built in.

- **Complete.** Subscriptions, methods, alarms and conditions, history, file transfer, certificate management and
  the companion models of whole industries, in one library, as a client and as a server.
- **Extended and hardened.** Built on opcua-asyncio, brought up to OPC UA 1.05, extended with the server features
  listed below and hardened against the attacks known for OPC UA servers.
- **Effortless.** Encrypted from the first connection, set up with four commands, written in a few lines of async or
  plain blocking Python.

```bash
uv add enginir-opcua          # or: pip install enginir-opcua
```

## A secure connection in one minute

Create a server and a client, make them trust each other, add a user:

```bash
enginir-opcua init server srv --endpoint opc.tcp://0.0.0.0:4840/demo/
enginir-opcua init client cli
enginir-opcua pair srv/pki cli/pki
enginir-opcua user add srv/users.toml alice --role user
```

Serve a value:

```python
import asyncio

from enginir_opcua import Server
from enginir_opcua.config import ServerConfig


async def main() -> None:
    server = Server(config=ServerConfig.from_toml("srv/server.toml"))
    await server.init()
    idx = await server.register_namespace("urn:example:demo")
    temperature = await server.nodes.objects.add_variable(idx, "Temperature", 21.5)
    async with server:
        while True:
            await asyncio.sleep(1)
            await temperature.write_value(await temperature.read_value() + 0.1)


asyncio.run(main())
```

Read it from another program, as `alice` (password in `ENGINIR_OPCUA_PASSWORD`):

```python
import asyncio

from enginir_opcua import Client


async def main() -> None:
    async with Client.quickstart("opc.tcp://localhost:4840/demo/", pki="cli/pki", username="alice") as client:
        idx = await client.get_namespace_index("urn:example:demo")
        temperature = await client.nodes.objects.get_child(f"{idx}:Temperature")
        print(await temperature.read_value())


asyncio.run(main())
```

That is a signed and encrypted channel, two certificates that trust each other and nobody else, and a user whose
role decides what `alice` may change. Connecting to a server you didn't set up works the same way: the first attempt
prints the `enginir-opcua trust` command for each side.

## What you can build

### Get machine data into Python

Read a production line into a script, a notebook or a database, with the blocking API if you don't want async:

```python
from enginir_opcua.sync import Client

with Client.quickstart("opc.tcp://192.168.0.10:4840", pki="pki") as client:
    line = [client.get_node(f"ns=3;s=Line1.{name}") for name in ("Temperature", "Pressure", "Speed")]
    print(client.read_values(line))
```

Subscriptions deliver every change as it happens, history reads fetch the past, and the server's own data types
arrive as Python objects (`load_data_type_definitions`).

### Turn an instrument into an OPC UA device

Companion specifications define how a kind of device looks on OPC UA, so every client already knows where to find
its serial number, its state and its data. Import them and create your device as an instance, with all mandatory
parts filled in. A spectrometer by the Analyser Devices (ADI) model:

```python
await server.import_xml("Opc.Ua.Di.NodeSet2.xml")
await server.import_xml("Opc.Ua.Adi.NodeSet2.xml")
di = await server.get_namespace_index("http://opcfoundation.org/UA/DI/")
adi = await server.get_namespace_index("http://opcfoundation.org/UA/ADI/")
spectrometer = await server.nodes.objects.add_object(idx, "Spectrometer", objecttype=ua.NodeId(1011, adi))
serial = await spectrometer.get_child([f"{di}:Identification", f"{di}:SerialNumber"])
await serial.write_value("SN-0001")
spectrum = await spectrometer.add_variable(idx, "Absorbance", [0.0] * 256)
```

The same works for lab devices (LADS), machines (Machinery) and every other model published as a NodeSet2 file.
[Example 07][ex-instrument] builds the complete spectrometer.

### Simulate a machine for testing

Your SCADA, MES or analytics code needs a machine to talk to, and the machine is in another country. Import the
NodeSet2 file its vendor ships and serve it; your tests and your CI get the same address space:

```python
server = Server.quickstart("opc.tcp://127.0.0.1:4840/machine/", pki="pki")
await server.init()
await server.import_xml("Machine.NodeSet2.xml")
async with server:
    ...  # write test values, run the tests
```

### Bridge a device that doesn't speak OPC UA

A scale on a serial port, a Modbus controller, a sensor with its own SDK: give each value a callback, and the device
is asked only when a client reads:

```python
weight = await device.add_variable(idx, "Weight", 0.0)
server.set_attribute_value_callback(weight.nodeid, lambda nodeid, attribute: ua.DataValue(scale.read_kg()))
```

### Run it in production

- history of values and events, in memory or SQLite ([example 06][ex-history])
- alarms and conditions that operators acknowledge and confirm ([example 12][ex-alarms])
- files and directories that clients read and write ([example 08][ex-files])
- certificates and trust lists managed remotely by a security administrator ([example 14][ex-certificates])
- reverse connect, so a server inside a protected network dials out to its clients ([example 16][ex-reverse])
- diagnostics of sessions and subscriptions ([example 13][ex-diagnostics])
- one TOML file for the whole configuration, served with `enginir-opcua server --config server.toml`

## What it supports from the standard

engiNIR-OPCUA follows OPC UA 1.05 (OPC 10000) and accepts peers that speak 1.04.

| Part | Supported |
|---|---|
| 3, 5 Address space and information model | custom object, variable, event and data types; structures, unions, enumerations and OptionSets with their DataTypeDefinition; NodeSet2 import and export; diagnostics and model change events |
| 4 Services | discovery and discovery server, sessions, browse, read and write, methods, node management, subscriptions for data changes and events, subscription transfer |
| 6 Mappings | `opc.tcp` with the binary encoding; Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss; anonymous, user name and X.509 users; reverse connect |
| 9 Alarms and conditions | conditions, acknowledgeable and limit alarms, refresh |
| 10 Programs | program state machines |
| 11 Historical access | raw values and events, stored in memory or SQLite |
| 12 Certificate management | push management of certificates and trust lists |
| 14 PubSub | UADP over UDP (experimental) |
| 20 File transfer | files and directories |
| Companion specifications | DI, ADI, LADS, Machinery and the other models published as NodeSet2 |

What is not supported yet, such as the ECC policies and WebSockets, is listed under
[Supported features and limits][limits].

Coming from asyncua? Most code moves over by changing the import; the [migration guide][migration] lists the rest.

## Command line

The same tool sets up certificates and users, serves a configuration and inspects any server:

```bash
enginir-opcua discover  -u opc.tcp://192.168.0.10:4840                         # endpoints and policies
enginir-opcua ls        -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n i=85   # browse the Objects folder
enginir-opcua read      -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n "ns=3;s=Line1.Temperature"
enginir-opcua subscribe -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n "ns=3;s=Line1.Temperature"
enginir-opcua write     -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n "ns=3;s=Line1.Setpoint" 185
```

No server at hand? `enginir-opcua server --pki-dir demo-pki --populate` starts one with sample nodes.

## Documentation

<https://enginir-opcua.readthedocs.io/>

- [Quick setup][quick-setup]: profiles, configuration files, users and roles, trusting certificates
- [Client][client], [Server][server] and the [blocking API][sync]
- [Examples][examples]: 17 runnable programs
- [Supported features and limits][limits]
- [Migrating from asyncua][migration] and the [CHANGELOG][changelog]

## Contributing

```bash
uv sync && git submodule update --init --depth 1 nodeset
uv run pytest -q -m "not slow"
```

Conventions for code and tests: [AGENTS.md][agents] and [tests/README.md][tests-readme].

## License

LGPL-3.0-or-later; see [COPYING][copying], [COPYING.GPL][copying-gpl] and [NOTICE][notice]. The original library
was written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors; this fork was made on 2026-10-25.

[pypi]: https://pypi.org/project/enginir-opcua/
[pypi-badge]: https://img.shields.io/pypi/v/enginir-opcua
[python-badge]: https://img.shields.io/pypi/pyversions/enginir-opcua
[ci]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/python-package.yml
[ci-badge]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/python-package.yml/badge.svg
[interop]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/interop.yml
[interop-badge]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/interop.yml/badge.svg
[docs]: https://enginir-opcua.readthedocs.io/en/latest/
[docs-badge]: https://readthedocs.org/projects/enginir-opcua/badge/?version=latest
[license-badge]: https://img.shields.io/badge/license-LGPL--3.0--or--later-blue
[copying]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/COPYING
[copying-gpl]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/COPYING.GPL
[notice]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/NOTICE
[changelog]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/CHANGELOG.md
[agents]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/AGENTS.md
[tests-readme]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/tests/README.md
[ex-history]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/06_events_and_history.py
[ex-instrument]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/07_instrument_server.py
[ex-files]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/08_file_transfer.py
[ex-alarms]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/12_alarms.py
[ex-diagnostics]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/13_diagnostics.py
[ex-certificates]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/14_certificate_management.py
[ex-reverse]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/16_reverse_connect.py
[migration]: https://enginir-opcua.readthedocs.io/en/latest/migration.html
[quick-setup]: https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/quick-setup.html
[client]: https://enginir-opcua.readthedocs.io/en/latest/usage/client/overview.html
[server]: https://enginir-opcua.readthedocs.io/en/latest/usage/server/overview.html
[sync]: https://enginir-opcua.readthedocs.io/en/latest/usage/sync/overview.html
[examples]: https://enginir-opcua.readthedocs.io/en/latest/usage/examples.html
[limits]: https://enginir-opcua.readthedocs.io/en/latest/usage/limits.html

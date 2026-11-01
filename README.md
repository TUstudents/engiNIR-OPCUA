# engiNIR-OPCUA

[![PyPI][pypi-badge]][pypi]
[![Python][python-badge]][pypi]
[![CI][ci-badge]][ci]
[![Interoperability][interop-badge]][interop]
[![Documentation][docs-badge]][docs]
[![License: LGPL-3.0-or-later][license-badge]][copying]

**OPC UA for Python: connect to machines and instruments, or make your own device an OPC UA server.**

engiNIR-OPCUA is a client and a server in one library, built on asyncio with a blocking API for scripts. It follows
OPC UA 1.05 and is tested on every push against the OPC Foundation's reference implementation.

```bash
uv add enginir-opcua          # or: pip install enginir-opcua
uv tool install enginir-opcua # only the enginir-opcua command line
```

## Client: read, write and subscribe

```python
import asyncio

from enginir_opcua import Client


class Print:
    def datachange_notification(self, node, value, data):
        print(node, value)


async def main() -> None:
    client = Client.quickstart("opc.tcp://192.168.0.10:4840", pki="pki", username="operator")
    async with client:
        temperature = client.get_node("ns=3;s=Line1.Temperature")
        print(await temperature.read_value())
        await client.get_node("ns=3;s=Line1.Setpoint").write_value(185.0)

        subscription = await client.create_subscription(500, Print())
        await subscription.subscribe_data_change(temperature)
        await asyncio.sleep(60)


asyncio.run(main())
```

The client keeps its certificate in `pki/` and reads the password from `ENGINIR_OPCUA_PASSWORD`. The first connect
fails until the server and the client trust each other's certificate; the error prints the `enginir-opcua trust`
command for each side.

The same without async, for scripts and notebooks:

```python
from enginir_opcua.sync import Client

with Client.quickstart("opc.tcp://192.168.0.10:4840", pki="pki") as client:
    print(client.get_node("ns=3;s=Line1.Temperature").read_value())
```

The client also browses the address space, calls methods, reads history and events, acknowledges alarms, decodes the
server's custom structures (`load_data_type_definitions`), transfers files, reconnects with its subscriptions after an
outage, and follows redundant servers (`HaClient`).

## Server: put your device on the network

```bash
enginir-opcua init server oven --endpoint opc.tcp://0.0.0.0:4840/oven/
enginir-opcua user add oven/users.toml alice --role user
```

```python
import asyncio
from datetime import timedelta

from enginir_opcua import Server, ua, uamethod
from enginir_opcua.config import ServerConfig


async def main() -> None:
    server = Server(config=ServerConfig.from_toml("oven/server.toml"))
    await server.init()
    idx = await server.register_namespace("urn:example:oven")
    oven = await server.nodes.objects.add_object(idx, "Oven")
    temperature = await oven.add_variable(idx, "Temperature", 20.0)
    setpoint = await oven.add_variable(idx, "Setpoint", 180.0)
    await setpoint.set_writable()

    @uamethod
    async def heat_to(parent, target: float) -> None:
        await setpoint.write_value(target)

    await oven.add_method(idx, "HeatTo", heat_to, [ua.VariantType.Double], [])
    await server.historize_node_data_change(temperature, period=timedelta(days=1))

    async with server:
        while True:
            await asyncio.sleep(1)
            current, target = await temperature.read_value(), await setpoint.read_value()
            await temperature.write_value(current + (target - current) * 0.1)


asyncio.run(main())
```

Anyone may read and subscribe; `alice` may also write the setpoint and call `HeatTo`. Clients can read the last day of
temperatures as history.

What else a server can offer, each with a runnable example:

- values read from the device only when a client asks (`set_attribute_value_callback`)
- methods with named, typed and documented arguments ([04][ex-methods])
- custom structures and enumerations that clients decode by themselves ([05][ex-types])
- events, and history of values and events in memory or SQLite ([06][ex-history])
- alarms and conditions that clients acknowledge and confirm ([12][ex-alarms])
- files and directories that clients read and write ([08][ex-files])
- the standard diagnostics of sessions and subscriptions ([13][ex-diagnostics])
- reverse connect, for a server behind a firewall that dials out to its clients ([16][ex-reverse])
- a TOML configuration file, and `enginir-opcua server --config` to serve it without code

**Companion models.** Import the NodeSets of the OPC UA companion specifications and create instances of their types
with all mandatory parts: Devices (DI), Analyser Devices (ADI) with `SpectrometerDeviceType`, LADS for lab devices,
Machinery and others. [Example 07][ex-instrument] builds a spectrometer with its spectrum and wavelength axis.

## Command line

```bash
enginir-opcua discover  -u opc.tcp://192.168.0.10:4840                         # endpoints and policies
enginir-opcua ls        -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n i=85   # browse the Objects folder
enginir-opcua read      -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n "ns=3;s=Line1.Temperature"
enginir-opcua subscribe -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n "ns=3;s=Line1.Temperature"
enginir-opcua write     -u opc.tcp://192.168.0.10:4840 --pki-dir pki -n "ns=3;s=Line1.Setpoint" 185
```

No server at hand? `enginir-opcua server --pki-dir demo-pki --populate` starts one with sample nodes.

## Why engiNIR-OPCUA

- **Tested against the reference.** On every push, CI builds the OPC Foundation's UA-.NETStandard stack and runs this
  client against its server and its client against this server: browse, read, write, methods, subscriptions,
  events, alarms, history, reconnect, subscription transfer and reverse connect.
- **Checked against the standard.** It started from opcua-asyncio 2.1.0; a review of the whole code against OPC UA
  1.05 found 422 problems, nearly 300 of them bugs. All are fixed or decided, each with a test, and the
  [CHANGELOG][changelog] cites the part of the specification behind every change.
- **Secure by default.** Endpoints are encrypted, nothing is trusted until you say so, and the server is hardened
  against the known attacks on OPC UA servers. The `legacy` and `development` profiles relax this for old devices
  and local tests, and log every relaxed setting.
- **Modern Python.** Python 3.12 and newer, asyncio with a blocking API on top, fully type-annotated and checked with
  strict mypy.

## Coming from asyncua

Most code moves over by changing the import to `enginir_opcua`, and both packages install side by side. The
[migration guide][migration] lists the changes you will meet.

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
[ex-methods]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/04_methods.py
[ex-types]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/05_custom_types.py
[ex-history]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/06_events_and_history.py
[ex-instrument]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/07_instrument_server.py
[ex-files]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/08_file_transfer.py
[ex-alarms]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/12_alarms.py
[ex-diagnostics]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/13_diagnostics.py
[ex-reverse]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/16_reverse_connect.py
[migration]: https://enginir-opcua.readthedocs.io/en/latest/migration.html
[quick-setup]: https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/quick-setup.html
[client]: https://enginir-opcua.readthedocs.io/en/latest/usage/client/overview.html
[server]: https://enginir-opcua.readthedocs.io/en/latest/usage/server/overview.html
[sync]: https://enginir-opcua.readthedocs.io/en/latest/usage/sync/overview.html
[examples]: https://enginir-opcua.readthedocs.io/en/latest/usage/examples.html
[limits]: https://enginir-opcua.readthedocs.io/en/latest/usage/limits.html

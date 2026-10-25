# engiNIR-OPCUA

OPC UA / IEC 62541 client and server library for Python 3.10+ and PyPy, built on asyncio.

engiNIR-OPCUA is a modified version of [FreeOpcUa/opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0, forked on 2026-10-25. It is published on PyPI as `enginir-opcua` and imported as `enginir_opcua`. The changes so far are the new package name and default application identity, and work on security and specification-conformance fixes. The original library was written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors.

License: LGPL-3.0-or-later. See [COPYING](COPYING), [COPYING.GPL](COPYING.GPL) and [NOTICE](NOTICE).

The API offers both a low-level interface to send and receive all UA defined structures and high-level classes for writing a server or a client in a few lines. Low-level and high-level calls can be mixed in one application. Most low-level code is generated from the OPC UA nodeset files. A synchronous wrapper over the async API is in `enginir_opcua.sync`.

# Warnings

engiNIR-OPCUA comes with absolutely no warranty. Version 3.0.0 will contain breaking changes compared to asyncua 2.x, including secure defaults. They are listed in the changelog when they land.

# Installation

With uv or pip:

    uv pip install enginir-opcua

## Migrating from asyncua

- Imports: replace `asyncua` with `enginir_opcua`, for example `from enginir_opcua import Client, Server, ua`.
- Command line tools: the names have an `enginir-` prefix, for example `enginir-uaread` and `enginir-uaserver`.
- Default identity: the server endpoint is `opc.tcp://0.0.0.0:4840/enginir-opcua/server/`, its ApplicationUri is `urn:enginir:opcua:server` and its ManufacturerName is `engiNIR`. The client ApplicationUri is `urn:enginir:opcua:client`. Set these explicitly if your peers or certificates depend on the old values.
- `enginir-opcua` and `asyncua` can be installed in the same environment.

# Usage

We assume that you already have some experience with Python, the asyncio module, the async / await syntax and the concept of asyncio Tasks.

## Client class

The `Client` class provides a high level API for connecting to OPC UA servers, session management and access to basic
address space services.
The client can be used as a context manager. The client will then automatically connect and disconnect withing the `with`syntax.

```python
from enginir_opcua import Client

async with Client(url="opc.tcp://localhost:4840/enginir-opcua/server/") as client:
    while True:
        # Do something with client
        node = client.get_node("i=85")
        value = await node.read_value()
```

Of course, you can also call the `connect`, `disconnect` methods yourself if you do not want to use the context manager.

See the example folder and the code for more information on the client API.

## Node class

The `Node` class provides a high level API for management of nodes as well as data access services.

## Subscription class

The `Subscription` class provides a high level API for management of monitored items.

## Server class

The `Server` class provides a high level API for creation of OPC UA server instances.

# Documentation

The documentation is available here [ReadTheDocs](http://opcua-asyncio.readthedocs.org/en/latest/).

The API remains mostly unchanged with regards to [python-opcua](http://opcua-asyncio.rtfd.io/).
The main difference is that most methods are now asynchronous.
Please have a look at [the examples](examples) and/or the code.

A simple GUI client is available at: https://github.com/FreeOpcUa/opcua-client-gui

Browse the examples: [examples](examples)

The minimal examples are a good starting point.
Minimal client example: [examples/client-minimal.py](examples/client-minimal.py)
Minimal server example: [examples/server-minimal.py](examples/server-minimal.py)

A set of command line tools also available: [tools](tools)

- `enginir-uadiscover `(find_servers, get_endpoints and find_servers_on_network calls)
- `enginir-uals `(list children of a node)
- `enginir-uahistoryread`
- `enginir-uaread `(read attribute of a node)
- `enginir-uawrite `(write attribute of a node)
- `enginir-uacall `(call method of a node)
- `enginir-uasubscribe `(subscribe to a node and print datachange events)
- `enginir-uaclient `(connect to server and start python shell)
- `enginir-uaserver `(starts a demo OPC UA server)
  `tools/uaserver --populate --certificate cert.pem --private_key pk.pem`

How to generate certificate: [examples/generate_certificate.sh](examples/generate_certificate.sh)

## Client support

What works:

- connection to server, opening channel, session
- browsing and reading attributes value
- getting nodes by path and nodeids
- creating subscriptions
- subscribing to items for data change
- subscribing to events
- adding nodes
- method call
- user and password
- history read
- login with certificate
- communication encryption
- removing nodes

Tested servers: freeopcua C++, freeopcua Python, prosys, kepware, beckhoff, winCC, B&R, …

Not implemented yet:

- localized text feature
- XML protocol
- WebSocket
- maybe automatic reconnection...

## Server support

What works:

- creating channel and sessions
- read/set attributes and browse
- getting nodes by path and nodeids
- autogenerate address space from spec
- adding nodes to address space
- datachange events
- events
- methods
- basic user implementation (one existing user called admin, which can be disabled, all others are read only)
- encryption
- certificate handling
- removing nodes
- history support for data change and events
- more high level solution to create custom structures

Tested clients: freeopcua C++, freeopcua Python, uaexpert, prosys, quickopc

Not yet implemented:

- WebSocket
- session restore
- alarms
- XML protocol
- views
- localized text features
- better security model with users and password

### Running a server on a Raspberry Pi

Setting up the standard address-space from XML is the most time-consuming step of the startup process which may lead to
long startup times on less powerful devices like a Raspberry Pi. By passing a path to a cache-file to the server constructor,
a shelve holding the address space will be created during the first startup. All following startups will make use of the
cache-file which leads to significantly better startup performance (~3.5 vs 125 seconds on a Raspberry Pi Model B).

# Development

Code follows PEP8 apart for line lengths which should be max 160 characters and OPC UA structures that keep camel case
from XML definition.

All protocol code is under opcua directory

- `enginir_opcua/ua` contains all UA structures from specification, most are autogenerated
- `enginir_opcua/common` contains high level objects and methods used both in server and client
- `enginir_opcua/client` contains client specific code
- `enginir_opcua/server` contains server specific code
- `enginir_opcua/utils` contains some utilities function and classes
- `enginir_opcua/tools` contains code for command lines tools
- `schemas` contains the XML and text files from specification and the python scripts used to autogenerate code
- `tests` contains tests
- `docs` contains files to auto generate documentation from doc strings
- `examples` contains many example files
- `examples/sync` contains many example files using sync API
- `tools` contains python scripts that can be used to run command line tools from repository without installing

## Running a command for testing:

```
uv run enginir-uals -u opc.tcp://localhost:4840/myserver
```

## Running tests:

```
uv run pytest -v -s tests
```

## Coverage

```
uv run pytest -v -s --cov enginir_opcua --cov-report=html
```

## Linting

To apply linting checks (including ruff, and mypy) at each commit run,

```bash
uv run ruff check .
uv run mypy enginir_opcua tests
```

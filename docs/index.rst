:html_theme.sidebar_secondary.remove:

=============
engiNIR-OPCUA
=============

.. rst-class:: lead

    An OPC UA client and server for Python, built on asyncio and secure from the first line.

engiNIR-OPCUA implements OPC UA (IEC 62541) for Python 3.12 and newer: clients, servers, subscriptions, events,
alarms, history, methods, file transfer, redundancy and PubSub. Encrypted connections, certificate trust and user
roles are switched on by default, and every one of them can be set up in a few lines.

.. code-block:: console

    uv add enginir-opcua

.. tab-set::

    .. tab-item:: Setup

        .. code-block:: console

            enginir-opcua init server srv --endpoint opc.tcp://127.0.0.1:4840/demo/
            enginir-opcua init client cli
            enginir-opcua pair srv/pki cli/pki
            enginir-opcua user add srv/users.toml alice --role user

    .. tab-item:: Server

        .. code-block:: python

            import asyncio

            from enginir_opcua import Server


            async def main() -> None:
                server = Server.quickstart("opc.tcp://127.0.0.1:4840/demo/", pki="srv/pki", users="srv/users.toml")
                await server.init()
                idx = await server.register_namespace("urn:example:demo")
                temperature = await server.nodes.objects.add_variable(idx, "Temperature", 21.5)
                async with server:
                    while True:
                        await asyncio.sleep(1)
                        await temperature.write_value(await temperature.read_value() + 0.1)


            asyncio.run(main())

    .. tab-item:: Client

        .. code-block:: python

            import asyncio

            from enginir_opcua import Client


            async def main() -> None:
                client = Client.quickstart("opc.tcp://127.0.0.1:4840/demo/", pki="cli/pki", username="alice")
                async with client:
                    idx = await client.get_namespace_index("urn:example:demo")
                    temperature = await client.nodes.objects.get_child(f"{idx}:Temperature")
                    print(await temperature.read_value())


            asyncio.run(main())

The setup commands create both PKI directories and a user; nothing is trusted automatically, so
``enginir-opcua pair`` makes the two directories trust each other. The client reads the password of ``alice`` from
``ENGINIR_OPCUA_PASSWORD``. :doc:`usage/get-started/quick-setup` explains every step.


Start here
==========

.. grid:: 1 2 2 3
    :gutter: 3

    .. grid-item-card:: :octicon:`rocket` Quick setup
        :link: usage/get-started/quick-setup
        :link-type: doc

        A secure server and client, the two profiles, configuration files, users and the trust commands.

    .. grid-item-card:: :octicon:`book` OPC UA basics
        :link: usage/get-started/opc-ua-basics
        :link-type: doc

        Nodes, namespaces, endpoints, security and sessions: the terms the rest of the documentation uses.

    .. grid-item-card:: :octicon:`arrow-switch` Migrating from asyncua
        :link: migration
        :link-type: doc

        What changes when you move an application from ``asyncua`` 2.x, and the first things to update.

    .. grid-item-card:: :octicon:`device-desktop` Client
        :link: usage/client/overview
        :link-type: doc

        Connect, browse, read and write, call methods, subscribe, and survive a lost connection or a failed server.

    .. grid-item-card:: :octicon:`server` Server
        :link: usage/server/overview
        :link-type: doc

        Endpoints, the security defaults, users and roles, methods and events, logging and observing.

    .. grid-item-card:: :octicon:`code` Examples
        :link: usage/examples
        :link-type: doc

        Sixteen runnable programs, from a secure pair to alarms, history, file transfer and reverse connect.

    .. grid-item-card:: :octicon:`sync` Synchronous API
        :link: usage/sync/overview
        :link-type: doc

        The same client and server for programs, scripts and notebooks that don't use ``asyncio``.

    .. grid-item-card:: :octicon:`broadcast` PubSub
        :link: usage/pubsub/overview
        :link-type: doc

        Publish and subscribe over UDP with UADP messages, without sessions. Experimental.

    .. grid-item-card:: :octicon:`file-code` API reference
        :link: api/index
        :link-type: doc

        Every public module, class and function, generated from the source.


Secure by default
=================

.. grid:: 1 1 2 2
    :gutter: 3

    .. grid-item::

        **Encrypted endpoints.** The quick setup offers SignAndEncrypt with Basic256Sha256, Aes128_Sha256_RsaOaep
        and Aes256_Sha256_RsaPss. An endpoint without security exists only when you ask for it.

    .. grid-item::

        **Explicit trust.** Certificates are checked in the order of OPC 10000-4 on both sides of every secure
        channel. Server and client trust nobody until you put a certificate into the PKI directory.

    .. grid-item::

        **Users and roles.** Anonymous sessions may read, browse and subscribe. Writing, calling methods and changing
        the address space need a user with the right role; passwords are stored as salted hashes.

    .. grid-item::

        **Clear errors.** A wrong setting raises a ``ConfigurationError`` that names it, and a refused certificate
        tells you its thumbprint and the command that trusts it.


About the project
=================

engiNIR-OPCUA is a fork of `opcua-asyncio <https://github.com/FreeOpcUa/opcua-asyncio>`_ 2.1.0, made on 2026-10-25.
The original library was written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors. The import package
is ``enginir_opcua`` and the commands start with ``enginir-opcua``, so it can be installed next to ``asyncua``.

- Source code and issues: https://github.com/TUstudents/engiNIR-OPCUA
- Package: https://pypi.org/project/enginir-opcua/
- Changes: `CHANGELOG.md <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/CHANGELOG.md>`_
- License: LGPL-3.0-or-later

.. toctree::
    :hidden:

    usage/index
    migration
    api/index

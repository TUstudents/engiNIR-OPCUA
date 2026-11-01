:html_theme.sidebar_secondary.remove:

=============
engiNIR-OPCUA
=============

.. rst-class:: lead

    OPC UA for Python, from the lab bench to the plant floor: connect, serve and secure your devices in minutes.

engiNIR-OPCUA is a client and a server in one library, built on asyncio with a blocking API for scripts. It follows
OPC UA 1.05; :doc:`usage/limits` lists what it covers.

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

        A secure server and client, the three profiles, configuration files, users and the trust commands.

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

        Seventeen runnable programs, from a secure pair to alarms, history, file transfer and reverse connect.

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


Why engiNIR-OPCUA
=================

.. grid:: 1 1 3 3
    :gutter: 3

    .. grid-item::

        **Complete.** Subscriptions, methods, alarms and conditions, history, file transfer, certificate management
        and the companion models of whole industries, as a client and as a server.

    .. grid-item::

        **Extended and hardened.** Built on opcua-asyncio, brought up to OPC UA 1.05, extended with server-side
        alarms, file transfer, certificate management and reverse connect, and hardened against the attacks known for
        OPC UA servers.

    .. grid-item::

        **Effortless.** Encrypted from the first connection, set up with four commands, written in a few lines of
        async or plain blocking Python.


About the project
=================

engiNIR-OPCUA is a fork of `opcua-asyncio <https://github.com/FreeOpcUa/opcua-asyncio>`_ 2.1.0, made on 2026-10-25.
The original library was written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors. The import package
is ``enginir_opcua`` and the commands start with ``enginir-opcua``, so it can be installed next to ``asyncua``.

- Source code: https://github.com/TUstudents/engiNIR-OPCUA
- Package: https://pypi.org/project/enginir-opcua/
- Changes: `CHANGELOG.md <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/CHANGELOG.md>`_
- License: LGPL-3.0-or-later

.. toctree::
    :hidden:

    usage/index
    migration
    api/index

=======================
A Minimal OPC-UA Server
=======================

Let's start exploring the :code:`enginir_opcua` package by building a minimal runnable server.
It is secure from the start: only encrypted and signed connections are offered, and a client has to be
trusted before it can connect. The :doc:`quick-setup` page explains the pieces; this page builds a server you can
keep running, and :doc:`minimal-client` the client for it. Both in one process are in
`01_secure_pair.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/01_secure_pair.py>`_.

Preparing the certificates and a user
=====================================

A server needs a PKI directory with its certificate, and a client that is allowed to connect needs one too. The
command line sets both up for development on one machine:

.. code-block:: console

    $ enginir-opcua init server srv --endpoint opc.tcp://127.0.0.1:4840/enginir-opcua/server/
    $ enginir-opcua init client cli --application-uri urn:enginir:opcua:client
    $ enginir-opcua pair srv/pki cli/pki
    $ enginir-opcua user add srv/users.toml alice --role user

``pair`` makes the two directories trust each other, and it says that it is for one machine only; on a network you
move the certificates yourself with ``enginir-opcua trust``. ``user add`` asks for a password and stores only a salted
hash. A user with the role ``user`` may read, write and call methods; anonymous clients may only read.

The server
==========

.. code-block:: python
    :caption: server.py

    import asyncio

    from enginir_opcua import Server, ua, uamethod


    @uamethod
    def multiply(parent: ua.NodeId, x: float, y: float) -> float:
        return x * y


    async def main() -> None:
        server = Server.quickstart(
            "opc.tcp://127.0.0.1:4840/enginir-opcua/server/", pki="srv/pki", users="srv/users.toml"
        )
        await server.init()
        idx = await server.register_namespace("urn:example:minimal")

        my_object = await server.nodes.objects.add_object(idx, "MyObject")
        my_variable = await my_object.add_variable(idx, "MyVariable", 6.7)
        await my_variable.set_writable()
        await server.nodes.objects.add_method(
            idx, "multiply", multiply, [ua.VariantType.Double, ua.VariantType.Double], [ua.VariantType.Double]
        )

        async with server:
            count = 0.0
            while True:
                await asyncio.sleep(1)
                count += 0.1
                await my_variable.write_value(count)


    asyncio.run(main())

Run it with :code:`python server.py`.

Setup and configuration
=======================

:meth:`Server.quickstart() <enginir_opcua.server.server.Server.quickstart>` returns a configured server with the
``secure`` profile: Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, always SignAndEncrypt.
:meth:`~enginir_opcua.server.server.Server.init` creates the PKI directory when it is missing and loads the
certificate. A custom namespace is registered with
:meth:`~enginir_opcua.server.server.Server.register_namespace`. It's recommended that all custom objects, variables
and methods live in a namespace of their own. We store its index as :code:`idx` and use it to add our objects.

Creating objects, variables and methods
=======================================

:meth:`~enginir_opcua.common.node.Node.add_object` and :meth:`~enginir_opcua.common.node.Node.add_variable` create the
object "MyObject" and a variable below it. By default all variables are read-only, so we are explicit and make it
writable. A method is a Python function decorated with :meth:`~enginir_opcua.common.methods.uamethod`, registered with
:meth:`~enginir_opcua.common.node.Node.add_method` together with the types of its arguments. An undecorated function
works too, but then the conversion from and to UA Variant types is up to you. Methods with named arguments are in
`04_methods.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/04_methods.py>`_.

Starting the server
===================

Using the server as a context manager with :code:`async with server: ...` starts it and shuts it down cleanly. To keep
it alive a loop is needed; here the loop also updates the variable once a second.

Looking at it from the command line
===================================

The command line tools (see :ref:`usage/get-started/installation:command line tools`) can connect with a secure
channel by pointing them at the client's PKI directory. They use the ApplicationUri
:code:`urn:enginir:opcua:client`, which is why the client was initialised with it above.

.. code-block:: console

    $ enginir-opcua ls -u opc.tcp://127.0.0.1:4840/enginir-opcua/server/ --pki-dir cli/pki \
          --security Basic256Sha256,SignAndEncrypt -n i=85
    $ enginir-opcua read -u opc.tcp://127.0.0.1:4840/enginir-opcua/server/ --pki-dir cli/pki \
          --security Basic256Sha256,SignAndEncrypt --user alice -p "0:Objects,2:MyObject,2:MyVariable"

The second command reads the password from the environment variable :code:`ENGINIR_OPCUA_PASSWORD` or asks for it
with :code:`--ask-password`.

Now that we have a working server, let's go on and write :ref:`usage/get-started/minimal-client:a minimal opc-ua client`!

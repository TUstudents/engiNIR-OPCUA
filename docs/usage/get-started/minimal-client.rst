=======================
A Minimal OPC-UA Client
=======================

In this section we will build a client which reads and writes data of the server created in the last section and
calls the method which the server provides. Running the client code requires a running server of course, so open a new
terminal and run :code:`python server.py` to start it. The certificates and the user ``alice`` were set up in
:doc:`minimal-server`.

.. code-block:: python
    :caption: client.py

    import asyncio

    from enginir_opcua import Client


    async def main() -> None:
        client = Client.quickstart(
            "opc.tcp://127.0.0.1:4840/enginir-opcua/server/",
            pki="cli/pki",
            username="alice",
            password="alices-password",
            application_uri="urn:enginir:opcua:client",
        )
        async with client:
            idx = await client.get_namespace_index("urn:example:minimal")
            my_variable = await client.nodes.objects.get_child([f"{idx}:MyObject", f"{idx}:MyVariable"])
            print("MyVariable:", await my_variable.read_value())
            await my_variable.write_value(3.9)
            print("MyVariable after the write:", await my_variable.read_value())
            result = await client.nodes.objects.call_method(f"{idx}:multiply", 3, 7)
            print("multiply(3, 7) =", result)


    asyncio.run(main())

Put the real password in an environment variable instead of the source: leave out ``password`` and set
``ENGINIR_OPCUA_PASSWORD``, which :meth:`Client.quickstart() <enginir_opcua.client.client.Client.quickstart>` reads when
no password is given.

Connecting to the server
========================

:meth:`Client.quickstart() <enginir_opcua.client.client.Client.quickstart>` creates a
:class:`~enginir_opcua.client.client.Client` with the ``secure`` profile: Basic256Sha256 with SignAndEncrypt. The
client's PKI directory has to hold the server's certificate in ``trusted/certs`` (``enginir-opcua pair`` did that), or
the connection fails with an error that names the thumbprint and the command to trust it. The client supports the same
async context manager as the server, which opens and closes the connection for us. Without ``username`` the session is
anonymous and read-only.

Getting the namespace
=====================

As all our custom objects live in a custom namespace, we need the namespace index to address them. This is done with
:meth:`~enginir_opcua.client.client.Client.get_namespace_index`. The list of all namespaces of the server is returned by
:meth:`~enginir_opcua.client.client.Client.get_namespace_array`.

Read / Write Variables
======================

To read or write a variable of an object, we first need its :class:`~enginir_opcua.common.node.Node`. The
:meth:`~enginir_opcua.common.node.Node.get_child` method of the Objects node (which is just a regular node) turns the
known path into a Node.

.. note:: Using :meth:`~enginir_opcua.common.node.Node.get_child` will perform a server request
    in the background to resolve the path to a node. Extensive usage of this method can
    create a lot of network traffic which is not strictly required if the node id is known.
    If you know the node id it's better to use the :meth:`~enginir_opcua.client.client.Client.get_node`
    method of the client. For example :code:`client.get_node("ns=2;i=2")` or
    :code:`client.get_node(ua.NodeId(2, 2))` could be used in the example.
    Note that the latter call is not :code:`async`!

Once we have our node object, the variable value can be read or written directly using
the :meth:`~enginir_opcua.common.node.Node.read_value` and :meth:`~enginir_opcua.common.node.Node.write_value`
methods. The read method automatically transforms the opc-ua type to a python type but the
:meth:`~enginir_opcua.common.node.Node.read_data_value` method can be used if the original type of
the variable is of interest. The write interface is built flexible and a :class:`~enginir_opcua.ua.uatypes.Variant`
is also accepted to specify the exact type to be used. A write needs the role ``user``; an anonymous client is refused
with ``BadUserAccessDenied`` (see `02_users_and_roles.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/02_users_and_roles.py>`_).

Calling Methods
===============

The method interface is similar to the interface of variables. In the example the special
node :code:`client.nodes.objects`, which is in fact just a shortcut to the :code:`0:Objects`
node, is used to call the method. The :meth:`~enginir_opcua.common.node.Node.call_method`
must be called on the parent node of the actual method node.

Where to go next
================

Subscriptions and reconnecting are in `03_read_write_subscribe.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/03_read_write_subscribe.py>`_, and the whole list of
examples is on the :doc:`quick-setup` page.

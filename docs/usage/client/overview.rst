===============
Client Overview
===============

This page walks through what a client does, in the order an application meets it: create it, set its security, connect,
find nodes, read and write, subscribe, and cope with a lost connection. The code is asynchronous; the same things in
a program without ``asyncio`` are on the page :doc:`../sync/overview`.

Creating a client
=================

Create a :class:`enginir_opcua.client.client.Client` with the URL of the server. The URL has the form
``opc.tcp://<host>:<port>[/<path>]``; the port is usually 4840, but check the documentation of your server. A user name and
password may be part of the URL (``opc.tcp://user:password@host:4840``), but then they show up in the process list and in
the shell history; use ``client.set_user()`` and ``client.set_password()`` instead.

.. code-block:: python

    from enginir_opcua import Client

    client = Client("opc.tcp://localhost:4840/enginir-opcua/server/", timeout=4)

``timeout`` is the time in seconds that every request may take. The other constructor arguments are
``watchdog_intervall``, ``auto_reconnect`` and its two delays (see `Losing the connection`_),
``allow_deprecated_policies`` and ``observer`` (see :doc:`../common/observer`).

Connecting to a server
======================

``connect()`` opens the socket, the SecureChannel and a Session; ``disconnect()`` closes them. The client is an async
context manager, which does both:

.. code-block:: python

    async with Client(url) as client:
        value = await client.nodes.root.read_browse_name()

Without ``async with``, call ``await client.connect()`` and make sure ``await client.disconnect()`` runs, for example in a
``finally`` block.

Security
--------

A client without any security setting uses the SecurityPolicy *None*: nothing is signed or encrypted, and the server must
offer that endpoint. For a secure channel, set the policy before you connect:

.. code-block:: python

    from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
    from enginir_opcua import ua

    client = Client(url)
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate="client-cert.der",
        private_key="client-key.pem",
        server_certificate="server-cert.der",
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    await client.connect()

The same in one string: ``await client.set_security_string("Basic256Sha256,SignAndEncrypt,client-cert.der,client-key.pem,server-cert.der")``.

.. note:: ``set_security()`` and ``set_security_string()`` ask the server for its endpoints, so they use a connection of
   their own. They need a client that is *not* connected: call them before ``connect()``, and call ``disconnect()`` first
   if the client is connected. Otherwise they raise ``ConnectionError`` ("already connected").

A secure channel needs trust in both directions. The client trusts nothing until it is told to:

- pass ``server_certificate=`` to ``set_security()``; the certificate is *pinned*, and no other server certificate is
  accepted; or
- use a PKI directory with ``await client.set_pki_directory("pki")``; its ``own/`` folder holds the certificate and key
  of the client, and a server certificate in ``trusted/`` is trusted (see :doc:`../common/pki-directory`); or
- pass a trust store: ``client.set_trust_store(TrustStore([...], [...]))``.

A server certificate that is not trusted makes ``connect()`` fail, and the certificate is saved in ``rejected/certs`` of the
PKI directory so that you can look at it and move it to ``trusted/certs``. Nothing is trusted automatically. The server only
learns that the security check failed; the client's exception names the reason.

Who is connecting
-----------------

Without further settings the client connects as Anonymous. For a user name and password call ``client.set_user("name")``
and ``client.set_password("secret")`` before ``connect()``. For a user certificate use ``load_client_certificate`` and
``load_private_key`` (they hold the certificate and key of the *user*, not of the application). The server decides what each user may do.

Namespaces
==========

Nodes of a server live in namespaces; a NodeId is a namespace *index* and an identifier. The indices belong to one server
and can change when the server restarts, so look them up by URI:

.. code-block:: python

    idx = await client.get_namespace_index("urn:example:my-namespace")
    array = await client.get_namespace_array()

``get_namespace_index`` raises an error if the server does not know the URI. ``register_namespace`` adds a URI to the
server's namespace array if the server lets you write it. When the server has custom structures or enumerations, load their
definitions after connecting with ``await client.load_data_type_definitions()``; the classes appear in the
:mod:`enginir_opcua.ua` module and in ``client.types``.

Browsing and accessing nodes
============================

``client.nodes`` has the commonly used nodes (``root``, ``objects``, ``server``, ``types``, ...). Any node can be found by its
NodeId or by a browse path from another node:

.. code-block:: python

    objects = client.nodes.objects
    variable = await objects.get_child(["2:MyObject", "2:MyVariable"])
    same = client.get_node("ns=2;i=2")

    children = await objects.get_children()
    value = await variable.read_value()
    await variable.write_value(3.5)

Each call of ``get_child`` and ``get_children`` is a request to the server. When you read many nodes, use the methods of
the client that take lists (``read_values``, ``write_values``, ``read_attributes``, ``browse_nodes``); they send one request
for all nodes. Writing needs a user the server allows to write. ``write_value`` converts a Python value to the data type
of the node; pass a :class:`enginir_opcua.ua.Variant` or a DataValue when you need to control the type.

Calling methods
---------------

``await parent.call_method("2:MethodName", arg1, arg2)`` calls a method of an object. The arguments are converted to the
types the method declares; the result is the output value, or a list when the method has several outputs.

Subscriptions
=============

A subscription asks the server to send a notification when a value changes or an event occurs. There are two ways to receive
them.

*Handler mode*: pass an object with the methods ``datachange_notification(node, value, data)``,
``event_notification(event)`` and ``status_change_notification(status)``. The methods may be ``async``. A handler runs on the
event loop, one call after another for one subscription; keep it short.

.. code-block:: python

    class Handler:
        async def datachange_notification(self, node, value, data):
            print(node, value)

    subscription = await client.create_subscription(500, Handler())
    await subscription.subscribe_data_change(variable)

*Iterator mode*: without a handler, iterate over the subscription. The events come as ``DataChangeEvent``, ``OpcEvent`` and
``StatusChangeEvent`` objects:

.. code-block:: python

    async with await client.create_subscription(500) as subscription:
        await subscription.subscribe_data_change(variable)
        async for event in subscription:
            print(event.node, event.value)

The first argument is the publishing interval in milliseconds. The two modes exclude each other for one subscription. If the
application is slower than the server, a subscription in iterator mode keeps the newest ``queue_maxsize`` events (1000 by
default) and drops the oldest; a drop is logged and counted in ``Subscription.dropped_events``. Delete a subscription with
``await subscription.delete()``; leaving the ``async with`` block does that.

Losing the connection
=====================

By default a client that loses its connection stays disconnected: calls raise an error, and ``connection_lost_callback``, if
set, is called. With ``Client(url, auto_reconnect=True)`` a supervisor task watches the connection and, when it is lost,
opens a new channel, activates the old Session (or creates a new one if the server dropped it), recreates the subscriptions the
server lost and fetches the notifications it can still republish. Requests made meanwhile wait until the connection is back
or ``reconnect_request_timeout`` (60 s) passes. ``reconnect_max_delay`` (30 s) caps the wait between attempts, which grows
by doubling.

``client.state`` is one of ``disconnected``, ``connecting``, ``socket_open``, ``channel_open``, ``connected``,
``reconnecting`` and ``disconnecting``. To wait for a state without a race, use

.. code-block:: python

    async with client.subscribe_state() as states:
        await states.wait_for_state(UaClientState.CONNECTED)

where ``UaClientState`` is in ``enginir_opcua.client.ua_client``.

To keep a Session across a restart of the *client* program, set ``client.session_state_path`` to a file before connecting;
the client writes the session token there and tries to activate that Session next time instead of creating a new one.

Redundant servers
=================

For servers that form a redundant set (OPC 10000-4, 6.6), :class:`enginir_opcua.client.ha.ha_client.HaClient` keeps one
client per server, picks the one to use from the ServiceLevel and moves the subscriptions when it fails over. Only the warm
mode is implemented. See the docstrings of the :mod:`enginir_opcua.client.ha` package.

Errors
======

A service that the server answers with a Bad status raises a subclass of
:class:`enginir_opcua.ua.uaerrors.UaStatusCodeError`, for example ``BadNodeIdUnknown``; ``except
ua.uaerrors.BadNodeIdUnknown`` catches it. A request that gets no answer in ``timeout`` seconds raises ``TimeoutError``; a lost
connection raises ``ConnectionError`` or a Bad status for the closed channel. A wrong setting (an unknown policy, a missing
certificate) raises ``ConfigurationError`` before any connection is made.

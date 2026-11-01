===============
Server Overview
===============

A :class:`enginir_opcua.server.server.Server` owns an address space, listens on one endpoint and serves the OPC UA
services to the clients that connect. This page covers how to configure it and what to know before you run it for real.
The first server is built step by step in :doc:`../get-started/minimal-server`.

Creating and starting a server
==============================

.. code-block:: python

    from enginir_opcua import Server

    server = Server.quickstart("opc.tcp://0.0.0.0:4840/enginir-opcua/server/", pki="pki", users="users.toml")
    await server.init()
    idx = await server.register_namespace("urn:example:my-namespace")

    async with server:
        ...

``Server.quickstart`` takes a profile and any setting of :class:`~enginir_opcua.config.ServerConfig`;
``Server(config=ServerConfig.from_toml("server.toml"))`` reads the same settings from a file that
``enginir-opcua init server`` writes (see :doc:`../get-started/quick-setup`). ``init()`` builds the standard address
space, which takes a moment; pass a cache file (``init(shelf_file)``) to make later starts faster. ``async with
server`` calls ``start()`` and ``stop()``. Add your own nodes with
``server.nodes.objects.add_object(...)`` and the other ``add_*`` methods before or after the start; give them a namespace
that you registered.

Endpoints
=========

The server listens on one TCP address given by ``set_endpoint``; the host part is the interface to bind to, ``0.0.0.0`` for
all of them, and the URL is what clients are told to connect to. Behind NAT or in a container, where the client reaches the
server under another address than the one it binds, set ``server.socket_address`` to the address to bind.

Every combination of SecurityPolicy and MessageSecurityMode that the server allows is offered as an endpoint, with the user
token types that the user manager accepts. The profiles ``secure``, ``development`` and ``legacy`` set the defaults of all
security settings; see :doc:`../common/security`.

Security defaults
=================

- The endpoint without security (policy *None*) is **off**. Turn it on for tests and closed networks with
  ``Server(allow_no_security=True)``; the server then warns at start.
- The policies Basic256Sha256, Aes128Sha256RsaOaep and Aes256Sha256RsaPss are on, each with SignAndEncrypt only.
  ``server.set_security_policy([...])`` chooses the set and accepts every policy and mode, the deprecated Basic128Rsa15
  and Basic256 and the Sign modes included; naming one is the request, and the server warns for each weak endpoint.
- The server trusts no client certificate until it is told which ones to trust. Give it a PKI directory with
  ``await server.set_pki_directory("pki")`` (see :doc:`../common/pki-directory`) or a trust store with
  ``server.set_trust_store(...)``. A rejected client certificate is saved in ``rejected/certs`` for you to look at; the client
  is only told that the security check failed.
- The ApplicationUri of the server (``await server.set_application_uri(...)``) has to be in its certificate; set it before
  you create or load the certificate.

Users
=====

The *user manager* decides who a user is. The default, ``AnonymousReadOnlyUserManager``, accepts anonymous sessions and
gives them the read-only role. For other users pass a manager to the constructor:

.. code-block:: python

    from enginir_opcua.server.user_managers import CertificateUserManager

    server = Server(user_manager=CertificateUserManager())
    await server.user_manager.add_user("client.der", "operator")

``CertificateUserManager`` knows users by their X509 certificate. ``PermissiveUserManager`` accepts every user name and
password and is for tests only. To use your own database, subclass ``UserManager`` and implement ``get_user``; it returns a
``User`` with a role (``Anonymous``, ``User``, ``Admin`` or ``SecurityAdmin``) or ``None`` to refuse. The users file
of the quick setup (``FileUserManager``) is the usual choice. A password sent without encryption is
refused unless ``server.allow_plaintext_password = True``.

What a user may do with a node is decided by the roles and the node's AccessLevel and UserAccessLevel; a variable is
writable by clients only after ``await node.set_writable()``.

Threading
=========

The server is not thread-safe. It runs on the event loop that started it and its address space and services have no locks.
Call it only from that loop: from other tasks, yes; from another thread, no. To work with a server from a thread, use the
synchronous wrapper (:doc:`../sync/overview`), which hands each call to the loop, or use
``asyncio.run_coroutine_threadsafe``.

Method callbacks are called as follows: a callback defined with ``async def`` runs on the loop; a plain function (the usual
``@uamethod def f(parent, x)``) runs in a thread of a thread pool, so it may block, but then it must not touch the address
space or other server objects directly. Callbacks for attribute values (``set_attribute_value_callback``) run on the loop and
must not block.

What a server can offer
=======================

Methods
    ``await node.add_method(idx, "Name", callback, [input types], [output types])`` with a callback decorated with
    ``@uamethod``; a method imported from an XML file needs ``server.link_method(node, callback)``. Named, documented
    arguments are in `04_methods.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/04_methods.py>`_.

Values from the device
    ``server.set_attribute_value_callback(node.nodeid, callback)`` makes a read call ``callback(nodeid, attribute)``,
    which returns a ``DataValue``, instead of returning the stored value: the device is asked only when a client
    reads. The callback runs on the event loop and must not block.

Events
    ``await server.get_event_generator(event_type, emitting_node)`` and ``await generator.trigger(message=...)``;
    ``create_custom_event_type`` adds your own event types.

History
    ``await server.historize_node_data_change(node, period=timedelta(days=7))`` stores every change of a variable,
    ``historize_node_event`` the events of an object. The storage is in memory unless you set a file:
    ``server.iserver.history_manager.set_storage(HistorySQLite("history.db"))`` before ``init()``, with
    ``HistorySQLite`` from :mod:`enginir_opcua.server.history_sql`. See
    `06_events_and_history.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/06_events_and_history.py>`_.

Alarms and conditions
    ``await server.create_condition(...)`` creates a Condition or an Alarm of OPC 10000-9 (limit alarms included) that
    clients acknowledge, confirm and refresh; ``update_value`` drives a limit alarm. See `12_alarms.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/12_alarms.py>`_.

Files
    ``await server.add_file(parent, "Name", path_or_memory_file, writable=...)`` and ``add_directory`` offer files and
    directory trees with the FileType and FileDirectoryType of OPC 10000-20. See `08_file_transfer.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/08_file_transfer.py>`_.

Certificate management
    ``await server.enable_push_management()``, or ``push_management = true`` in the configuration, lets a
    SecurityAdmin replace the certificate and the trust lists over OPC UA (OPC 10000-12). See
    `14_certificate_management.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/14_certificate_management.py>`_.

Reverse connect
    ``server.add_reverse_connect(client_url)`` makes a server behind a firewall connect out to a client that listens
    (OPC 10000-6, 7.1.2.6). See `16_reverse_connect.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/16_reverse_connect.py>`_.

Diagnostics
    The standard diagnostics below ``Server/ServerDiagnostics``: summary counters, sessions and subscriptions, and
    the security diagnostics for a SecurityAdmin. See `13_diagnostics.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/13_diagnostics.py>`_.

Companion models
    ``await server.import_xml("Opc.Ua.Di.NodeSet2.xml")`` loads a NodeSet2 file; instances of its types are created
    with all mandatory children by ``add_object(idx, "Name", objecttype=...)``. See `07_instrument_server.py
    <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/07_instrument_server.py>`_.

Logging and observing
=====================

The library logs through the standard :mod:`logging` module with the module names as logger names. Set the level of
``enginir_opcua`` to ``INFO`` to see the connections and sessions. There is no Observer on the server side yet
(see :doc:`../common/observer`).

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

    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/enginir-opcua/server/")
    idx = await server.register_namespace("urn:example:my-namespace")

    async with server:
        ...

``init()`` builds the standard address space, which takes a moment; pass a cache file (``init(shelf_file)``) to make later
starts faster. ``async with server`` calls ``start()`` and ``stop()``. Add your own nodes with
``server.nodes.objects.add_object(...)`` and the other ``add_*`` methods before or after the start; give them a namespace
that you registered.

Endpoints
=========

The server listens on one TCP address given by ``set_endpoint``; the host part is the interface to bind to, ``0.0.0.0`` for
all of them, and the URL is what clients are told to connect to. Behind NAT or in a container, where the client reaches the
server under another address than the one it binds, set ``server.socket_address`` to the address to bind.

Every combination of SecurityPolicy and MessageSecurityMode that the server allows is offered as an endpoint, with the user
token types that the user manager accepts.

Security defaults
=================

- The endpoint without security (policy *None*) is **off**. Turn it on for tests and closed networks with
  ``Server(allow_no_security=True)``.
- The policies Basic256Sha256, Aes128Sha256RsaOaep and Aes256Sha256RsaPss are on, each in Sign and SignAndEncrypt.
  The deprecated Basic128Rsa15 and Basic256 need ``Server(allow_deprecated_policies=True)``.
  ``server.set_security_policy([...])`` chooses the set.
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
``User`` with a role (``Anonymous``, ``User`` or ``Admin``) or ``None`` to refuse. A password sent without encryption is
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

Methods and events
==================

Add a method with ``await node.add_method(idx, "Name", callback, [input types], [output types])`` and decorate the callback with
``@uamethod``; a method imported from an XML file needs ``server.link_method(node, callback)``. To send events create an
event generator with ``await server.get_event_generator(event_type)`` and call ``await generator.trigger(message=...)``.

Logging and observing
=====================

The library logs through the standard :mod:`logging` module with the module names as logger names. Set the level of
``enginir_opcua`` to ``INFO`` to see the connections and sessions. There is no Observer on the server side yet
(see :doc:`../common/observer`).

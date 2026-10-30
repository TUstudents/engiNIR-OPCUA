======================
Migrating from asyncua
======================

engiNIR-OPCUA 3.0 starts from ``asyncua`` 2.1.0. The API is the same in most places, but the defaults are secure
and many details now follow the specification more closely, so an application usually needs a few changes before it
runs. This page lists the ones most applications meet, in the order you will meet them. The complete list of
changes, with the parts of the specification behind them, is in
`CHANGELOG.md <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/CHANGELOG.md>`_.


1. Package and imports
======================

Replace the dependency and the import package. There is no ``asyncua`` alias, so both packages can be installed
side by side while you move over.

.. code-block:: console

    uv remove asyncua
    uv add enginir-opcua

.. list-table::
    :header-rows: 1
    :widths: 50 50

    * - asyncua 2.x
      - engiNIR-OPCUA 3.0
    * - ``from asyncua import Client, Server, ua``
      - ``from enginir_opcua import Client, Server, ua``
    * - ``from asyncua.sync import Client``
      - ``from enginir_opcua.sync import Client``
    * - ``uaread``, ``uals``, ``uaserver``, ...
      - ``enginir-opcua read``, ``enginir-opcua ls``, ``enginir-opcua server``, ...

Python 3.12 or newer is required. The old command names exist as ``enginir-uaread`` and so on, print a deprecation
notice and are removed in 4.0.0. ``--password`` is gone from the command line; use ``--ask-password`` or the
environment variable ``ENGINIR_OPCUA_PASSWORD``.


2. Security is on
=================

This is the change every application meets. In ``asyncua`` a new server offered an endpoint without security and
accepted any certificate; in engiNIR-OPCUA neither side trusts anything until you configure it.

**Endpoints.** A server offers only signed and encrypted endpoints. An endpoint without security exists only with
``Server(allow_no_security=True)`` or ``NoSecurity`` in ``set_security_policy()``, and ``Basic128Rsa15`` and
``Basic256`` need ``allow_deprecated_policies=True`` on both sides. A server without any endpoint refuses to start
with a ``ConfigurationError``.

**Certificates and trust.** Both sides check the peer's certificate at every secure channel: chain, signature,
validity, key usage, host name and ApplicationUri. The trusted certificates live in a PKI directory. The easiest way
to set one up is the quick setup, which creates the directory and a self-signed certificate on the first start:

.. code-block:: python

    server = Server.quickstart("opc.tcp://0.0.0.0:4840/my/server/", pki="server-pki")
    client = Client.quickstart("opc.tcp://plc.example:4840/my/server/", pki="client-pki")

Then trust the other side with ``enginir-opcua trust`` (or ``enginir-opcua pair`` for two directories on one
machine). An application that sets up security by hand calls ``set_pki_directory()`` or ``set_trust_store()`` on the
server and the client. The certificates that came with the ``asyncua`` examples fail the new checks; create new ones.

**Users.** Anonymous sessions are read-only: they can read, browse, subscribe and read history, but not write, call
methods or change the address space. The ``admin`` user that accepted any password and ``Server.allow_remote_admin``
are gone. Give the server a users file, with users added by ``enginir-opcua user add``, and pick a role for each:
``user`` may write and call methods, ``admin`` may also change the address space. ``PermissiveUserManager`` keeps the
old behaviour as an explicit, insecure choice for tests.

**Renamed hook.** ``Server.set_certificate_validator(hook)`` and ``Client.certificate_validator`` are
``set_application_hook()`` and ``application_hook``; ``set_certificate_validator()`` now takes a whole
``CertificateValidator``.

:doc:`usage/get-started/quick-setup` walks through all of this with a server and client that work together.


3. New default identity
=======================

The default endpoint is ``opc.tcp://0.0.0.0:4840/enginir-opcua/server/``, the ApplicationUris are
``urn:enginir:opcua:server`` and ``urn:enginir:opcua:client`` and the ManufacturerName is ``engiNIR``. Clients that
connect to a server with the default path, and certificates that carry the old ApplicationUri, need the new values.


4. Behaviour that changed
=========================

These changes don't raise an error at once, so look for them in your code.

**Writing.** No role bypasses AccessLevel or WriteMask; set ``await node.set_writable()`` on every variable that
clients write. A write checks the DataType, ValueRank and ArrayDimensions of the value.

**Methods.** ``Node.call_method`` converts the arguments to the method's declared input types. A hand-built
``ua.Argument`` needs a ValueRank, and a method without a callback answers ``Bad_NotSupported``.

**Subscriptions.** The default sampling interval of ``subscribe_data_change`` is the publishing interval, not 50 ms.
A queue size of 0 or 1 means 1 (it used to mean 10 000). ``subscribe_alarms_and_conditions`` calls ConditionRefresh
after subscribing; pass ``refresh=False`` for the old behaviour. ``get_keepalive_count`` and
``get_subscription_revised_params`` are replaced by ``subscription_parameters``.

**Structures.** Boolean fields of generated structures default to ``False``, as the specification says. For example
``ua.ReadRawModifiedDetails()`` no longer asks for modified values and bounds, and ``ua.MonitoringParameters()`` no
longer discards the oldest value; set the field when you need ``True``.

**Strings.** ``NodeId.to_string()`` writes ``svr=`` in front, and ``from_string()`` refuses anything malformed.
``QualifiedName.to_string()`` writes names in namespace 0 without a prefix (``Root``, not ``0:Root``), which also
changes ``Node.get_path(as_string=True)``.

**Status codes.** They are matched by their top 16 bits, so ``except ua.uaerrors.BadNodeIdUnknown`` also catches a
code with info bits set.

**History.** A custom history backend implements the new ``HistoryStorageInterface``. SQLite history files written by
``asyncua`` are refused with an error that names the file.

**Alarms.** ``bind_condition_methods`` is gone: ConditionRefresh and the condition methods are always available, and
``server.create_condition()`` creates Conditions and Alarms with the Part 9 behaviour.

**Synchronous API.** Subscription handlers run on a handler thread, so they may call the sync API; a sync call made
on the event loop thread raises ``RuntimeError``.

**Removed internals.** ``Server.default_timeout``, ``SecureConnection`` (now ``SecureChannel``) and several other
internal names are gone; the changelog lists them.


5. A checklist
==============

#. Replace the dependency and the imports.
#. Create PKI directories and exchange the certificates, or configure ``allow_no_security=True`` for a test setup.
#. Add a users file with roles, or decide which clients stay anonymous and read-only.
#. Call ``set_writable()`` on the variables that clients write.
#. Update hard-coded endpoint URLs and ApplicationUris.
#. Run your tests and check the places listed in `4. Behaviour that changed`_.

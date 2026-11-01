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

**Endpoints.** A server offers only SignAndEncrypt endpoints. An endpoint without security exists only with
``Server(allow_no_security=True)`` or ``NoSecurity`` in ``set_security_policy()``, and ``set_security_policy()`` takes
the deprecated ``Basic128Rsa15`` and ``Basic256`` and the Sign modes when you name them. A server without any endpoint
refuses to start with a ``ConfigurationError``. See `Security profiles`_ below.

**Clients.** ``Client(url)`` no longer connects without security by default; see `Security profiles`_ below.

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


Security profiles
-----------------

The library has three security profiles, ``secure`` (the default), ``development`` and ``legacy``; see
:doc:`usage/common/security`. They change the following.

**Clients without a choice.** ``Client(url).connect()`` used to open a channel without security when nothing was
configured. It now raises a ``ConfigurationError``. Write ``Client(url, allow_no_security=True)`` for a test setup, call
``set_security()``, or use ``Client.quickstart(url, pki=...)``. The same holds for the sync ``Client``. Discovery
without a session (``connect_and_get_server_endpoints``, ``connect_and_find_servers``) needs no choice. The commands
``enginir-opcua read``, ``ls`` and the other client commands refuse without ``--security`` or ``--pki-dir``; add
``--security None`` for a server without security.

**``allow_deprecated_policies`` is removed** on ``Server`` and ``Client`` (and the sync classes). Name the policy:
``server.set_security_policy([...])`` and ``client.set_security(SecurityPolicyBasic128Rsa15, ...)`` accept it and log a
warning.

**``ServerConfig.allow_no_security`` is removed.** List ``"None"`` in ``security``. A TOML file that still has the key
fails with "unknown setting".

**The ``legacy`` profile** is for old devices: the server offers every policy and mode and no security, the client
takes ``security = "auto"``, the strongest endpoint the server offers. ``enginir-opcua init --profile legacy`` writes
its configuration.

**Clear-text passwords.** A client refuses to send a password over a channel that is not SignAndEncrypt when the server
offers no encrypted user token. Set ``client.allow_plaintext_password = True`` (the ``development`` profile does, and
``--allow-plaintext-password`` on the command line) if you must. A server that sends passwords in clear text still
needs ``allow_plaintext_password`` as before.

**``Server()`` offers SignAndEncrypt only.** The Sign-only endpoints of the secure policies are no longer in the
default list. ``Server.quickstart(..., profile="legacy")`` or ``set_security_policy()`` brings them back.

**The demo server.** ``enginir-opcua server`` is secure by default and needs ``--pki-dir``; ``--no-security`` is the
explicit request for the old behaviour, and ``--accept-all-logins`` works only together with it.


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
DateTime fields default to DateTime.MinValue instead of the current time, so set ``StartTime`` and ``EndTime`` of
history details and any timestamp you send.

**Dates and times.** DateTime.MinValue is ``ua.DATETIME_MIN_VALUE`` (0001-01-01 UTC, Python's earliest time); a
DateTime of 0 on the wire decodes to it instead of 1601-01-01. Test for a null DateTime with ``ua.is_null_datetime()``,
which is true for every time at or before 1601-01-01 UTC, and check it before arithmetic or time zone conversion.
``ua.datetime_to_ticks()`` and ``ua.ticks_to_datetime()`` replace ``datetime_to_win_epoch()`` and
``win_epoch_to_datetime()``; ``get_win_epoch()`` is gone. The Picoseconds of a DataValue count 10 ps below the
microsecond (0 to 99 999), so the 100 ns digit survives a round trip.

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
#. Create PKI directories and exchange the certificates, or write ``Client(url, allow_no_security=True)`` and
   ``Server(allow_no_security=True)`` for a test setup.
#. Add a users file with roles, or decide which clients stay anonymous and read-only.
#. Call ``set_writable()`` on the variables that clients write.
#. Update hard-coded endpoint URLs and ApplicationUris.
#. Run your tests and check the places listed in `4. Behaviour that changed`_.

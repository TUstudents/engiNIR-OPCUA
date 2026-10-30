===========
Quick Setup
===========

The quick setup gives you a secure server and client with a few lines, and an error message that names the setting
that is wrong. It adds no protocol behaviour: it collects the settings that are otherwise many
:class:`~enginir_opcua.server.server.Server` setters and :class:`~enginir_opcua.client.client.Client` calls into
configuration objects, and it names two ready-made combinations, the *profiles*. The setters stay available as the
low-level API.

A secure pair
=============

:meth:`Server.quickstart() <enginir_opcua.server.server.Server.quickstart>` and
:meth:`Client.quickstart() <enginir_opcua.client.client.Client.quickstart>` return a configured object that is not yet
started. The PKI directory is created on ``await server.init()`` (the client creates its own at the first
``connect()``), each with a self-signed application certificate whose ApplicationUri matches the configuration. To
have the certificate earlier, for example to hand it to the other side before anything connects, call
``await client.init_pki()`` or ``await server.init_pki()``: it creates the directory and the certificate, returns the
certificate and can be called again.

**Nothing is trusted automatically.** Before a secure connection can work, each side has to trust the other's
certificate; this is the one step that cannot be skipped. The example does it in code; on a command line you use
``enginir-opcua pair`` (below).

.. literalinclude:: ../../../examples/01_secure_pair.py
    :caption: 01_secure_pair.py
    :pyobject: main

The runnable file, with its imports, is `01_secure_pair.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/01_secure_pair.py>`_. The two minimal pages that
follow, :doc:`minimal-server` and :doc:`minimal-client`, split it into two programs.

Profiles
========

.. list-table::
    :header-rows: 1
    :widths: 18 41 41

    * -
      - ``secure`` (default)
      - ``development``
    * - Server security
      - Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, all with SignAndEncrypt only
      - No security, and Basic256Sha256 with SignAndEncrypt
    * - Client security
      - Basic256Sha256, SignAndEncrypt
      - No security
    * - Network
      - Any address
      - Loopback only (``127.0.0.1``, ``::1``, ``localhost``); another host is a ``ConfigurationError``
    * - Start
      - Quiet
      - Logs a warning that the server offers a connection without security
    * - Trust
      - Nothing trusted until you say so
      - Nothing trusted for the secured endpoint; the unsecured one needs no certificate
    * - Users
      - A users file (below); anonymous sessions are read-only
      - The same

Use ``development`` only on your own machine, to try things out. The only example that uses it is
`15_development_profile.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/15_development_profile.py>`_,
and it says so at the top.

Settings and configuration objects
==================================

Everything else is a keyword argument of ``quickstart``: ``Server.quickstart(endpoint, profile="secure",
pki="./pki", users=None, **overrides)`` and ``Client.quickstart(url, profile="secure", pki="./pki", username=None,
password=None, **overrides)``. An override is any field of :class:`~enginir_opcua.config.ServerConfig` or
:class:`~enginir_opcua.config.ClientConfig`, for example ``name``, ``application_uri``, ``security``,
``limits=ServerLimits(max_sessions=10)`` or ``auto_reconnect=True``. An unknown name is an error.

A configuration is validated as a whole, and every error names the setting as it is written in the TOML file::

    ConfigurationError: server.endpoint: the development profile only listens on a loopback address, got
    'opc.tcp://0.0.0.0:4840/dev/'; use 127.0.0.1 or localhost, or profile "secure"

The same objects can be built directly and passed to the constructors, ``Server(config=...)`` and
``Client(config=...)``. A config replaces the other constructor arguments; mixing them is an error.

Configuration files
-------------------

``ServerConfig.from_toml(path)`` and ``ClientConfig.from_toml(path)`` read a TOML file with the standard library's
``tomllib``. Unknown keys are errors, relative paths in the file are relative to the file, and secrets never live in
it: a password comes from the environment variable named by ``password_env`` (default ``ENGINIR_OPCUA_PASSWORD``),
and a users file is found through ``users_file`` or ``ENGINIR_OPCUA_USERS_FILE``. ``config.dump(path)`` writes the file
with a comment for every setting; ``enginir-opcua init`` does it for you:

.. code-block:: toml

    [server]
    profile = "secure"
    endpoint = "opc.tcp://127.0.0.1:4840/enginir-opcua/server/"
    application_uri = "urn:enginir:opcua:server"
    pki = "pki"
    users_file = "users.toml"

    [server.limits]
    max_sessions = 100

.. code-block:: python

    from enginir_opcua import Server
    from enginir_opcua.config import ServerConfig

    server = Server(config=ServerConfig.from_toml("server.toml"))
    await server.init()

Redundant servers and the synchronous API
=========================================

``HaClient.quickstart(urls, profile="secure", pki="./pki", username=None, password=None, **overrides)`` gives a client
for a redundant set the same quick setup: all its clients share the PKI directory and the host-derived ApplicationUri,
and ``await ha.init_pki()`` creates the certificate before ``start()``. See `09_ha_client.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/09_ha_client.py>`_.

``enginir_opcua.sync.Server.quickstart`` and ``enginir_opcua.sync.Client.quickstart`` have the same arguments and one
more, ``tloop``, to run both on one :class:`~enginir_opcua.sync.ThreadLoop`; the sync client has ``init_pki()`` too. See
`11_sync.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/11_sync.py>`_.

Users and roles
===============

A server that should accept more than anonymous read access takes a users file: a TOML file with a name, a role and a
salted ``scrypt`` hash for each user. Plain-text passwords are never stored.

.. code-block:: console

    $ enginir-opcua user add users.toml alice --role user
    added user 'alice' (role user) to users.toml
    $ enginir-opcua user list users.toml
    alice user

The roles are ``user``, ``admin`` and ``security_admin``. Anonymous sessions have the read-only role and can read,
browse, subscribe and read history. A ``user`` may also write, call methods and update history, an ``admin`` may also
change the address space, and a ``security_admin`` may also manage certificates and read the security diagnostics. The
file is read again when it changes. In code, ``write_users``, ``hash_password`` and ``UserRecord`` in
:mod:`enginir_opcua.crypto.users_file` write the same file, and ``FileUserManager(path, anonymous=True)`` is the user
manager behind ``Server.quickstart(users=path)``. See `02_users_and_roles.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/02_users_and_roles.py>`_.

The trust commands
==================

The program ``enginir-opcua`` has five commands for setting up the trust between two applications. They work on PKI
directories (see :doc:`../common/pki-directory`).

``enginir-opcua init server|client DIR``
    Create ``DIR/pki`` with a self-signed application certificate, and a commented ``DIR/server.toml`` or
    ``DIR/client.toml``. Options: ``--endpoint`` (``--url`` for a client), ``--profile``, ``--name``,
    ``--application-uri``, ``--force``. An existing certificate is never replaced.

``enginir-opcua pki list [--pki DIR]``
    Show the folders of a PKI directory with the subject, thumbprint and expiry of every certificate.

``enginir-opcua trust THUMBPRINT_OR_FILE [--pki DIR]``
    Trust a certificate: move a rejected one, by thumbprint, from ``rejected/certs`` to ``trusted/certs``, or add a
    certificate file. A server or client that refuses a peer tells you the command to run, with the thumbprint.

``enginir-opcua pair SERVER_PKI CLIENT_PKI``
    Copy each certificate into the other directory's ``trusted/certs``. It prints a warning: nobody checks who holds
    the key, so it is for development on one machine. On a network, compare the thumbprints yourself and use
    ``trust``.

``enginir-opcua user add|list|remove FILE``
    Manage a users file, see above. ``add`` asks for the password; ``--password-stdin`` reads one line from standard
    input.

A complete session on one machine:

.. code-block:: console

    $ enginir-opcua init server srv --endpoint opc.tcp://127.0.0.1:4840/enginir-opcua/server/
    created  srv/pki
    created  srv/pki/own/certs/application.der  thumbprint 584532607f12...  expires 2027-10-29
    created  srv/server.toml
    $ enginir-opcua init client cli --url opc.tcp://127.0.0.1:4840/enginir-opcua/server/
    $ enginir-opcua pair srv/pki cli/pki
    trusted  301d083dbf7e...  CN=urn:host:enginir-opcua:client  in srv/pki/trusted/certs
    trusted  584532607f12...  CN=urn:host:enginir-opcua:server  in cli/pki/trusted/certs
    $ enginir-opcua user add srv/users.toml alice --role user

If a peer's certificate has not been trusted, the log of the server says which, and how:

.. code-block:: text

    client certificate 8b66...a1e (CN=urn:enginir:example:guest) rejected: it is not trusted; trust it with:
    enginir-opcua trust 8b66...a1e --pki srv/pki

A SecurityAdmin can do the same over OPC UA with the push model of OPC 10000-12; see
`14_certificate_management.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/14_certificate_management.py>`_.

Examples
========

The ``examples`` directory of the repository has one runnable file per task, from this secure pair to alarms,
history, file transfer and reverse connect. :doc:`../examples` describes each of them.

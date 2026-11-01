=================
Security Profiles
=================

The library is secure when you give it no options, and it lets you choose something weaker when you must. This page
describes the three profiles, the settings behind them, what is logged, and the low-level calls that bypass them.

Principles
==========

#. **No options means secure.** ``Server()``, ``Client(url)``, ``Server.quickstart(...)`` and
   ``Client.quickstart(...)`` without a profile use the ``secure`` posture. Nothing weaker happens without a request.
#. **A profile is a complete posture.** It sets every security dimension of the library, not only the channel policy:
   the policies, the network, the certificate checks, user tokens, clear-text passwords and server registrations.
#. **A weaker choice is yours, logged and never blocked.** Choosing ``development`` or ``legacy``, or overriding one
   setting with a weaker value, is allowed. It is logged as a warning once, when the server starts or the client
   connects, and the line names the setting and the risk.
#. **Low-level calls support everything.** ``set_security_policy``, ``set_security``, ``set_identity_tokens`` and
   ``allow_plaintext_password`` work without checks. An explicit low-level call is a request.
#. **Only what cannot work is an error:** an unknown name, a value out of range, and a ``development`` setup that
   leaves the loopback interface.

The profiles
============

Server
------

.. list-table::
    :header-rows: 1
    :widths: 16 14 24 24 22

    * - Dimension
      - Setting
      - ``secure`` (default)
      - ``development``
      - ``legacy``
    * - Channel policies
      - ``security``
      - Basic256Sha256, Aes128Sha256RsaOaep and Aes256Sha256RsaPss, SignAndEncrypt only
      - None, and Basic256Sha256 with SignAndEncrypt
      - The secure policies in Sign and SignAndEncrypt, Basic256 and Basic128Rsa15 in both modes, and None
    * - Network
      - ``endpoint``
      - Any address
      - Loopback only; another address is an error
      - Any address
    * - Application PKI
      - ``pki``, ``create_pki``
      - Required
      - Required for the secure endpoint
      - Required for the secure endpoints
    * - Certificate validation
      - ``suppress``
      - Nothing suppressed
      - ``revocation_unknown``, ``issuer_revocation_unknown``, ``host_name_invalid``
      - The same three
    * - User tokens offered
      - ``identity_tokens``
      - Anonymous (if ``anonymous``), UserName (with users), Certificate (with a user trust store)
      - The same
      - The same
    * - Anonymous sessions
      - ``anonymous``
      - On, read-only
      - On
      - On
    * - Passwords in clear text
      - ``allow_plaintext_password``
      - Off
      - On (loopback only)
      - Off
    * - Accept-every-login manager
      - ``user_manager``
      - Warning for ``PermissiveUserManager``
      - Allowed silently
      - Warning
    * - Discovery registrations
      - ``accept_server_registrations``
      - Off
      - Off
      - Off
    * - Start-up log
      -
      - The endpoints
      - Warning: no security, this machine only
      - One warning per weak endpoint and setting

Client
------

.. list-table::
    :header-rows: 1
    :widths: 16 14 24 24 22

    * - Dimension
      - Setting
      - ``secure`` (default)
      - ``development``
      - ``legacy``
    * - Channel
      - ``security``
      - Basic256Sha256, SignAndEncrypt
      - None
      - ``auto``: the strongest endpoint the server offers, falling back to None; any policy and mode may be named
    * - Network
      - ``url``
      - Any
      - Loopback only
      - Any
    * - Application PKI
      - ``pki``
      - Required
      - Not needed with None
      - Required for a secure policy
    * - Server certificate validation
      - ``suppress``
      - Nothing suppressed
      - ``revocation_unknown``, ``issuer_revocation_unknown``, ``host_name_invalid``
      - The same three
    * - Password in clear text
      - ``allow_plaintext_password``
      - Off: the client refuses to send it
      - On
      - Off
    * - Pinned server certificate
      - ``server_certificate``
      - Optional
      - Optional
      - Optional

Every policy and mode is accepted in every profile. The profile only decides the defaults.

Settings and overrides
======================

The settings are fields of :class:`~enginir_opcua.config.ServerConfig` and
:class:`~enginir_opcua.config.ClientConfig`, in a TOML file or as keyword arguments of ``quickstart``. A setting that
is not given takes the value of the profile. A setting that is given replaces it, and it replaces the whole value: a
``security`` list is the list, not an addition to the profile's.

.. code-block:: python

    server = Server.quickstart(
        "opc.tcp://0.0.0.0:4840/my/server/",
        pki="server-pki",
        security=["Basic256Sha256,SignAndEncrypt", "Basic256Sha256,Sign"],
        suppress=["host_name_invalid"],
    )

The server above is still the ``secure`` profile, but two of its settings are weaker than the profile's and each is
logged. The server settings are ``security``, ``suppress``, ``identity_tokens``, ``allow_plaintext_password``,
``accept_server_registrations``, ``push_management``, ``anonymous`` and ``user_manager``. ``push_management = true``
makes ``init()`` call ``Server.enable_push_management()``, so a SecurityAdmin can manage the certificate and the trust
lists over OPC UA (OPC 10000-12). The client settings are ``security`` (a
``Policy,Mode`` text, ``None`` or ``auto``), ``suppress`` and ``allow_plaintext_password``. ``suppress`` names the
certificate errors that are accepted instead of rejected, such as ``revocation_unknown``.

``config.weaknesses()`` returns the log lines of a configuration as a list, so a test or a start-up check can look at
them without starting anything.

The log lines
=============

A configured server logs ``config.weaknesses()`` once at ``start()``, a configured client once at ``connect()``. Each
line is a warning. A ``development`` server logs:

.. code-block:: text

    profile development: offers a connection without security and relaxes certificate checks; it is meant for this machine only
    server.security: None: no security, the channel is neither signed nor encrypted
    server.suppress: revocation_unknown, issuer_revocation_unknown, host_name_invalid suppressed: a certificate with these errors is accepted instead of rejected
    server.allow_plaintext_password: passwords may cross the network in clear text

and a ``development`` client logs the same with ``client.`` in front of the settings. The other lines are:

.. code-block:: text

    profile legacy: offers deprecated, unencrypted and unsecured channels and relaxes certificate checks for old devices
    profile legacy: takes the strongest channel the server offers, falling back to none, and relaxes certificate checks
    server.security: Basic128Rsa15,Sign: deprecated cipher, weak against modern attacks; signed but not encrypted, the content can be read
    server.accept_server_registrations: any server may register with this one, the registrations are not authenticated
    server.user_manager: PermissiveUserManager accepts every login
    client.security: auto falls back to no security when the server offers nothing better

A low-level server and client, which have no configuration, warn about what they use:

.. code-block:: text

    opc.tcp://127.0.0.1:4840/ offers no security: the channel is neither signed nor encrypted
    The deprecated policy Basic128Rsa15_SignAndEncrypt is offered, do not use it anymore
    opc.tcp://127.0.0.1:4840/ connects without security: the channel is neither signed nor encrypted
    Sending the password in clear text: the channel does not encrypt it

``Client(url)`` without a choice
================================

A client that has no security setting does not fall back to an unsecured channel. ``connect()`` raises a
:class:`~enginir_opcua.ua.uaerrors.ConfigurationError` before it opens a socket:

.. code-block:: text

    no security is configured: use Client.quickstart(url, pki=...) with a PKI directory, call set_security(...), or ask for no security with Client(url, allow_no_security=True)

There are three ways out:

.. code-block:: python

    client = Client.quickstart(url, pki="client-pki")
    client = Client(url)
    await client.set_security(SecurityPolicyBasic256Sha256, "cert.der", "key.pem", server_certificate="server.der")
    client = Client(url, allow_no_security=True)

The first uses a profile, the second calls ``set_security`` before ``connect()``, and the third is the explicit
request for a channel without security; the client logs a warning when it connects. Discovery that never opens a
session works without a choice: ``connect_and_get_server_endpoints``, ``connect_and_find_servers`` and
``connect_sessionless``. OPC 10000-4 runs these on an unsecured channel.

A user password is sent only when the user token is encrypted or the channel is SignAndEncrypt. Otherwise the client
raises a ``ConfigurationError`` that names ``allow_plaintext_password``; set ``client.allow_plaintext_password = True``
to send it anyway. The ``development`` profile sets it.

The command-line tools
======================

``enginir-opcua read``, ``ls``, ``write``, ``call``, ``subscribe``, ``history``, ``shell`` and ``generate-structs``
follow the same rule. Without ``--security`` and without ``--pki-dir`` they refuse and name the choices.
``--security None`` is the explicit request for no security. ``--pki-dir DIR`` alone connects with Basic256Sha256 and
SignAndEncrypt, and ``--security Policy,Mode`` with it chooses another policy. ``--allow-plaintext-password`` sets
``client.allow_plaintext_password``. ``discover`` needs no choice.

``enginir-opcua server`` is a demo server and secure too. Without ``--pki-dir`` (or ``--certificate`` with
``--private-key``) it refuses. ``--no-security`` also offers an endpoint without security and logs the warning above;
only with ``--no-security`` does ``--accept-all-logins`` work. ``enginir-opcua server --config FILE`` follows the file
and its profile and logs the weaknesses at start. ``enginir-opcua init --profile secure|development|legacy`` writes the
configuration of a profile.

The low-level API
=================

The low-level API takes every choice at its word.

.. code-block:: python

    server = Server(allow_no_security=True)
    server.set_security_policy([ua.SecurityPolicyType.Basic128Rsa15_SignAndEncrypt, ua.SecurityPolicyType.NoSecurity])
    server.allow_plaintext_password = True

    client = Client(url, allow_no_security=True)
    client.allow_plaintext_password = True
    await client.set_security(SecurityPolicyBasic128Rsa15, "cert.der", "key.pem", mode=ua.MessageSecurityMode.Sign)

``Server()`` alone offers the three secure policies with SignAndEncrypt only. ``Server(allow_no_security=True)`` adds
the endpoint without security, and ``set_security_policy`` accepts any policy, deprecated ones included; naming a
deprecated policy needs no flag. ``set_security`` of the client takes any policy and warns for a deprecated one.

The profile examples are `01_secure_pair.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/01_secure_pair.py>`_, `15_development_profile.py
<https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/15_development_profile.py>`_ and
`17_legacy_profile.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/17_legacy_profile.py>`_.

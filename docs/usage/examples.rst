========
Examples
========

The `examples <https://github.com/TUstudents/engiNIR-OPCUA/tree/master/examples>`_ directory of the repository has
one runnable program per task. Each runs a server and its clients in one process, uses a temporary PKI directory with
freshly generated certificates, ends by itself and prints ``OK <name>``; the test suite runs all of them, so they
match the current API. Run one from a checkout:

.. code-block:: console

    uv run python examples/01_secure_pair.py

``07_instrument_server.py`` also needs the NodeSet files of the ``nodeset`` submodule:
``git submodule update --init nodeset``.


Getting started
===============

`01_secure_pair.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/01_secure_pair.py>`_
    A secure server and client with ``Server.quickstart`` and ``Client.quickstart``. Each side creates a PKI directory
    with a self-signed certificate, and each puts the other's certificate into its ``trusted/certs`` folder, the one
    step that nothing does automatically.

`02_users_and_roles.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/02_users_and_roles.py>`_
    A users file with salted password hashes and three clients: anonymous (read only), a ``user`` (may also write and
    call methods) and an ``admin`` (may also change the address space). A refused request comes back as
    ``BadUserAccessDenied``.

`11_sync.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/11_sync.py>`_
    The same server and client without ``async`` and ``await``, through :mod:`enginir_opcua.sync`, with a
    subscription handler that runs on a handler thread.

`15_development_profile.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/15_development_profile.py>`_
    The ``development`` profile: no security and loopback addresses only, for experiments on your own machine. It is
    the only example without encryption.


Reading, writing and calling
============================

`03_read_write_subscribe.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/03_read_write_subscribe.py>`_
    ``read_value`` and ``write_value``, a data-change subscription with a handler, and a client with
    ``auto_reconnect=True`` whose session and subscription come back after the server restarts.

`04_methods.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/04_methods.py>`_
    A method with typed, named arguments declared with ``ua.Argument``. The client reads the declaration, calls the
    method and handles a refused call.

`05_custom_types.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/05_custom_types.py>`_
    Enumerations and structures added at runtime with ``new_enum`` and ``new_struct``, a variable that holds a
    structure, and a client that loads the type definitions from the server and decodes the values.


Events, alarms and history
==========================

`06_events_and_history.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/06_events_and_history.py>`_
    A custom event type and its generator, a client that subscribes to the events, and the history of a variable and
    of the events, read back by the client.

`12_alarms.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/12_alarms.py>`_
    An exclusive level alarm created with ``Server.create_condition`` and driven by ``update_value``, and a client
    that tracks the current alarms with ``ConditionTracker`` and acknowledges them.


Information models and files
============================

`07_instrument_server.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/07_instrument_server.py>`_
    The DI and ADI companion specifications imported from NodeSet2 files, a ``SpectrometerDeviceType`` instance with
    its identification, spectral range and a spectrum, browsed and read by a client.

`08_file_transfer.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/08_file_transfer.py>`_
    ``Server.add_file`` for a file on disk and an in-memory file, ``Server.add_directory`` for a directory tree, and
    a client that reads, writes, creates and deletes files with ``UaFile`` and ``UaDirectory``.


Operations
==========

`09_ha_client.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/09_ha_client.py>`_
    Two servers with warm redundancy and an ``HaClient`` that keeps its subscription on the healthy one and fails
    over when the first server reports a low ServiceLevel.

`13_diagnostics.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/13_diagnostics.py>`_
    The standard diagnostics nodes below ``Server/ServerDiagnostics``: the summary counters, the per-session and
    per-subscription arrays, and the security diagnostics that need the SecurityAdmin role.

`14_certificate_management.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/14_certificate_management.py>`_
    Certificate management over OPC UA with ``Server.enable_push_management``: a client is rejected, and a
    SecurityAdmin reads the rejected list and trusts its certificate remotely.

`16_reverse_connect.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/16_reverse_connect.py>`_
    Reverse connect for a server behind a firewall: the server dials out with ``add_reverse_connect``, and the client
    waits for it with ``listen_reverse``.


PubSub
======

`10_pubsub.py <https://github.com/TUstudents/engiNIR-OPCUA/blob/master/examples/10_pubsub.py>`_
    A publisher and a subscriber over UDP on the loopback interface: a published data set, a writer group that sends
    UADP messages and a reader whose sink receives the fields. PubSub is experimental and has no message security;
    see :doc:`pubsub/overview`.

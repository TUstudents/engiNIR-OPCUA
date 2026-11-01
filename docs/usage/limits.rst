=============================
Supported features and limits
=============================

What engiNIR-OPCUA implements, and what it does not implement yet. The baseline is OPC 10000 v1.05; peers that speak
1.04 are accepted.

Supported
=========

.. list-table::
    :header-rows: 1
    :widths: 25 75

    * - Area
      - Supported
    * - Transport
      - ``opc.tcp`` with the UA binary encoding (OPC 10000-6, 7.1), including reverse connect (7.1.2.6)
    * - Security policies
      - Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss with Sign or SignAndEncrypt; None.
        The deprecated Basic256 and Basic128Rsa15 only in the ``legacy`` profile
    * - User identity
      - Anonymous, user name and password, X.509 certificate
    * - Client services
      - Discovery, sessions, browse and translate, read and write, methods, subscriptions with data changes and events,
        history read (raw values and events), subscription transfer, reconnect, redundant servers (``HaClient``)
    * - Server services
      - Discovery (also as a discovery server with ``accept_server_registrations``), sessions, the view, attribute,
        method, node management, monitored item and subscription services, history read of raw values and events
    * - Information model
      - Custom object, variable, data and event types; structures, unions, enumerations and OptionSets with their
        DataTypeDefinition; NodeSet2 import and export; companion specifications such as DI, ADI, LADS and Machinery
    * - Server features
      - Alarms and conditions, history storage in memory or SQLite, file transfer (FileType and FileDirectoryType),
        Program state machines, diagnostics, model change events, certificate management over OPC UA
        (OPC 10000-12 push management)
    * - PubSub
      - Experimental: UADP over UDP; see :doc:`pubsub/overview`
    * - APIs
      - asyncio, and a blocking API (:doc:`sync/overview`) with the same methods

Not supported yet
=================

.. list-table::
    :header-rows: 1
    :widths: 25 75

    * - Area
      - Not supported
    * - Security policies
      - The ECC policies (ECC_nistP256, ECC_nistP384, ECC_brainpoolP256r1, ECC_brainpoolP384r1) and the channel-bound
        session signatures that come with them (OPC 10000-4, 6.1.8)
    * - Transports and encodings
      - HTTPS, WebSockets (``opc.wss``) and the JSON encoding (OPC 10000-6, 5.4); XML only for NodeSet files
    * - Server services
      - HistoryUpdate, QueryFirst and QueryNext, FindServersOnNetwork; they answer ``Bad_ServiceUnsupported``
    * - History read
      - Processed (aggregates), at-time and modified values, annotations; they answer
        ``Bad_HistoryOperationUnsupported``
    * - Certificate management
      - The pull model and a Global Discovery Server; only push management is implemented
    * - PubSub
      - Message security, JSON, MQTT, chunking and the configuration methods

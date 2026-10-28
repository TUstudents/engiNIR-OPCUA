PubSub (experimental)
=====================

``enginir_opcua.pubsub`` implements a part of OPC UA PubSub (OPC 10000-14): a publisher sends the values of a
DataSet as UADP messages over UDP, and a subscriber receives them and writes them to variables of a server or
hands them to your code. The package is **experimental**: the classes and their defaults can still change, and
the feature list below is the boundary of what has been tested.

What is implemented
-------------------

.. list-table::
    :header-rows: 1
    :widths: 30 70

    * - Area
      - Support
    * - Message mapping
      - UADP NetworkMessages and DataSetMessages: key frames with Variant, DataValue or RawData fields, events,
        keep-alive and heartbeat messages, delta frames on the receiving side, promoted fields. Messages with
        reserved values or an unknown version are skipped and counted.
    * - Transport
      - UDP unicast, multicast and broadcast (``opc.udp://host:port``), IPv4 and IPv6.
    * - Publisher
      - PublishedDataSets from a dictionary, from variables of a server (``PublishedDataItems``) or from your own
        ``PubSubDataSource``. WriterGroups publish on a fixed schedule (``PublishingInterval``), honour
        ``Priority``, ``Enabled``, ``KeepAliveTime`` and ``MaxNetworkMessageSize``, and order the DataSetWriters
        by ``DataSetOrdering``.
    * - Subscriber
      - DataSetReaders filter by PublisherId, WriterGroupId and DataSetWriterId, check the configuration
        version and the number of fields, ignore duplicates and old messages, and follow
        ``MessageReceiveTimeout``. SubscribedDataSets are ``SubScribedTargetVariables`` (with index ranges and
        override handling) and ``SubscribedDataSetMirror``.
    * - Address space
      - The configuration appears under the ``PublishSubscribe`` object. A configuration can be loaded from and
        saved to a UABinaryFile.

What is not implemented
-----------------------

* **Message security.** Signing and encryption (``SecurityMode`` ``Sign`` and ``SignAndEncrypt``), security
  groups and the security key service. A group or reader configured for them refuses to start, and messages
  that carry a security header are dropped.
* JSON message encoding and the MQTT and Ethernet transports, DTLS over UDP.
* Chunking: a NetworkMessage larger than ``MaxNetworkMessageSize`` is not sent (a warning is logged once), and
  received chunk messages are skipped.
* Delta frames on the publishing side: ``KeyFrameCount`` above 1 still sends key frames.
* Discovery probes and announcements, and the retrieval of updated DataSetMetaData.
* Messages without a payload header (fixed layouts), and actions.
* The ``Enable``, ``Disable``, ``AddReaderGroup``, ``AddWriterGroup`` and ``RemoveGroup`` methods answer
  ``Bad_NotImplemented``. A PubSubState is kept for what runs: ``Operational``, ``Disabled`` and ``Error``, and
  ``PreOperational`` for a reader that is waiting for its first message.

Unauthenticated data
--------------------

Because there is no message security, **anybody who can send UDP datagrams to the address and port of a
subscriber can feed it DataSetMessages**. With ``SubScribedTargetVariables`` those values are written to variables
of your server. Use PubSub only on a network you trust, or separate it with a firewall or VLAN, and keep
the bind rules below.

Publisher and subscriber
------------------------

A standalone publisher (the full examples are in ``examples/pubsub``):

.. code-block:: python

    from enginir_opcua import pubsub, ua
    from enginir_opcua.pubsub.udp import UdpSettings

    meta = pubsub.DataSetMeta.Create("Simple")
    meta.add_scalar("Int32", ua.VariantType.Int32)
    pds = pubsub.PublishedDataSet.Create("SimpleDataSet", meta)
    pds.get_source().datasources["Simple"] = {"Int32": ua.DataValue(ua.Variant(ua.Int32(1)))}

    connection = pubsub.PubSubConnection.udp_uadp(
        "Publisher", ua.UInt16(1), UdpSettings(Url="opc.udp://239.0.0.1:4840"),
        writer_groups=[
            pubsub.WriterGroup.new_uadp(
                "WriterGroup1", ua.UInt16(1), publishing_interval=1000,
                writer=[pubsub.DataSetWriter.new_uadp("Writer1", "SimpleDataSet", ua.UInt16(32), datavalue=True)],
            )
        ],
    )
    async with pubsub.PubSub.new(connections=[connection], datasets=[pds]):
        ...

A subscriber creates a ``DataSetReader`` for the same PublisherId, WriterGroupId and DataSetWriterId with the
same metadata, and a sink: an object with ``on_dataset_received(meta, fields)`` and ``on_state_change(meta, state)``,
or a ``SubScribedTargetVariables`` that maps fields to variables of a server:

.. code-block:: python

    reader = pubsub.DataSetReader.new(
        ua.Variant(ua.UInt16(1)), ua.UInt16(1), ua.UInt16(32), meta, name="Reader", enabled=True, subscribed=sink
    )
    group = pubsub.ReaderGroup.new("ReaderGroup1", [reader], enable=True)
    connection = pubsub.PubSubConnection.udp_uadp(
        "Subscriber", ua.UInt16(2), UdpSettings(Url="opc.udp://239.0.0.1:4840"), reader_groups=[group]
    )

Readers and reader groups are created disabled unless you pass ``enabled=True`` and ``enable=True``. Writers and
writer groups are enabled by default. A disabled element does nothing.

With a server, ``await server.get_pubsub()`` returns a ``PubSub`` that mirrors its configuration in the address
space and writes into the server's variables; ``PubSub.start()`` and ``PubSub.stop()`` start and stop everything.
If a connection can't start, ``start()`` raises the first error and leaves nothing running.

Addresses and the bind rule
---------------------------

* **Multicast** (an address in the multicast range): the subscriber joins the group on the connection's
  ``NetworkInterface`` and binds to the group address; the publisher sends through the same interface. Set the
  interface when the host has more than one network card. ``NetworkInterface`` is an IP address or an interface
  name. ``Loopback`` (``UdpSettings(Loopback=...)``) decides whether a host receives its own multicast, and
  ``TTL`` sets the hop limit.
* **Unicast**: the connection's URL is the address the subscriber listens on, and the destination of a
  publisher is the ``address`` of its ``WriterGroup`` (``WriterGroup.new_uadp(..., address="opc.udp://host:port")``).
  Without a group address, a publisher sends to the connection's URL. A connection that only publishes does not
  open a receive address at all.
* **Bind rule.** The library never listens on all interfaces by itself. A unicast subscriber binds to its
  ``NetworkInterface`` when one is given, to the URL's host when that is an IP address, and to loopback
  when the host is a name such as ``localhost``. To listen on all interfaces, write ``0.0.0.0`` (or ``::``) as the
  ``NetworkInterface`` explicitly. The standard (OPC 10000-14 v1.05, 7.3.2.3) says an empty interface means all
  interfaces; this library is stricter on purpose, so a subscriber that should be reachable from other hosts
  must be configured for it.
* A multicast connection refuses a WriterGroup that has an address: that group stays in the ``Error`` state.
* IPv6 hosts are written in brackets: ``opc.udp://[ff02::1]:4840``.

Reading the state
-----------------

``OpcUdp.counters`` (``connection._protocol.counters``) counts what a connection did: datagrams received, sent, skipped
by reason, malformed, dropped because the receive queue was full, and messages too large to send. Writer
groups and readers have their own ``counters`` for published messages, dropped messages by reason, ignored
duplicates and errors. Malformed datagrams give a rate-limited warning on the ``enginir_opcua.pubsub.udp`` logger,
never one log record per datagram.

A reader that doesn't see a new message within ``MessageReceiveTimeout`` milliseconds goes to ``Error`` and tells
its sink; the next valid message brings it back to ``Operational``.

Values and status
-----------------

A field with a Bad status is sent as a Variant holding the status, an Uncertain one as a Variant holding a
DataValue; the subscriber turns both back into a DataValue. ``SubScribedTargetVariables`` applies the override
handling of each target when a field is Bad and once when the reader leaves ``Operational``: ``OverrideValue``
writes the configured value with ``Good_LocalOverride``, ``LastUsableValue`` keeps the last value with
``Uncertain_LastUsableValue``, and ``Disabled`` writes a null value with the Bad status. Targets that are not
writable (their ``AccessLevel`` has no write bit) are not written: the write is counted and logged once.

Data types of the session are found through the server's type registry (``server.types``), so DataSets can carry
structures that you registered for the server.

Limits worth knowing
--------------------

* One socket and one receive task per connection; datagrams are processed in the order they arrive.
* Sequence numbers (DataSetMessage and NetworkMessage) start at 0 and roll over after 65535.
* RawData fields need a fixed size: String and ByteString fields need ``MaxStringLength``, arrays need
  ``ArrayDimensions``, and only scalar built-in types and fixed one-dimensional arrays are supported. A writer
  whose fields can't be sent as RawData sends messages with the ``Valid`` flag cleared and logs it once.

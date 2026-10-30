=============
OPC UA Basics
=============

OPC UA (Open Platform Communications Unified Architecture, IEC 62541) is a standard for exchanging data between
industrial machines and software. It defines both the data model, how a device describes what it offers, and the
protocol to reach it. This page explains the terms that the rest of the documentation uses and shows where each one
lives in engiNIR-OPCUA. The specification itself is free to read at https://reference.opcfoundation.org.


Clients and servers
===================

A **server** holds data and offers services: a PLC, a machine, a gateway or a piece of software. A **client**
connects to it to read and write values, call methods and receive changes. One program can be both.

A connection has two layers:

- The **secure channel** carries the messages. It signs and encrypts them according to the endpoint the client
  chose, and both sides check each other's certificate when it opens.
- The **session** runs inside the channel and represents the user: anonymous, a user name and password, or an X509
  user certificate. The server decides from the user's roles what the session may do.

In engiNIR-OPCUA these are :class:`~enginir_opcua.server.server.Server` and
:class:`~enginir_opcua.client.client.Client`; ``async with client`` opens the channel and the session and closes
them again.


The address space
=================

A server presents its data as an **address space**: a graph of **nodes** connected by **references**. Every node
belongs to one **node class**:

.. list-table::
    :header-rows: 1
    :widths: 22 78

    * - Node class
      - What it is
    * - Object
      - A thing, such as a machine, a sensor or a folder. Objects organise the other nodes.
    * - Variable
      - A value, with its data type. A *property* is a Variable that describes its parent, such as a unit or a range.
    * - Method
      - A function that a client can call on an Object, with typed input and output arguments.
    * - ObjectType, VariableType
      - Templates. An Object of type ``TemperatureSensorType`` gets the children that the type defines.
    * - DataType
      - A type of value: a built-in type such as Double or String, an enumeration or a structure.
    * - ReferenceType
      - A kind of reference, such as ``Organizes``, ``HasComponent`` or ``HasProperty``.
    * - View
      - A subset of the address space for a particular purpose.

Every node has **attributes**. All nodes have a NodeId, a BrowseName and a DisplayName; a Variable also has a Value,
a DataType and an AccessLevel that says whether the value can be read and written. :class:`~enginir_opcua.common.node.Node`
reads them with methods such as ``read_value()``, ``read_browse_name()`` and ``read_attribute()``.

**References** connect the nodes. Hierarchical references (``Organizes``, ``HasComponent``, ``HasProperty``) form
the tree that a client browses from the Root node down through ``Objects``. ``HasTypeDefinition`` points from a node
to its type. :meth:`~enginir_opcua.common.node.Node.get_children` and
:meth:`~enginir_opcua.common.node.Node.get_references` follow them.


NodeIds and namespaces
======================

A **NodeId** identifies a node on a server. It has a namespace index and an identifier, which is a number, a string,
a GUID or a byte string. As text it is written ``ns=2;i=42`` or ``ns=2;s=Line1.Temperature``; the namespace index 0
is left out (``i=85`` is the Objects folder).

A **namespace** is a URI, such as ``http://opcfoundation.org/UA/`` for the standard nodes or
``urn:example:my-plant`` for yours. The server keeps the list of its namespaces in the NamespaceArray, and the
**namespace index** is the position of a URI in that list. The index can differ from one server, or one start, to
the next, so a client looks it up by URI with :meth:`~enginir_opcua.client.client.Client.get_namespace_index`, and a
server registers its own with :meth:`~enginir_opcua.server.server.Server.register_namespace`.

A **BrowseName** is a qualified name, a namespace index and a text such as ``2:Temperature``. A **browse path** is a
list of BrowseNames from a starting node, such as ``["0:Objects", "2:Line1", "2:Temperature"]``, and
:meth:`~enginir_opcua.common.node.Node.get_child` resolves it to a node. :doc:`../common/node-nodeid` has the
details.


Information models
==================

Namespace 0 holds the **standard address space**: the base types, the Server object with its status and
capabilities, and the types for events, alarms, history and file transfer. A server built with engiNIR-OPCUA has it
from :meth:`~enginir_opcua.server.server.Server.init` on.

**Companion specifications** define types for a domain, such as machinery, robotics or analyser devices, and are
published as NodeSet XML files. :meth:`~enginir_opcua.server.server.Server.import_xml` loads such a file, and
``instantiate()`` creates Objects of the imported types.


Services, subscriptions and events
==================================

Clients use a fixed set of **services**: Read and Write for attributes, Browse to follow references, Call for
methods, and HistoryRead for stored values and events. engiNIR-OPCUA wraps them in the methods of ``Node``.

Instead of polling, a client creates a **subscription** with a **publishing interval** and adds **monitored items**
to it. The server samples each item at its **sampling interval**, queues the changes and sends them in one
notification per publishing interval. A subscription is kept alive by keep-alive messages and ends when the client
stops asking for notifications for its **lifetime**.

**Events** are notifications about something that happened: a state change, an audit record, a message. **Alarms and
conditions** (OPC 10000-9) are events with a state that can be active, acknowledged, confirmed and shelved.
:meth:`~enginir_opcua.common.subscription.Subscription.subscribe_events` and
:meth:`~enginir_opcua.common.subscription.Subscription.subscribe_alarms_and_conditions` receive them.


Endpoints and security
======================

A server offers one or more **endpoints**. Each has a URL, ``opc.tcp://host:4840/path``, a **security policy** and
a **security mode**:

- The **security policy** names the algorithms, such as ``Basic256Sha256`` or ``Aes256_Sha256_RsaPss``. ``None``
  means no security at all.
- The **security mode** is ``None``, ``Sign`` (messages can't be changed) or ``SignAndEncrypt`` (they can't be read
  either).

A client asks for the list with GetEndpoints and picks one. Every application has an **application instance
certificate** that contains its **ApplicationUri**. Secure connections need each side to **trust** the other's
certificate: the certificate, or the CA that issued it, has to be in the application's trust list. engiNIR-OPCUA
keeps certificates, keys and trust lists in a **PKI directory**, described in :doc:`../common/pki-directory`.

The **user token** of the session proves who the user is. The server maps users to **roles**, and the roles decide
which services a session may use. In engiNIR-OPCUA anonymous sessions are read-only by default.


More of the standard
====================

- **History** (OPC 10000-11): the server stores values and events of historized nodes; clients read them with
  ``read_raw_history()`` and ``read_event_history()``.
- **Discovery** (OPC 10000-12): clients find servers and their endpoints through FindServers and GetEndpoints, or
  through a discovery server. ``enginir-opcua discover`` shows them.
- **Redundancy** (OPC 10000-4): several servers offer the same data, and a client fails over between them.
  :class:`~enginir_opcua.client.ha.ha_client.HaClient` does this on the client side.
- **PubSub** (OPC 10000-14): publishers send data sets to subscribers without sessions, for example over UDP
  multicast. See :doc:`../pubsub/overview`.


The parts of the specification
==============================

The specification is published as OPC 10000, in numbered parts. Docstrings in engiNIR-OPCUA cite them as
``OPC 10000-4 v1.05, 5.9.2``: part, edition and section.

.. list-table::
    :header-rows: 1
    :widths: 22 78

    * - Part
      - Topic
    * - OPC 10000-3
      - Address space model: node classes, attributes, references
    * - OPC 10000-4
      - Services, sessions, subscriptions, certificate validation
    * - OPC 10000-5
      - Information model: the standard nodes and types
    * - OPC 10000-6
      - Mappings: binary encoding, the ``opc.tcp`` protocol, security policies
    * - OPC 10000-7
      - Profiles
    * - OPC 10000-9
      - Alarms and conditions
    * - OPC 10000-11
      - Historical access
    * - OPC 10000-12
      - Discovery and certificate management
    * - OPC 10000-14
      - PubSub
    * - OPC 10000-20
      - File transfer


Further reading
===============

https://reference.opcfoundation.org
    The complete specification, free to read online. Links and citations in this documentation point there.

https://www.open62541.org
    An open source OPC UA stack in C. Its documentation explains the architecture and data modelling of OPC UA in
    depth.

https://www.unified-automation.com
    Commercial OPC UA tools; UaExpert, a graphical client, is free to download and useful for looking at a server.

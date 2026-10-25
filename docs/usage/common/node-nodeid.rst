==================
NodeId's and Nodes
==================

The NodeId Class
================

:class:`enginir_opcua.ua.uatypes.NodeId` objects are used as unique ids for :class:`~enginir_opcua.common.node.Node`'s
and are therefore used on the server and client side to access specific nodes. The two classes
:class:`~enginir_opcua.ua.uatypes.NodeId` and :class:`~enginir_opcua.common.node.Node` should not
be confused: The NodeId is the unique identifier of an actual Node. While the NodeId is used to identify
a specific node, the Node object can be used to access the underlying data.
To learn more about the Node class, head over to :ref:`usage/common/node-nodeid:the node class`.


A NodeId contains two main pieces of information that allow a unique mapping in the opc-ua address space:
The :attr:`~enginir_opcua.ua.uatypes.NodeId.Identifier` and the :attr:`~enginir_opcua.ua.uatypes.NodeId.NamespaceIndex`.
In addition there is the :attr:`~enginir_opcua.ua.uatypes.NodeId.NodeIdType` attribute which is used
to specify which opc-ua type is used for the Identifier. In addition to the :class:`~enginir_opcua.ua.uatypes.NodeId`
class, there is also the a :class:`~enginir_opcua.ua.uatypes.ExpandedNodeId` which adds the
:attr:`~enginir_opcua.ua.uatypes.ExpandedNodeId.NamespaceUri` and :attr:`~enginir_opcua.ua.uatypes.ExpandedNodeId.ServerIndex`
attributes to make the ID unique across different servers and namespaces.


Creating NodeId's
-----------------

As already mentioned above, the NodeId class supports different types for the Identifier.
The type is handled automatically on class instantiation and there is usually no need
to set the type manually. Creating new NodeIds usually looks like this:

.. code-block:: python

    >>> from enginir_opcua import ua
    >>> ua.NodeId(1, 2)  # Integer Identifier
    NodeId(Identifier=1, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>)
    >>> ua.NodeId('Test', 2)  # String Identifier
    NodeId(Identifier='Test', NamespaceIndex=2, NodeIdType=<NodeIdType.String: 3>)
    >>> ua.NodeId(b'Test', 2)  # Bytes Identifier
    NodeId(Identifier=b'Test', NamespaceIndex=2, NodeIdType=<NodeIdType.ByteString: 5>)

A NodeId can also be built from a single string:

.. code-block:: python

    >>> ua.NodeId.from_string('ns=2;i=4')
    NodeId(Identifier=4, NamespaceIndex=2, NodeIdType=<NodeIdType.Numeric: 2>)
    >>> ua.NodeId.from_string('ns=2;s=Test')
    NodeId(Identifier='Test', NamespaceIndex=2, NodeIdType=<NodeIdType.String: 3>)

The string form follows the OPC UA specification (Part 6, 5.1.12). It is a sequence of
components separated by semicolons, written in this order, where only the identifier is required:

.. code-block:: text

    [svr=<server index>;] [ns=<namespace index>; | nsu=<namespace URI>;] <identifier>

svr
    The index of the server, written as digits. If it is present, a
    :class:`~enginir_opcua.ua.uatypes.ExpandedNodeId` is returned. It is only written when it is not 0.
    The older spelling :code:`srv=` is still read, but only in this first position.
ns, nsu
    The namespace, either as an index or as a URI. They exclude each other. A URI is percent-encoded so that
    it contains no semicolon: :code:`;` is written as :code:`%3B` and :code:`%` as :code:`%25`, and every
    :code:`%XX` sequence is decoded when reading. A string with :code:`nsu` returns an
    :class:`~enginir_opcua.ua.uatypes.ExpandedNodeId` with :code:`NamespaceIndex` 0.
    Nodes in namespace 0, or in the OPC UA namespace URI, use the identifier alone.
i, s, g, b
    The identifier, which is always the last component. The character selects the type: :code:`i=` a decimal
    number, :code:`s=` a string, :code:`g=` a Guid in the form :code:`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
    and :code:`b=` opaque bytes in standard Base64. A string identifier takes everything up to the end of the
    text, so it may itself contain semicolons and equals signs.

.. code-block:: python

    >>> ua.NodeId.from_string('ns=10;i=12345').to_string()
    'ns=10;i=12345'
    >>> ua.NodeId.from_string('svr=1;nsu=http://example.com/hello;s=Water;Pump')
    ExpandedNodeId(Identifier='Water;Pump', NamespaceIndex=0, NodeIdType=<NodeIdType.String: 3>, NamespaceUri='http://example.com/hello', ServerIndex=1)

Text that does not follow this grammar raises :class:`~enginir_opcua.ua.uaerrors.UaStringParsingError`.
That includes an unknown key, an identifier that is not last, a number that is not made of digits, a malformed
Guid, and a :code:`b=` value that is not valid Base64. Server URIs (:code:`svu=`) cannot be stored in a
:class:`~enginir_opcua.ua.uatypes.ExpandedNodeId` and are rejected.

:class:`~enginir_opcua.ua.uatypes.QualifiedName` has a string form too (Part 6, 5.1.12, Table 7):
the bare name for namespace 0 and :code:`<index>:<name>` for other namespaces, for example
:code:`3:Hello:World`. :meth:`~enginir_opcua.ua.uatypes.QualifiedName.from_string` also reads
:code:`nsu=<uri>;<name>` when it is given the list of namespace URIs through its :code:`namespaces` argument.


What else?
----------

The :class:`~enginir_opcua.ua.uatypes.NodeId` class is actually just a normal UA data-type like
other objects as :class:`~enginir_opcua.ua.uatypes.QualifiedName` or :class:`~enginir_opcua.ua.uatypes.Variant`
are, with some additional logic to make it easier to work with.

..
   The enginir_opcua package models all datatypes as :mod:`dataclasses`.

   The info about dataclasses is an internal detail of a package implementation,
   that may change in future. Maybe users should not know about it to avoid dependency on it.


The Node Class
==============

The :class:`~enginir_opcua.common.node.Node` class is a central part used on the server and client.
On the server side nodes are created and configured as well as read and written. On the client
side we can browse through the nodes, access and manipulate their values. Nodes should not
be confused with :class:`~enginir_opcua.ua.uatypes.NodeId`: Each node has a NodeId an can be accessed
through it. NodeId uniquely identifies the Node within the server.

The Node class exposes a wide range of the OPC-UA protocol for easy access, however, to fully
optimize your code you will need to use lower level functions. Beside that, for many usecases
the Node class might be the right thing to use for simpler usecases and makes it certainly
easier to get started with OPC-UA.

Accessing Nodes
---------------

As mentioned above, the Node class provides access to a lot of functionality, on the server
and client side. Therefore, both, the server and client, provide a :code:`get_node` method:
:meth:`enginir_opcua.client.client.Client.get_node` & :meth:`enginir_opcua.server.server.Server.get_node`.
These functions can be used to get a node by it's NodeId, for example:

.. code-block::

    >>> client.get_node("ns=2;i=2")
    Node(NodeId(Identifier=2, NamespaceIndex=2, NodeIdType=<NodeIdType.Numeric: 2>))

Note that using :code:`get_node` does not check if the node actually exists! The method
just creates a new node which later can be used to query data.

.. note:: As a rule of thumb: If the method is synchronous, there is no communication between
    server and client. In such cases only input validation is performed.

The node now can be used to read / write / ... data from the server:

.. code-block::

    >>> node = client.get_node("ns=2;i=2")
    >>> name = (await node.read_browse_name()).Name
    >>> value = (await node.read_value())
    >>> print(f"{name} = {value}")
    MyVariable = 16.59999
    >>> await node.write_value(5.0)  # Must use 5.0, see note below
    >>> value = (await node.read_value())
    >>> print(f"{name} = {value}")
    MyVariable = 5.0

Writing values using :meth:`~enginir_opcua.common.node.Node.write_value` can be tricky in some cases
as the method converts the python type to a OPC-UA datatype. In the example above we explicitly
need to pass in a :code:`float` to enforce a conversion to a :attr:`~enginir_opcua.ua.uatypes.VariantType.Double`.
If :code:`5` is passed in, the value will be sent as a :attr:`VariantType.Int64`, which would
result in a error as the sent datatype does not match the expected type on the server side.

.. todo:: If there is ever a section which goes into more detail, add a link!

The node object can also be used to browse to other nodes. There are several methods available
as shown in the following short example:

.. code-block::

    >>> # Get the parent of a node
    >>> parent = await node.get_parent()
    >>> print(parent)
    Node(NodeId(Identifier=1, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>))

    >>> # Get all children of a node
    >>> await parent.get_children()
    [Node(NodeId(Identifier=2, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>))]

    >>> # Get a specific child (by NodeId) of a node
    >>> await parent.get_child("2:MyVariable")
    Node(NodeId(Identifier=2, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>))

Note that in the last example we use the browse path of child as argument to
:meth:`~enginir_opcua.common.node.Node.get_child`. With the same method it's also possible
to access a child several levels deeper than the current node:

.. code-block::

    >>> await c.nodes.objects.get_child(['2:MyObject', '2:MyVariable'])
    Node(NodeId(Identifier=2, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>))

Here we start at the objects node an traverse via MyObject to MyVariable. Always keep in
mind that browsing through the nodes will create network traffic and server load. If
you already know the NodeId using :meth:`~enginir_opcua.client.client.Client.get_node` should
be preferred. You might also consider caching NodeIds which you found through browsing
to reduce the traffic.

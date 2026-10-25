========================
Installation & CLI Tools
========================

Package Installation
====================

engiNIR-OPCUA is published on `PyPI <https://pypi.org/project/enginir-opcua/>`_ as :code:`enginir-opcua`
and imported as :code:`enginir_opcua`. To install it, run

.. code-block:: console

    pip install enginir-opcua

To install the current development version from the source repository, run

.. code-block:: console

    pip install git+https://github.com/TUstudents/engiNIR-OPCUA.git
    # or, if git is not available
    pip install https://github.com/TUstudents/engiNIR-OPCUA/archive/refs/heads/master.zip

To check the installation, or to report the version in a bug report, run this in a Python interpreter:

.. code-block:: python

    import enginir_opcua
    print(enginir_opcua.__version__)

engiNIR-OPCUA is a fork of `FreeOpcUa/opcua-asyncio <https://github.com/FreeOpcUa/opcua-asyncio>`_ 2.1.0.
It can be installed next to the :code:`asyncua` package, because the import package and the command names differ.


Command Line Tools
==================

The package installs these command line tools:

:code:`enginir-uabrowse`:
    Browse OPC-UA node and print result

:code:`enginir-uacall`:
    Call method of a node

:code:`enginir-uaclient`:
    Connect to server and start python shell. root and objects nodes are available. Node specified in command line is available as mynode variable.

:code:`enginir-uadiscover`:
    Performs OPC UA discovery and prints information on servers and endpoints.

:code:`enginir-uageneratestructs`:
    Generate a Python module from the xml structure definition (.bsd), the node argument is typically a children of i=93.

:code:`enginir-uahistoryread`:
    Read history of a node.

:code:`enginir-uals`:
    Browse OPC-UA node and print result.

:code:`enginir-uaread` / :code:`enginir-uawrite`:
    Read / Write attribute of a node, by default reads value of a node.

:code:`enginir-uaserver`:
    Run an example OPC-UA server. By importing xml definition and using enginir-uawrite command line, it is even possible to expose real data using this server.

:code:`enginir-uasubscribe`:
    Subscribe to a node and print results

These command line tools can be used from within the environment in which the package was installed. To get more information run:

.. code-block:: console

    <tool> --help
    # For example
    enginir-uaread --help


More Tools for Development
==========================

.. todo:: Create a list of additional tools which are nice to have during development
    Possible Tools:

    - opcua-client (https://github.com/FreeOpcUa/opcua-client-gui)
    - UaModeler (https://www.unified-automation.com/products/development-tools/uamodeler.html)

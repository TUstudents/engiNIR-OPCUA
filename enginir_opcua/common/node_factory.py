from __future__ import annotations

import enginir_opcua
from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession


def make_node(session: AbstractSession, nodeid: ua.NodeId) -> enginir_opcua.Node:
    """
    Node factory
    Needed no break cyclical import of `Node`
    """
    from .node import Node

    return Node(session, nodeid)

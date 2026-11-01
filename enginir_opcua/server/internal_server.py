"""
The internal server: the address space, the services and the limits behind the network front end of Server.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from copy import copy
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from enginir_opcua import ua

from ..common.callback import CallbackService, CallbackType
from ..common.connection import ChannelSettings
from ..common.node import Node
from ..common.utils import ServiceError
from ..crypto import uacrypto
from ..crypto.truststore import TrustStore
from ..crypto.validator import ApplicationHook, CertificateValidator
from .address_space import AddressSpace, AttributeService, MethodService, NodeData, NodeManagementService, ViewService
from .conditions import ConditionManager
from .diagnostics import DiagnosticsCollector
from .file_transfer import FileService
from .history import HistoryManager
from .identity import TOKEN_TYPES, IdentityGuard
from .internal_session import InternalSession, SessionManager
from .model_change import ModelChangeNotifier
from .service_dispatch import Dispatcher
from .service_handlers import build_service_table
from .subscription_service import SubscriptionService
from .user_managers import AnonymousReadOnlyUserManager, UserManager

_logger = logging.getLogger(__name__)


@dataclass
class OperationLimits:
    """The OperationLimits of ServerCapabilities: the most operations one request of each service may carry."""

    max_nodes_per_read: int = 10_000
    max_nodes_per_history_read_data: int = 10_000
    max_nodes_per_history_read_events: int = 10_000
    max_nodes_per_write: int = 10_000
    max_nodes_per_history_update_data: int = 10_000
    max_nodes_per_history_update_events: int = 10_000
    max_nodes_per_method_call: int = 10_000
    max_nodes_per_browse: int = 10_000
    max_nodes_per_register_nodes: int = 10_000
    max_nodes_per_translate_browse_paths: int = 10_000
    max_nodes_per_node_management: int = 10_000
    max_monitored_items_per_call: int = 10_000


OPERATION_LIMIT_NODES: dict[str, int] = {
    "max_nodes_per_read": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead,
    "max_nodes_per_history_read_data": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData,
    "max_nodes_per_history_read_events": (
        ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents
    ),
    "max_nodes_per_write": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite,
    "max_nodes_per_history_update_data": (
        ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData
    ),
    "max_nodes_per_history_update_events": (
        ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents
    ),
    "max_nodes_per_method_call": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall,
    "max_nodes_per_browse": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse,
    "max_nodes_per_register_nodes": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes,
    "max_nodes_per_translate_browse_paths": (
        ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds
    ),
    "max_nodes_per_node_management": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement,
    "max_monitored_items_per_call": ua.ObjectIds.Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall,
}


class ServerDesc:
    """
    A server this one knows for FindServers: itself, or a server registered with RegisterServer(2), with its
    discovery configurations and the clock time of its registration.
    """

    def __init__(
        self,
        serv: ua.ApplicationDescription,
        cap: list[ua.DiscoveryConfiguration] | None = None,
        registered_at: float | None = None,
    ) -> None:
        self.Server = serv
        self.Capabilities = cap
        self.registered_at = registered_at


class InternalServer:
    """
    There is one `InternalServer` for every `Server`.

    Its attributes hold the server limits; set them before `Server.init()`. Among them:
    max_pending_messages_per_connection, the parsed messages queued behind one connection before it is closed;
    max_connections, the accepted TCP connections, refused at connection_made; hello_timeout_seconds and
    max_pending_activation_seconds (0 disables), after which a connection without Hello or without an activated
    session is closed; max_message_size_before_activation (128 KiB), the largest message a channel without an activated
    session may send, so that an anonymous discovery channel cannot make the server hold max_message_size of an
    unfinished message; max_lifetime_count, max_keep_alive_count and max_subscription_lifetime_ms, which bound how long
    an orphaned subscription lives; max_subscriptions, the subscriptions of the whole server.
    """

    def _namespace_uris(self) -> list[str]:
        value = self.aspace.read_attribute(ua.NodeId(ua.ObjectIds.Server_NamespaceArray), ua.AttributeIds.Value)
        return list(value.Value.Value) if value.Value is not None and value.Value.Value else []

    def __init__(self, user_manager: UserManager | None = None) -> None:
        self.logger = logging.getLogger(__name__)
        self.callback_service = CallbackService()
        self.endpoints: list[ua.EndpointDescription] = []
        self._channel_id_counter = 5
        self.allow_plaintext_password = False
        self.identity_guard = IdentityGuard()
        self.disabled_clock = False
        self._known_servers: dict[str, ServerDesc] = {}
        self.accept_server_registrations: bool = False
        self.max_registered_servers: int = 100
        self.registration_timeout: float = 600.0
        self.clock: Callable[[], float] = time.monotonic
        self.untrusted_hints_logged: dict[str, float] = {}
        self.max_session_timeout_ms: float = 600_000
        self.min_session_timeout_ms: float = 5_000
        self.max_unacked_messages_per_subscription: int = 5_000
        self.max_monitored_item_queue_size: int = 1_000
        self.default_event_queue_size: int = 100
        self.min_sampling_interval_ms: float = 10.0
        self.history_sampling_interval_ms: float = 0.0
        self.max_history_data_response_size: int = 10_000
        self.max_history_continuation_points: int = 10
        self.max_sampling_interval_ms: float = 3_600_000.0
        self.max_monitored_items_per_subscription: int = 10_000
        self.max_monitored_items: int = 100_000
        self.max_pending_messages_per_connection: int = 500
        self.max_connections: int = 1_000
        self.channel_settings: ChannelSettings = ChannelSettings()
        self.hello_timeout_seconds: float = 30.0
        self.max_pending_activation_seconds: float = 30.0
        self.max_message_size_before_activation: int = 131_072
        self.max_lifetime_count: int = 15_000
        self.max_keep_alive_count: int = 5_000
        self.min_publishing_interval_ms: float = 50.0
        self.max_publishing_interval_ms: float = 3_600_000.0
        self.max_subscription_lifetime_ms: float = 86_400_000.0
        self.max_notifications_per_publish: int = 10_000
        self.max_subscriptions: int = 1_000
        self.max_subscriptions_per_session: int = 100
        self.max_browse_continuation_points: int = 10
        self.max_browse_references_per_node: int = 10_000
        self.max_translate_matches: int = 1_000
        self.max_string_length: int = 16_777_216
        self.max_byte_string_length: int = 16_777_216
        self.max_array_length: int = 1_000_000
        self._file_service: FileService | None = None
        self.certificate: x509.Certificate | None = None
        self.certificate_chain: list[x509.Certificate] = []
        self.private_key: rsa.RSAPrivateKey | None = None
        self.aspace = AddressSpace()
        self.types = ua.TypeRegistry(namespaces=self._namespace_uris, parents=(ua.default_types,))
        self.attribute_service = AttributeService(self.aspace)
        self.view_service = ViewService(self.aspace, self)
        self.method_service = MethodService(self.aspace)
        self.node_mgt_service = NodeManagementService(self.aspace)
        self.asyncio_transports: list[Any] = []
        self.subscription_service: SubscriptionService = SubscriptionService(self.aspace, iserver=self)
        self.history_manager = HistoryManager(self)
        self.condition_manager = ConditionManager(self)
        if user_manager is None:
            user_manager = AnonymousReadOnlyUserManager()
        self.user_manager: UserManager = user_manager
        self.trust_store: TrustStore | None = None
        self.certificate_validator: CertificateValidator | None = None
        self.user_trust_store: TrustStore | None = None
        self.user_certificate_grace_seconds: float = 60.0
        self.wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC)
        self._user_validator: CertificateValidator | None = None
        self._pinned_user_validator: tuple[frozenset[bytes], CertificateValidator] | None = None
        self.application_hook: ApplicationHook | None = None
        """extra check after the certificate validator accepted a certificate, raises a ServiceError to reject"""
        self.operation_limits = OperationLimits()
        self.diagnostics = DiagnosticsCollector(self)
        self.model_changes = ModelChangeNotifier(self)
        self.model_change_events: str = "all"
        self.session_manager = SessionManager(self)
        self.dispatcher = Dispatcher(self, build_service_table())
        self.isession: InternalSession = self.session_manager.new_in_process_session()
        self.current_time_node = Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
        self.server_status_node = Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerStatus))
        self.time_task: asyncio.Task[None] | None = None
        self._time_task_stop = asyncio.Event()
        self.match_discovery_endpoint_url: bool = True
        self.match_discovery_source_ip: bool = True
        self.supported_tokens: tuple[type, ...] = (
            ua.AnonymousIdentityToken,
            ua.X509IdentityToken,
            ua.UserNameIdentityToken,
        )

    @property
    def file_service(self) -> FileService:
        """The FileType and FileDirectoryType Objects of the server, created on first use."""
        if self._file_service is None:
            self._file_service = FileService(self)
        return self._file_service

    async def init(self, shelffile: Path | None = None) -> None:
        """Build the standard address space and install diagnostics, history and conditions."""
        await self.load_standard_address_space(shelffile)
        await self._address_space_fixes()
        await self.setup_nodes()
        await self.diagnostics.install()
        await self.history_manager.init()
        await self.condition_manager.init()

    async def setup_nodes(self) -> None:
        """Write the NamespaceArray, the ServerArray, the OperationLimits and the ServerCapabilities limits."""
        uries = ["http://opcfoundation.org/UA/"]
        ns_node = Node(self.isession, ua.NodeId(ua.ObjectIds.Server_NamespaceArray))
        await ns_node.write_value(uries)
        server_array_node = Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerArray))
        await server_array_node.write_value(ua.Variant([], ua.VariantType.String))

        params = ua.WriteParameters()
        for limit in fields(self.operation_limits):
            nodeid = OPERATION_LIMIT_NODES[limit.name]
            attr = ua.WriteValue()
            attr.NodeId = ua.NodeId(nodeid)
            attr.AttributeId = ua.AttributeIds.Value
            attr.Value = ua.DataValue(
                ua.Variant(getattr(self.operation_limits, limit.name), ua.VariantType.UInt32),
                StatusCode=ua.StatusCode(ua.StatusCodes.Good),
                SourceTimestamp=datetime.now(UTC),
            )
            params.NodesToWrite.append(attr)
        capabilities = {
            ua.ObjectIds.Server_ServerCapabilities_MaxHistoryContinuationPoints: ua.Variant(
                self.max_history_continuation_points, ua.VariantType.UInt16
            ),
            ua.ObjectIds.Server_ServerCapabilities_MinSupportedSampleRate: ua.Variant(
                self.min_sampling_interval_ms, ua.VariantType.Double
            ),
            ua.ObjectIds.Server_ServerCapabilities_MaxBrowseContinuationPoints: ua.Variant(
                self.max_browse_continuation_points, ua.VariantType.UInt16
            ),
            ua.ObjectIds.Server_ServerCapabilities_MaxMonitoredItemsQueueSize: ua.Variant(
                self.max_monitored_item_queue_size, ua.VariantType.UInt32
            ),
            ua.ObjectIds.Server_ServerCapabilities_MaxByteStringLength: ua.Variant(
                self.max_byte_string_length, ua.VariantType.UInt32
            ),
            ua.ObjectIds.Server_ServerCapabilities_MaxStringLength: ua.Variant(
                self.max_string_length, ua.VariantType.UInt32
            ),
            ua.ObjectIds.Server_ServerCapabilities_MaxArrayLength: ua.Variant(
                self.max_array_length, ua.VariantType.UInt32
            ),
        }
        for nodeid, variant in capabilities.items():
            capability = ua.WriteValue()
            capability.NodeId = ua.NodeId(nodeid)
            capability.AttributeId = ua.AttributeIds.Value
            capability.Value = ua.DataValue(variant)
            params.NodesToWrite.append(capability)
        result = await self.isession.write(params)
        for status in result:
            status.check()

    async def load_standard_address_space(self, shelf_file: Path | None = None) -> None:
        """
        Fill namespace 0 from the shelf file if it exists, else from the generated code, and then write the shelf
        file if one was named.
        """
        if shelf_file:
            if shelf_file.is_file() or shelf_file.with_suffix(".db").is_file():  # noqa: ASYNC240
                self.aspace.load_aspace_shelf(shelf_file)
                return
        from .standard_address_space import standard_address_space

        await asyncio.to_thread(standard_address_space.fill_address_space, self.node_mgt_service)
        if shelf_file:
            await asyncio.to_thread(self.aspace.make_aspace_shelf, shelf_file)

    async def _address_space_fixes(self) -> None:
        """
        Add the inverse Organizes references of BaseObjectType and BaseDataType to their folders, which the NodeSet
        lacks.
        """
        it = ua.AddReferencesItem()
        it.SourceNodeId = ua.NodeId(ua.ObjectIds.BaseObjectType)
        it.ReferenceTypeId = ua.NodeId(ua.ObjectIds.Organizes)
        it.IsForward = False
        it.TargetNodeId = ua.NodeId(ua.ObjectIds.ObjectTypesFolder)
        it.TargetNodeClass = ua.NodeClass.Object

        it2 = ua.AddReferencesItem()
        it2.SourceNodeId = ua.NodeId(ua.ObjectIds.BaseDataType)
        it2.ReferenceTypeId = ua.NodeId(ua.ObjectIds.Organizes)
        it2.IsForward = False
        it2.TargetNodeId = ua.NodeId(ua.ObjectIds.DataTypesFolder)
        it2.TargetNodeClass = ua.NodeClass.Object

        results = await self.isession.add_references([it, it2])
        for res in results:
            res.check()

    def load_address_space(self, path: str | Path) -> None:
        """
        Load address space from path
        """
        self.aspace.load(path)

    def dump_address_space(self, path: str | Path) -> None:
        """
        Dump current address space to path
        """
        self.aspace.dump(path)

    async def start(self) -> None:
        """Set the server state to Running, write the StartTime and start the clock and the session timeouts."""
        self.logger.info("starting internal server")
        for edp in self.endpoints:
            self._known_servers[edp.Server.ApplicationUri] = ServerDesc(edp.Server)
        await self.set_server_state(ua.ServerState.Running)
        start_time = datetime.now(UTC)
        status = copy(await self.server_status_node.read_value()) or ua.ServerStatusDataType()
        status.StartTime = start_time
        await self.server_status_node.write_value(status)
        await Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerStatus_StartTime)).write_value(start_time)
        if not self.disabled_clock:
            self._time_task_stop.clear()
            self.time_task = asyncio.create_task(self._set_current_time_loop())
        self.session_manager.start()
        self.model_changes.enabled = True

    async def set_server_state(self, state: ua.ServerState) -> None:
        """Write the State of ServerStatus."""
        status = copy(await self.server_status_node.read_value()) or ua.ServerStatusDataType()
        status.State = state
        await self.server_status_node.write_value(status)
        await Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerStatus_State)).write_value(
            state, ua.VariantType.Int32
        )

    async def stop(self) -> None:
        """Close all sessions, delete the subscriptions and stop history, diagnostics and conditions."""
        self.logger.info("stopping internal server")
        self.model_changes.enabled = False
        if self.time_task:
            self._time_task_stop.set()
            await self.time_task
        self.method_service.stop()
        await self.session_manager.close_all()
        for sub_id, sub in list(self.subscription_service.subscriptions.items()):
            await self.subscription_service.delete_subscriptions([sub_id], sub.session_id)
        await self.history_manager.stop()
        await self.diagnostics.stop()
        await self.condition_manager.stop()

    async def _set_current_time_loop(self) -> None:
        while not self._time_task_stop.is_set():
            status = copy(await self.server_status_node.read_value())
            status.CurrentTime = datetime.now(UTC)
            await self.server_status_node.write_value(status)
            await self.current_time_node.write_value(status.CurrentTime)
            try:
                await asyncio.wait_for(self._time_task_stop.wait(), 1)
            except TimeoutError:
                pass

    def get_new_channel_id(self) -> int:
        """Return the next SecureChannel id."""
        self._channel_id_counter += 1
        return self._channel_id_counter

    def add_endpoint(self, endpoint: ua.EndpointDescription) -> None:
        """Offer an endpoint."""
        self.endpoints.append(endpoint)

    def _mangle_endpoint_url(
        self,
        ep_url: str,
        params_ep_url: str | None = None,
        sockname: tuple[str, int] | None = None,
    ) -> str:
        url = urlparse(ep_url)
        if self.match_discovery_endpoint_url and params_ep_url:
            try:
                netloc = urlparse(params_ep_url).netloc
            except ValueError:
                netloc = ""
            if netloc:
                return url._replace(netloc=netloc).geturl()
        if self.match_discovery_source_ip and sockname:
            return url._replace(netloc=sockname[0] + ":" + str(sockname[1])).geturl()
        return url.geturl()

    async def get_endpoints(
        self, params: ua.GetEndpointsParameters | None = None, sockname: tuple[str, int] | None = None
    ) -> list[ua.EndpointDescription]:
        """
        GetEndpoints (OPC 10000-4 v1.05, 5.5.4): the endpoints, with the host of their URLs taken from the request URL
        or the local socket address as set by match_discovery_endpoint_url and match_discovery_source_ip.
        """
        self.logger.debug("get endpoint")
        edps = []
        params_ep_url = params.EndpointUrl if params else None
        for edp in self.endpoints:
            edp = copy(edp)
            edp.EndpointUrl = self._mangle_endpoint_url(edp.EndpointUrl, params_ep_url=params_ep_url, sockname=sockname)
            edp.Server = copy(edp.Server)
            edp.Server.DiscoveryUrls = [
                self._mangle_endpoint_url(url, params_ep_url=params_ep_url, sockname=sockname)
                for url in edp.Server.DiscoveryUrls
            ]
            edps.append(edp)
        return edps

    def find_servers(
        self, params: ua.FindServersParameters, sockname: tuple[str, int] | None = None
    ) -> list[ua.ApplicationDescription]:
        """
        FindServers (OPC 10000-4 v1.05, 5.5.2): this server and the registered servers whose registration has not
        expired; with ServerUris only those whose ApplicationUri is in the list.
        """
        servers = []
        wanted = set(params.ServerUris or [])
        our_application_uris = [edp.Server.ApplicationUri for edp in self.endpoints]
        for desc in list(self._known_servers.values()):
            if self._is_registration_expired(desc):
                continue
            if wanted and desc.Server.ApplicationUri not in wanted:
                continue
            if desc.Server.ApplicationUri in our_application_uris:
                serv = copy(desc.Server)
                serv.DiscoveryUrls = [
                    self._mangle_endpoint_url(url, params_ep_url=params.EndpointUrl, sockname=sockname)
                    for url in serv.DiscoveryUrls
                ]
            else:
                serv = desc.Server
            servers.append(serv)
        return servers

    def _is_registration_expired(self, desc: ServerDesc) -> bool:
        return desc.registered_at is not None and self.clock() - desc.registered_at > self.registration_timeout

    def _registered_uris(self) -> list[str]:
        return [uri for uri, desc in self._known_servers.items() if desc.registered_at is not None]

    def register_server(self, server: ua.RegisteredServer, conf: list[ua.DiscoveryConfiguration] | None = None) -> None:
        """
        Register a server, or remove it when IsOnline is False (OPC 10000-4 v1.05, 5.5.5); raise
        BadServerUriInvalid for the URI of this server and BadResourceUnavailable when the registry is full.
        """
        uri = server.ServerUri
        known = self._known_servers.get(uri)
        if known is not None and known.registered_at is None:
            raise ServiceError(ua.StatusCodes.BadServerUriInvalid)
        if not server.IsOnline:
            self._known_servers.pop(uri, None)
            return
        for expired in [u for u in self._registered_uris() if self._is_registration_expired(self._known_servers[u])]:
            del self._known_servers[expired]
        if known is None and len(self._registered_uris()) >= self.max_registered_servers:
            _logger.warning("Rejected the registration of %s: the registry is full", uri)
            raise ServiceError(ua.StatusCodes.BadResourceUnavailable)
        appdesc = ua.ApplicationDescription()
        appdesc.ApplicationUri = uri
        appdesc.ProductUri = server.ProductUri
        appdesc.ApplicationName = server.ServerNames[0]
        appdesc.ApplicationType = server.ServerType
        appdesc.DiscoveryUrls = server.DiscoveryUrls
        appdesc.GatewayServerUri = server.GatewayServerUri
        self._known_servers[uri] = ServerDesc(appdesc, conf, registered_at=self.clock())

    def register_server2(self, params: ua.RegisterServer2Parameters) -> None:
        """RegisterServer2: register_server with the discovery configurations."""
        return self.register_server(params.Server, params.DiscoveryConfiguration)

    async def enable_history_data_change(
        self, node: Node, period: timedelta | None = timedelta(days=7), count: int = 0
    ) -> None:
        """Start storing the data changes of node; see HistoryManager.historize_data_change."""
        await self.history_manager.historize_data_change(node, period, count)

    async def disable_history_data_change(self, node: Node) -> None:
        """Stop storing the data changes of node; the stored history stays readable."""
        await self.history_manager.dehistorize(node)

    async def enable_history_event(
        self, source: Node, period: timedelta | None = timedelta(days=7), count: int = 0
    ) -> None:
        """Start storing the events that reach source; see HistoryManager.historize_event."""
        await self.history_manager.historize_event(source, period, count)

    async def disable_history_event(self, source: Node) -> None:
        """Stop storing the events of source; the stored history stays readable."""
        await self.history_manager.dehistorize(source)

    def subscribe_server_callback(self, event: CallbackType, handle: Callable[..., Any]) -> None:
        """Call handle for every server callback of this type."""
        self.callback_service.addListener(event, handle)

    def unsubscribe_server_callback(self, event: CallbackType, handle: Callable[..., Any]) -> None:
        """Stop calling handle for this callback type."""
        self.callback_service.removeListener(event, handle)

    async def write_attribute_value(
        self, nodeid: ua.NodeId, datavalue: ua.DataValue, attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> None:
        """
        Write datavalue to the Attribute as the application itself: the access bits are not checked, the type, shape
        and range are. Raises the error of a bad result.
        """
        status = await self.aspace.write_attribute_value(nodeid, attr, datavalue)
        status.check()

    def set_attribute_value_callback(
        self,
        nodeid: ua.NodeId,
        callback: Callable[[ua.NodeId, ua.AttributeIds], ua.DataValue],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> None:
        """
        Set a callback function to the Attribute that returns a value for read_attribute_value() instead of the
        written value. Note that it does not trigger the datachange_callbacks unlike write_attribute_value().
        """
        self.aspace.set_attribute_value_callback(nodeid, attr, callback)

    def set_attribute_value_setter(
        self,
        nodeid: ua.NodeId,
        setter: Callable[[NodeData, ua.AttributeIds, ua.DataValue], ua.StatusCode | Awaitable[Any] | None],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> None:
        """
        Set a setter function for the Attribute. This setter will be called when a new value is written, instead of
        storing it, and has to store the value itself. Its returned StatusCode is the result of the write (nothing
        returned is Good); a bad result, or a raised status-coded error, means nothing was written and the data change
        callbacks are not called.
        """
        self.aspace.set_attribute_value_setter(nodeid, attr, setter)

    def read_attribute_value(self, nodeid: ua.NodeId, attr: ua.AttributeIds = ua.AttributeIds.Value) -> ua.DataValue:
        """Read an Attribute directly, without the access checks of a client read."""
        return self.aspace.read_attribute_value(nodeid, attr)

    def user_certificate_validator(self) -> CertificateValidator | None:
        """
        Return the validator for the certificates of X509 identity tokens: one on the user trust store, else one on
        the certificates the user manager pins, else None.
        """
        store = self.user_trust_store
        if store is not None:
            if self._user_validator is None or self._user_validator.trust_store is not store:
                self._user_validator = CertificateValidator(store)
            return self._user_validator
        pinned = getattr(self.user_manager, "pinned_certificates", None)
        certificates = pinned() if pinned is not None else []
        if not certificates:
            return None
        key = frozenset(uacrypto.der_from_x509(certificate) for certificate in certificates)
        if self._pinned_user_validator is None or self._pinned_user_validator[0] != key:
            pinned_store = TrustStore()
            for certificate in certificates:
                pinned_store.pin(certificate)
            self._pinned_user_validator = (key, CertificateValidator(pinned_store))
        return self._pinned_user_validator[1]

    def offered_token_classes(self) -> tuple[type, ...]:
        """Return the supported identity token types that the user manager also accepts."""
        accepted = getattr(self.user_manager, "accepted_token_types", None)
        if accepted is None:
            return tuple(self.supported_tokens)
        return tuple(token for token in self.supported_tokens if TOKEN_TYPES.get(token) in accepted)

    def set_user_manager(self, user_manager: UserManager) -> None:
        """Set the user manager that authenticates the identity tokens of ActivateSession."""
        self.user_manager = user_manager

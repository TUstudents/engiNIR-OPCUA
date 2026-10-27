"""
Internal server implementing opcu-ua interface.
Can be used on server side or to implement binary/https opc-ua servers
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import Callable
from copy import copy
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from struct import unpack_from
from typing import Any
from urllib.parse import urlparse

from enginir_opcua import ua

from ..common.callback import CallbackService
from ..common.connection import ChannelSettings
from ..common.node import Node
from ..common.utils import ServiceError
from ..crypto import security_policies, uacrypto
from ..crypto.truststore import TrustStore
from ..crypto.validator import ApplicationHook, CertificateValidator
from .address_space import AddressSpace, AttributeService, MethodService, NodeData, NodeManagementService, ViewService
from .event_generator import EventGenerator
from .history import HistoryManager
from .internal_session import InternalSession, SessionManager
from .service_dispatch import Dispatcher
from .service_handlers import build_service_table
from .subscription_service import SubscriptionService
from .user_managers import PermissiveUserManager, UserManager

_logger = logging.getLogger(__name__)


USER_TOKEN_SECURITY_POLICIES: tuple[type[security_policies.SecurityPolicy], ...] = (
    security_policies.SecurityPolicyNone,
    security_policies.SecurityPolicyBasic128Rsa15,
    security_policies.SecurityPolicyBasic256,
    security_policies.SecurityPolicyBasic256Sha256,
    security_policies.SecurityPolicyAes128Sha256RsaOaep,
    security_policies.SecurityPolicyAes256Sha256RsaPss,
)


@dataclass
class OperationLimits:
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
    def __init__(self, serv: Any, cap: Any = None) -> None:
        self.Server = serv
        self.Capabilities = cap


class InternalServer:
    """
    There is one `InternalServer` for every `Server`.
    """

    def __init__(self, user_manager: UserManager | None = None) -> None:
        self.logger = logging.getLogger(__name__)
        self.callback_service = CallbackService()
        self.endpoints: list[ua.EndpointDescription] = []
        self._channel_id_counter = 5
        self.allow_remote_admin = True
        self.bind_condition_methods: bool | int = False
        self.disabled_clock = False  # for debugging, we may want to disable clock that writes too much in log
        self._known_servers: dict[str, ServerDesc] = {}  # used if we are a discovery server
        self.accept_server_registrations: bool = False
        # Server-side limits — clamp client-requested values to avoid resource exhaustion
        # when clients abandon long-lived sessions. Tighten on a per-deployment basis.
        self.max_session_timeout_ms: float = 600_000
        self.min_session_timeout_ms: float = 5_000
        self.max_unacked_messages_per_subscription: int = 5_000
        self.max_monitored_item_queue_size: int = 10_000
        # Per-connection inbound message queue depth. data_received() refuses
        # further frames and closes the transport once this many parsed
        # messages are queued behind the processor coroutine.
        self.max_pending_messages_per_connection: int = 500
        # Maximum number of accepted TCP connections (pre-activation included).
        # Refused at connection_made() to prevent FD exhaustion via parked sockets
        # that never call ActivateSession.
        self.max_connections: int = 1_000
        self.channel_settings: ChannelSettings = ChannelSettings()
        # A connection that has not sent its Hello this many seconds after connecting is closed.
        self.hello_timeout_seconds: float = 30.0
        # Connections that haven't activated a session this many seconds after
        # connecting are closed by the binary server. 0 disables the watchdog.
        self.max_pending_activation_seconds: float = 30.0
        # Subscription parameter clamps — protect against clients that ask for
        # near-infinite RevisedLifetimeCount and then close the session without
        # deleting subscriptions (CVE-2022-24298 family). Orphaned-subscription
        # lifetime is RevisedLifetimeCount * RevisedPublishingInterval, so the
        # count cap is what matters; PublishingInterval is left to the client.
        self.max_lifetime_count: int = 15_000
        self.max_keep_alive_count: int = 5_000
        self.min_publishing_interval_ms: float = 50.0
        self.max_publishing_interval_ms: float = 3_600_000.0
        self.max_subscription_lifetime_ms: float = 86_400_000.0
        self.max_notifications_per_publish: int = 10_000
        # Total subscription count cap across the whole server. Past this,
        # CreateSubscription returns BadTooManySubscriptions.
        self.max_subscriptions: int = 1_000
        self.max_subscriptions_per_session: int = 100
        self.certificate: Any = None
        self.certificate_chain: list[Any] = []
        self.private_key: Any = None
        self.aspace = AddressSpace()
        self.attribute_service = AttributeService(self.aspace)
        self.view_service = ViewService(self.aspace)
        self.method_service = MethodService(self.aspace)
        self.node_mgt_service = NodeManagementService(self.aspace)
        self.asyncio_transports: list[Any] = []
        self.subscription_service: SubscriptionService = SubscriptionService(self.aspace, iserver=self)
        self.history_manager = HistoryManager(self)
        if user_manager is None:
            _logger.info("No user manager specified. Using default permissive manager instead.")
            user_manager = PermissiveUserManager()
        self.user_manager = user_manager
        self.trust_store: TrustStore | None = None
        self.certificate_validator: CertificateValidator | None = None
        self.application_hook: ApplicationHook | None = None
        """extra check after the certificate validator accepted a certificate, raises a ServiceError to reject"""
        self.operation_limits = OperationLimits()
        self.session_manager = SessionManager(self)
        self.dispatcher = Dispatcher(self, build_service_table())
        self.isession: InternalSession = self.session_manager.new_in_process_session()
        self.current_time_node = Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
        self.server_status_node = Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerStatus))
        self.time_task: asyncio.Task[None] | None = None
        self._time_task_stop = asyncio.Event()
        self.match_discovery_endpoint_url: bool = True
        self.match_discovery_source_ip: bool = True
        self.supported_tokens = (ua.AnonymousIdentityToken, ua.X509IdentityToken, ua.UserNameIdentityToken)

    async def init(self, shelffile: Path | None = None) -> None:
        await self.load_standard_address_space(shelffile)
        await self._address_space_fixes()
        await self.setup_nodes()
        await self.history_manager.init()
        if self.bind_condition_methods:
            await self.setup_condition_methods()

    async def setup_condition_methods(self) -> None:
        for etype in (ua.ObjectIds.RefreshStartEventType, ua.ObjectIds.RefreshEndEventType):
            evgen = EventGenerator(self.isession)
            await evgen.init(etype, add_generates_event=False)
            # don't use isinstance(int), it also matches bool
            if isinstance(self.bind_condition_methods, int):
                evgen.event.Severity = self.bind_condition_methods
            self.subscription_service.standard_events[etype] = evgen

        self.isession.add_method_callback(
            ua.NodeId(ua.ObjectIds.ConditionType_ConditionRefresh), self.subscription_service.condition_refresh
        )
        self.isession.add_method_callback(
            ua.NodeId(ua.ObjectIds.ConditionType_ConditionRefresh2), self.subscription_service.condition_refresh
        )

    async def setup_nodes(self) -> None:
        """
        Set up some nodes as defined by spec
        """
        uries = ["http://opcfoundation.org/UA/"]
        ns_node = Node(self.isession, ua.NodeId(ua.ObjectIds.Server_NamespaceArray))
        await ns_node.write_value(uries)

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
        result = await self.isession.write(params)
        result[0].check()

    async def load_standard_address_space(self, shelf_file: Path | None = None) -> None:
        if shelf_file:
            if shelf_file.is_file() or shelf_file.with_suffix(".db").is_file():  # noqa: ASYNC240
                # import address space from shelf
                self.aspace.load_aspace_shelf(shelf_file)
                return
        # import address space from code generated from xml
        from .standard_address_space import standard_address_space

        await asyncio.to_thread(standard_address_space.fill_address_space, self.node_mgt_service)
        # import address space directly from xml, this has performance impact so disabled
        # importer = xmlimporter.XmlImporter(self.node_mgt_service)
        # importer.import_xml("/path/to/enginir-opcua/schemas/Opc.Ua.NodeSet2.xml", self)
        if shelf_file:
            # path was supplied, but file doesn't exist - create one for next start up
            await asyncio.to_thread(self.aspace.make_aspace_shelf, shelf_file)

    async def _address_space_fixes(self) -> None:
        """
        Looks like the xml definition of address space has some error. This is a good place to fix them
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

    async def set_server_state(self, state: ua.ServerState) -> None:
        status = copy(await self.server_status_node.read_value()) or ua.ServerStatusDataType()
        status.State = state
        await self.server_status_node.write_value(status)
        await Node(self.isession, ua.NodeId(ua.ObjectIds.Server_ServerStatus_State)).write_value(
            state, ua.VariantType.Int32
        )

    async def stop(self) -> None:
        self.logger.info("stopping internal server")
        if self.time_task:
            self._time_task_stop.set()
            await self.time_task
        self.method_service.stop()
        await self.session_manager.close_all()
        for sub_id, sub in list(self.subscription_service.subscriptions.items()):
            await self.subscription_service.delete_subscriptions([sub_id], sub.session_id)
        await self.history_manager.stop()

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
        self._channel_id_counter += 1
        return self._channel_id_counter

    def add_endpoint(self, endpoint: ua.EndpointDescription) -> None:
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
        self.logger.info("get endpoint")
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
        servers = []
        params_server_uris = [uri.split(":") for uri in params.ServerUris] if params.ServerUris else []
        our_application_uris = [edp.Server.ApplicationUri for edp in self.endpoints]
        for desc in self._known_servers.values():
            if params_server_uris:
                serv_uri = desc.Server.ApplicationUri.split(":")
                if not any(serv_uri[: len(uri)] == uri for uri in params_server_uris):
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

    def register_server(self, server: Any, conf: Any = None) -> None:
        appdesc = ua.ApplicationDescription()
        appdesc.ApplicationUri = server.ServerUri
        appdesc.ProductUri = server.ProductUri
        # FIXME: select name from client locale
        appdesc.ApplicationName = server.ServerNames[0]
        appdesc.ApplicationType = server.ServerType
        appdesc.DiscoveryUrls = server.DiscoveryUrls
        # FIXME: select discovery uri using reachability from client network
        appdesc.GatewayServerUri = server.GatewayServerUri
        self._known_servers[server.ServerUri] = ServerDesc(appdesc, conf)

    def register_server2(self, params: ua.RegisterServer2Parameters) -> None:
        return self.register_server(params.Server, params.DiscoveryConfiguration)

    async def enable_history_data_change(
        self, node: Node, period: timedelta | None = timedelta(days=7), count: int = 0
    ) -> None:
        """
        Set attribute Historizing of node to True and start storing data for history
        """
        await node.write_attribute(ua.AttributeIds.Historizing, ua.DataValue(True))
        await node.set_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.HistoryRead)
        await node.set_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.HistoryRead)
        await self.history_manager.historize_data_change(node, period, count)

    async def disable_history_data_change(self, node: Node) -> None:
        """
        Set attribute Historizing of node to False and stop storing data for history
        """
        await node.write_attribute(ua.AttributeIds.Historizing, ua.DataValue(False))
        await node.unset_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.HistoryRead)
        await node.unset_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.HistoryRead)
        await self.history_manager.dehistorize(node)

    async def enable_history_event(
        self, source: Node, period: timedelta | None = timedelta(days=7), count: int = 0
    ) -> None:
        """
        Set attribute History Read of object events to True and start storing data for history
        """
        event_notifier = await source.read_event_notifier()
        if ua.EventNotifier.SubscribeToEvents not in event_notifier:
            raise ua.UaError("Node does not generate events", event_notifier)
        if ua.EventNotifier.HistoryRead not in event_notifier:
            event_notifier.add(ua.EventNotifier.HistoryRead)
            await source.set_event_notifier(event_notifier)
        await self.history_manager.historize_event(source, period, count)

    async def disable_history_event(self, source: Node) -> None:
        """
        Set attribute History Read of node to False and stop storing data for history
        """
        await source.unset_attr_bit(ua.AttributeIds.EventNotifier, ua.EventNotifier.HistoryRead)
        await self.history_manager.dehistorize(source)

    def subscribe_server_callback(self, event: str, handle: Callable[..., Any]) -> None:
        """
        Create a subscription from event to handle
        """
        self.callback_service.addListener(event, handle)

    def unsubscribe_server_callback(self, event: str, handle: Callable[..., Any]) -> None:
        """
        Remove a subscription from event to handle
        """
        self.callback_service.removeListener(event, handle)

    async def write_attribute_value(
        self, nodeid: ua.NodeId, datavalue: ua.DataValue, attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> None:
        """
        directly write datavalue to the Attribute, bypassing some checks and structure creation,
        so it is a little faster
        """
        await self.aspace.write_attribute_value(nodeid, attr, datavalue)

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
        setter: Callable[[NodeData, ua.AttributeIds, ua.DataValue], None],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> None:
        """
        Set a setter function for the Attribute. This setter will be called when a new value is set using
        write_attribute_value() instead of directly writing the value. This is useful, for example, if you want to
        intercept writes to certain attributes to perform some kind of validation of the value to be written and return
        appropriate status codes to the client.
        """
        self.aspace.set_attribute_value_setter(nodeid, attr, setter)

    def read_attribute_value(self, nodeid: ua.NodeId, attr: ua.AttributeIds = ua.AttributeIds.Value) -> ua.DataValue:
        """
        directly read datavalue of the Attribute
        """
        return self.aspace.read_attribute_value(nodeid, attr)

    def set_user_manager(self, user_manager: UserManager) -> None:
        """
        set up a function which that will check for authorize users. Input function takes username
        and password as parameters and returns True of user is allowed access, False otherwise.
        """
        self.user_manager = user_manager

    def _username_token_policy(
        self, isession: Any, token: ua.UserNameIdentityToken
    ) -> tuple[ua.UserTokenPolicy, ua.EndpointDescription]:
        channel = isession.channel_security
        for endpoint in self.endpoints:
            if channel is not None and (
                endpoint.SecurityPolicyUri != channel.policy_uri or endpoint.SecurityMode != channel.mode
            ):
                continue
            for policy in endpoint.UserIdentityTokens:
                if policy.TokenType == ua.UserTokenType.UserName and policy.PolicyId == token.PolicyId:
                    return policy, endpoint
        self.logger.warning("Rejected user token with unknown PolicyId %s", token.PolicyId)
        raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)

    @staticmethod
    def _token_encryption_algorithm(policy: ua.UserTokenPolicy, endpoint: ua.EndpointDescription) -> str:
        policy_uri = policy.SecurityPolicyUri or endpoint.SecurityPolicyUri
        for policy_class in USER_TOKEN_SECURITY_POLICIES:
            if policy_class.URI == policy_uri:
                return policy_class.AsymmetricEncryptionURI
        raise ServiceError(ua.StatusCodes.BadSecurityPolicyRejected)

    def decrypt_user_token(self, isession: Any, token: ua.UserNameIdentityToken) -> tuple[str, str]:
        """
        unpack the username and password for the benefit of the user defined user manager
        """
        policy, endpoint = self._username_token_policy(isession, token)
        if not token.Password and not token.EncryptionAlgorithm:
            return token.UserName, token.Password
        expected_algorithm = self._token_encryption_algorithm(policy, endpoint)
        if (token.EncryptionAlgorithm or "") != expected_algorithm:
            self.logger.warning(
                "Rejected user token encrypted with %r, policy %s requires %r",
                token.EncryptionAlgorithm,
                policy.PolicyId,
                expected_algorithm,
            )
            raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)
        password = token.Password
        if expected_algorithm:
            password = self._decrypt_password_secret(isession.nonce, expected_algorithm, password)
        elif isinstance(password, bytes):
            password = password.decode("utf-8")
        return token.UserName, password

    def _decrypt_password_secret(self, nonce: bytes, algorithm: str, secret: bytes) -> str:
        if algorithm == "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
            raw = uacrypto.decrypt_rsa15(self.private_key, secret)
        elif algorithm == "http://www.w3.org/2001/04/xmlenc#rsa-oaep":
            raw = uacrypto.decrypt_rsa_oaep(self.private_key, secret)
        elif algorithm == "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256":
            raw = uacrypto.decrypt_rsa_oaep_sha256(self.private_key, secret)
        else:
            raise ServiceError(ua.StatusCodes.BadSecurityPolicyRejected)
        length = unpack_from("<I", raw)[0]
        plain = raw[4 : 4 + length]
        password, token_nonce = plain[: len(plain) - len(nonce)], plain[len(plain) - len(nonce) :]
        if len(plain) < len(nonce) or not hmac.compare_digest(token_nonce, nonce):
            self.logger.warning("Rejected user token that is not bound to the current server nonce")
            raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)
        return password.decode("utf-8")

    def verify_x509_token(self, isession: Any, token: ua.X509IdentityToken, signature: ua.SignatureData) -> bytes:
        """
        verify certificate signature
        """
        cert = uacrypto.x509_from_der(token.CertificateData)
        alg = signature.Algorithm
        sig = signature.Signature

        # TODO check if algorithm is allowed, throw BadSecurityPolicyRejected if not

        challenge = b""
        if self.certificate is not None:
            challenge += uacrypto.der_from_x509(self.certificate)
        if isession.nonce is not None:
            challenge += isession.nonce

        if not (alg and sig):
            raise ServiceError(ua.StatusCodes.BadUserSignatureInvalid)

        try:
            if alg == "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
                uacrypto.verify_sha1(cert, challenge, sig)
            elif alg == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                uacrypto.verify_sha256(cert, challenge, sig)
            elif alg == "http://opcfoundation.org/UA/security/rsa-pss-sha2-256":
                uacrypto.verify_pss_sha256(cert, challenge, sig)
            else:
                self.logger.warning("Unknown certificate signature algorithm %s", alg)
                raise ServiceError(ua.StatusCodes.BadSecurityPolicyRejected)
        except ua.uaerrors.SignatureError:
            raise ServiceError(ua.StatusCodes.BadUserSignatureInvalid) from None

        return token.CertificateData

import copy
import logging
from collections.abc import Callable

from enginir_opcua import ua

from ..common.connection import (
    HELLO_MAX_CHUNK_SIZE,
    AbortedMessage,
    MessageAborted,
    MessageTooLarge,
    OpenRequestError,
    SecureChannel,
    TransportError,
    TransportLimits,
    error_message_to_binary,
)
from ..common.utils import Buffer, ServiceError
from ..crypto.security_policies import SecurityPolicyNone
from ..ua.ua_binary import nodeid_from_binary, struct_from_binary, struct_to_binary, uatcp_to_binary
from .internal_server import InternalServer
from .internal_session import ChannelSecurity, PublishRequestData

_logger = logging.getLogger(__name__)


class UaProcessor:
    """
    Processor for OPC UA messages. Implements the OPC UA protocol for the server side.
    """

    def __init__(self, internal_server: InternalServer, transport, limits: TransportLimits):
        self.iserver: InternalServer = internal_server
        self.name = transport.get_extra_info("peername")
        self.sockname = transport.get_extra_info("sockname")
        self._transport = transport
        self._limits = copy.deepcopy(limits)  # Copy limits because they get overriden
        self._channel = SecureChannel(SecurityPolicyNone(), self._limits)
        self._hello_received: bool = False
        self._hello_protocol_version = 0
        self.on_token_window: Callable[[float], None] | None = None

    @property
    def last_used(self) -> float:
        return self._channel.last_used

    def channel_expires_in(self) -> float:
        return self._channel.expires_in()

    @property
    def channel_id(self) -> int:
        return self._channel.channel_id

    @property
    def security(self) -> ChannelSecurity:
        policy = self._channel.security_policy
        return ChannelSecurity(policy.peer_certificate, policy.URI, policy.Mode)

    @property
    def max_request_message_size(self) -> int:
        return self._limits.max_message_size

    @property
    def server_certificate(self) -> bytes | None:
        return self._channel.security_policy.host_certificate

    @property
    def signature_algorithm(self) -> str | None:
        return self._channel.security_policy.AsymmetricSignatureURI

    def sign(self, data: bytes) -> bytes:
        return self._channel.security_policy.asymmetric_cryptography.signature(data)

    def verify(self, data: bytes, signature: bytes | None) -> None:
        self._channel.security_policy.asymmetric_cryptography.verify(data, signature)

    @property
    def hello_received(self) -> bool:
        return self._hello_received

    def accept_hello(self, body: Buffer) -> bytes:
        try:
            hello = struct_from_binary(ua.Hello, body)
        except ua.UaError as e:
            raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Malformed Hello") from e
        ack = self._limits.create_acknowledge_and_set_limits(hello)
        self._hello_received = True
        self._hello_protocol_version = hello.ProtocolVersion
        return uatcp_to_binary(ua.MessageType.Acknowledge, ack)

    def max_receive_chunk_size(self) -> int:
        if self._hello_received:
            return self._limits.max_recv_buffer
        return HELLO_MAX_CHUNK_SIZE

    def set_policies(self, policies):
        self._channel.set_policy_factories(policies)

    def send_response(self, requesthandle, seqhdr, response, msgtype=ua.MessageType.SecureMessage):
        response.ResponseHeader.RequestHandle = requesthandle
        try:
            data = self._channel.message_to_binary(
                struct_to_binary(response), message_type=msgtype, request_id=seqhdr.RequestId
            )
        except MessageTooLarge:
            _logger.warning(
                "Response %s to request %s is above the limits of the client", type(response), requesthandle
            )
            fault = ua.ServiceFault()
            fault.ResponseHeader.RequestHandle = requesthandle
            fault.ResponseHeader.ServiceResult = ua.StatusCode(ua.StatusCodes.BadResponseTooLarge)
            data = self._channel.message_to_binary(
                struct_to_binary(fault), message_type=msgtype, request_id=seqhdr.RequestId
            )
        except MessageAborted as e:
            _logger.warning("Response to request %s was aborted", requesthandle)
            data = e.written
        self._transport.write(data)

    def open_secure_channel(self, message: ua.Message) -> bool:
        algohdr = message.security_header()
        assert isinstance(algohdr, ua.AsymmetricAlgorithmHeader)
        seqhdr = message.sequence_header()
        request = struct_from_binary(ua.OpenSecureChannelRequest, message.body())
        handle = request.RequestHeader.RequestHandle
        try:
            if not self._channel.is_open():
                self._channel.select_policy(
                    algohdr.SecurityPolicyURI, algohdr.SenderCertificate, request.Parameters.SecurityMode
                )
            self._channel.validate_open_request(
                message.channel_id(), algohdr, request.Parameters, self._hello_protocol_version
            )
        except TransportError as e:
            _logger.warning("Closing connection from %s: %s", self.name, e.reason)
            self._send_error(e.status)
            return False
        except OpenRequestError as e:
            _logger.warning("Rejecting OpenSecureChannel from %s: %s", self.name, e.reason)
            fault = ua.ServiceFault()
            fault.ResponseHeader.ServiceResult = ua.StatusCode(e.status)
            self.send_response(handle, seqhdr, fault, ua.MessageType.SecureOpen)
            return False
        channel = self._channel.open(request.Parameters, self.iserver, self.iserver.channel_settings)
        response = ua.OpenSecureChannelResponse()
        response.Parameters = channel
        self.send_response(handle, seqhdr, response, ua.MessageType.SecureOpen)
        if self.on_token_window is not None:
            self.on_token_window(self._channel.expires_in())
        return True

    def _send_error(self, status: int) -> None:
        self._transport.write(error_message_to_binary(status))

    async def process(self, header, body):
        try:
            msg = self._channel.receive_from_header_and_body(header, body)
        except ua.uaerrors.BadUserAccessDenied:
            _logger.warning("Unauthenticated user attempted to connect")
            return False
        except TransportError as e:
            _logger.warning("Closing connection from %s: %s", self.name, e.reason)
            self._send_error(e.status)
            return False
        except Exception as e:
            _logger.warning("Closing connection from %s: channel failure", self.name, exc_info=True)
            status = e.code if isinstance(e, ua.UaStatusCodeError) else ua.StatusCodes.BadSecurityChecksFailed
            self._send_error(status)
            return False
        if isinstance(msg, ua.Message):
            if header.MessageType == ua.MessageType.SecureOpen:
                return self.open_secure_channel(msg)
            if header.MessageType == ua.MessageType.SecureClose:
                self._channel.close()
                return False
            if header.MessageType == ua.MessageType.SecureMessage:
                return await self.process_message(msg.sequence_header(), msg.body())
        elif isinstance(msg, AbortedMessage):
            _logger.warning("Request %s was aborted by the client", msg.request_id)
        elif isinstance(msg, ua.ErrorMessage):
            _logger.warning("Received an error message type")
        elif msg is None:
            pass  # msg is a ChunkType.Intermediate of an ua.MessageType.SecureMessage
        else:
            _logger.warning("Unsupported message type: %s", header.MessageType)
            raise ServiceError(ua.StatusCodes.BadTcpMessageTypeInvalid)
        return True

    async def process_message(self, seqhdr, body):
        """
        Process incoming messages.
        """
        typeid = nodeid_from_binary(body)
        requesthdr = struct_from_binary(ua.RequestHeader, body)
        _logger.debug("process_message %r %r", typeid, requesthdr)
        try:
            return await self._process_message(typeid, requesthdr, seqhdr, body)
        except (ServiceError, ua.uaerrors.UaStatusCodeError) as e:
            status = ua.StatusCode(e.code)
            response = ua.ServiceFault()
            response.ResponseHeader.ServiceResult = status
            _logger.error("sending service fault response: %s (%s)", status.doc, status.name)
            self.send_response(requesthdr.RequestHandle, seqhdr, response)
            return True
        except ua.uaerrors.BadUserAccessDenied:
            _logger.warning("A request was refused because the user is not permitted to do it")
            response = ua.ServiceFault()
            response.ResponseHeader.ServiceResult = ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
            self.send_response(requesthdr.RequestHandle, seqhdr, response)
        except Exception:
            _logger.exception("Error while processing message")
            response = ua.ServiceFault()
            response.ResponseHeader.ServiceResult = ua.StatusCode(ua.StatusCodes.BadInternalError)
            self.send_response(requesthdr.RequestHandle, seqhdr, response)
            return True

    async def _process_message(self, typeid, requesthdr, seqhdr, body):
        manager = self.iserver.session_manager
        session = None
        user = None
        if typeid in [
            ua.NodeId(ua.ObjectIds.CreateSessionRequest_Encoding_DefaultBinary),
            ua.NodeId(ua.ObjectIds.CloseSessionRequest_Encoding_DefaultBinary),
            ua.NodeId(ua.ObjectIds.ActivateSessionRequest_Encoding_DefaultBinary),
            ua.NodeId(ua.ObjectIds.FindServersRequest_Encoding_DefaultBinary),
            ua.NodeId(ua.ObjectIds.GetEndpointsRequest_Encoding_DefaultBinary),
            ua.NodeId(ua.ObjectIds.RegisterServerRequest_Encoding_DefaultBinary),
            ua.NodeId(ua.ObjectIds.RegisterServer2Request_Encoding_DefaultBinary),
        ]:
            pass
        else:
            session = manager.resolve(self, requesthdr.AuthenticationToken)
            user = session.user
            if self._channel.security_policy.permissions is not None:
                if self._channel.security_policy.permissions.check_validity(user, typeid, body) is False:
                    raise ua.uaerrors.BadUserAccessDenied

        if typeid == ua.NodeId(ua.ObjectIds.CreateSessionRequest_Encoding_DefaultBinary):
            _logger.info("Create session request")
            params = struct_from_binary(ua.CreateSessionParameters, body)
            sessiondata = await manager.create_session(self, params, sockname=self.sockname)
            response = ua.CreateSessionResponse()
            response.Parameters = sessiondata
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.CloseSessionRequest_Encoding_DefaultBinary):
            _logger.info("Close session request")
            deletesubs = ua.ua_binary.Primitives.Boolean.unpack(body)
            await manager.close_session(self, requesthdr.AuthenticationToken, deletesubs)
            response = ua.CloseSessionResponse()
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.ActivateSessionRequest_Encoding_DefaultBinary):
            _logger.info("Activate session request")
            params = struct_from_binary(ua.ActivateSessionParameters, body)
            result = manager.activate_session(self, requesthdr.AuthenticationToken, params)
            response = ua.ActivateSessionResponse()
            response.Parameters = result
            self.send_response(requesthdr.RequestHandle, seqhdr, response)
        elif typeid == ua.NodeId(ua.ObjectIds.GetEndpointsRequest_Encoding_DefaultBinary):
            _logger.info("get endpoints request (%s)", user)
            params = struct_from_binary(ua.GetEndpointsParameters, body)
            endpoints = await self.iserver.get_endpoints(params, sockname=self.sockname)
            response = ua.GetEndpointsResponse()
            response.Endpoints = endpoints
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.FindServersRequest_Encoding_DefaultBinary):
            _logger.info("find servers request (%s)", user)
            params = struct_from_binary(ua.FindServersParameters, body)
            servers = self.iserver.find_servers(params, sockname=self.sockname)
            response = ua.FindServersResponse()
            response.Servers = servers
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.RegisterServerRequest_Encoding_DefaultBinary):
            _logger.info("register server request %s", user)
            if not self.iserver.accept_server_registrations:
                raise ServiceError(ua.StatusCodes.BadServiceUnsupported)
            serv = struct_from_binary(ua.RegisteredServer, body)
            self.iserver.register_server(serv)
            response = ua.RegisterServerResponse()
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.RegisterServer2Request_Encoding_DefaultBinary):
            _logger.info("register server 2 request %s", user)
            if not self.iserver.accept_server_registrations:
                raise ServiceError(ua.StatusCodes.BadServiceUnsupported)
            params = struct_from_binary(ua.RegisterServer2Parameters, body)
            results = self.iserver.register_server2(params)
            response = ua.RegisterServer2Response()
            response.ConfigurationResults = results
            self.send_response(requesthdr.RequestHandle, seqhdr, response)
        elif typeid == ua.NodeId(ua.ObjectIds.CloseSecureChannelRequest_Encoding_DefaultBinary):
            _logger.info("close secure channel request (%s)", user)
            self._channel.close()
            response = ua.CloseSecureChannelResponse()
            self.send_response(requesthdr.RequestHandle, seqhdr, response)
            return False
        else:
            assert session is not None
            await self._process_service(session, typeid, requesthdr, seqhdr, body)
        return True

    async def _process_service(self, session, typeid, requesthdr, seqhdr, body):
        user = session.user
        if typeid == ua.NodeId(ua.ObjectIds.ReadRequest_Encoding_DefaultBinary):
            _logger.info("Read request (%s)", user)
            params = struct_from_binary(ua.ReadParameters, body)
            results = await session.services.read(params)
            response = ua.ReadResponse()
            response.Results = results
            # _logger.info("sending read response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.WriteRequest_Encoding_DefaultBinary):
            _logger.info("Write request (%s)", user)
            params = struct_from_binary(ua.WriteParameters, body)
            results = await session.services.write(params)
            response = ua.WriteResponse()
            response.Results = results
            # _logger.info("sending write response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.BrowseRequest_Encoding_DefaultBinary):
            _logger.info("Browse request (%s)", user)
            params = struct_from_binary(ua.BrowseParameters, body)
            results = await session.services.browse(params)
            response = ua.BrowseResponse()
            response.Results = results
            # _logger.info("sending browse response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary):
            _logger.info("translate browsepaths to nodeids request (%s)", user)
            params = struct_from_binary(ua.TranslateBrowsePathsToNodeIdsParameters, body)
            paths = await session.services.translate_browsepaths_to_nodeids(params.BrowsePaths)
            response = ua.TranslateBrowsePathsToNodeIdsResponse()
            response.Results = paths
            # _logger.info("sending translate browsepaths to nodeids response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.AddNodesRequest_Encoding_DefaultBinary):
            _logger.info("add nodes request (%s)", user)
            params = struct_from_binary(ua.AddNodesParameters, body)
            results = await session.services.add_nodes(params.NodesToAdd)
            response = ua.AddNodesResponse()
            response.Results = results
            # _logger.info("sending add node response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.DeleteNodesRequest_Encoding_DefaultBinary):
            _logger.info("delete nodes request (%s)", user)
            params = struct_from_binary(ua.DeleteNodesParameters, body)
            results = await session.services.delete_nodes(params)
            response = ua.DeleteNodesResponse()
            response.Results = results
            # _logger.info("sending delete node response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.AddReferencesRequest_Encoding_DefaultBinary):
            _logger.info("add references request (%s)", user)
            params = struct_from_binary(ua.AddReferencesParameters, body)
            results = await session.services.add_references(params.ReferencesToAdd)
            response = ua.AddReferencesResponse()
            response.Results = results
            # _logger.info("sending add references response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.DeleteReferencesRequest_Encoding_DefaultBinary):
            _logger.info("delete references request (%s)", user)
            params = struct_from_binary(ua.DeleteReferencesParameters, body)
            results = await session.services.delete_references(params.ReferencesToDelete)
            response = ua.DeleteReferencesResponse()
            response.Parameters.Results = results
            # _logger.info("sending delete references response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.CreateSubscriptionRequest_Encoding_DefaultBinary):
            _logger.info("create subscription request (%s)", user)
            params = struct_from_binary(ua.CreateSubscriptionParameters, body)
            result = await session.services.create_subscription(
                params, session.forward_publish_response, request_callback=session.get_publish_request
            )
            response = ua.CreateSubscriptionResponse()
            response.Parameters = result
            # _logger.info("sending create subscription response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.ModifySubscriptionRequest_Encoding_DefaultBinary):
            _logger.info("modify subscription request")
            params = struct_from_binary(ua.ModifySubscriptionParameters, body)

            result = session.services.modify_subscription(params)

            response = ua.ModifySubscriptionResponse()
            response.Parameters = result

            # _logger.info("sending modify subscription response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.DeleteSubscriptionsRequest_Encoding_DefaultBinary):
            _logger.info("delete subscriptions request (%s)", user)
            params = struct_from_binary(ua.DeleteSubscriptionsParameters, body)
            results = await session.services.delete_subscriptions(params.SubscriptionIds)
            response = ua.DeleteSubscriptionsResponse()
            response.Results = results
            # _logger.info("sending delete subscription response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.CreateMonitoredItemsRequest_Encoding_DefaultBinary):
            _logger.info("create monitored items request (%s)", user)
            params = struct_from_binary(ua.CreateMonitoredItemsParameters, body)
            results = await session.services.create_monitored_items(params)
            response = ua.CreateMonitoredItemsResponse()
            response.Results = results
            # _logger.info("sending create monitored items response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.ModifyMonitoredItemsRequest_Encoding_DefaultBinary):
            _logger.info("modify monitored items request (%s)", user)
            params = struct_from_binary(ua.ModifyMonitoredItemsParameters, body)
            results = await session.services.modify_monitored_items(params)
            response = ua.ModifyMonitoredItemsResponse()
            response.Results = results
            # _logger.info("sending modify monitored items response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.DeleteMonitoredItemsRequest_Encoding_DefaultBinary):
            _logger.info("delete monitored items request (%s)", user)
            params = struct_from_binary(ua.DeleteMonitoredItemsParameters, body)
            results = await session.services.delete_monitored_items(params)
            response = ua.DeleteMonitoredItemsResponse()
            response.Results = results
            # _logger.info("sending delete monitored items response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.HistoryReadRequest_Encoding_DefaultBinary):
            _logger.info("history read request (%s)", user)
            params = struct_from_binary(ua.HistoryReadParameters, body)
            results = await session.services.history_read(params)
            response = ua.HistoryReadResponse()
            response.Results = results
            # _logger.info("sending history read response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.RegisterNodesRequest_Encoding_DefaultBinary):
            _logger.info("register nodes request (%s)", user)
            params = struct_from_binary(ua.RegisterNodesParameters, body)
            _logger.info("Node registration not implemented")
            response = ua.RegisterNodesResponse()
            response.Parameters.RegisteredNodeIds = params.NodesToRegister
            # _logger.info("sending register nodes response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.UnregisterNodesRequest_Encoding_DefaultBinary):
            _logger.info("unregister nodes request (%s)", user)
            params = struct_from_binary(ua.UnregisterNodesParameters, body)
            response = ua.UnregisterNodesResponse()
            # _logger.info("sending unregister nodes response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.PublishRequest_Encoding_DefaultBinary):
            params = struct_from_binary(ua.PublishParameters, body)
            subscriptions, results = session.services.publish(params.SubscriptionAcknowledgements)
            data = PublishRequestData(requesthdr=requesthdr, seqhdr=seqhdr, results=results, channel=self)
            await session.enqueue_publish(data, subscriptions)

        elif typeid == ua.NodeId(ua.ObjectIds.RepublishRequest_Encoding_DefaultBinary):
            _logger.info("re-publish request (%s)", user)
            params = struct_from_binary(ua.RepublishParameters, body)
            msg = session.services.republish(params)
            response = ua.RepublishResponse()
            response.NotificationMessage = msg
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.TransferSubscriptionsRequest_Encoding_DefaultBinary):
            _logger.info("transfer subscriptions request (%s)", user)
            params = struct_from_binary(ua.TransferSubscriptionsParameters, body)
            results = await session.services.transfer_subscriptions(params)
            response = ua.TransferSubscriptionsResponse()
            response.Parameters.Results = results
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.CallRequest_Encoding_DefaultBinary):
            _logger.info("call request (%s)", user)
            params = struct_from_binary(ua.CallParameters, body)
            results = await session.services.call(params.MethodsToCall)
            response = ua.CallResponse()
            response.Results = results
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.SetMonitoringModeRequest_Encoding_DefaultBinary):
            _logger.info("set monitoring mode request (%s)", user)
            params = struct_from_binary(ua.SetMonitoringModeParameters, body)
            results = await session.services.set_monitoring_mode(params)
            response = ua.SetMonitoringModeResponse()
            response.Parameters.Results = results
            _logger.info("sending set monitoring mode response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        elif typeid == ua.NodeId(ua.ObjectIds.SetPublishingModeRequest_Encoding_DefaultBinary):
            _logger.info("set publishing mode request (%s)", user)
            params = struct_from_binary(ua.SetPublishingModeParameters, body)
            results = await session.services.set_publishing_mode(params)
            response = ua.SetPublishingModeResponse()
            response.Parameters.Results = results
            _logger.info("sending set publishing mode response")
            self.send_response(requesthdr.RequestHandle, seqhdr, response)

        else:
            _logger.warning("Unknown message received %s (%s)", typeid, user)
            raise ServiceError(ua.StatusCodes.BadServiceUnsupported)

    async def close(self):
        _logger.info("Cleanup client connection: %s", self.name)
        await self.iserver.session_manager.on_channel_closed(self)

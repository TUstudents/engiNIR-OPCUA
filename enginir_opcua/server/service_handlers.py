"""The service entries of the server: one small handler per request type."""

from __future__ import annotations

from typing import Any

from enginir_opcua import ua

from ..common.utils import ServiceError
from ..ua.ua_binary import Primitives
from .identity import authorize_register_server
from .internal_session import PublishRequestData
from .service_dispatch import OperationBound, Permission, Requires, ServiceContext, ServiceEntry, entry


async def get_endpoints(ctx: ServiceContext, params: ua.GetEndpointsParameters) -> ua.GetEndpointsResponse:
    response = ua.GetEndpointsResponse()
    response.Endpoints = await ctx.iserver.get_endpoints(params, sockname=ctx.channel.sockname)
    return response


async def find_servers(ctx: ServiceContext, params: ua.FindServersParameters) -> ua.FindServersResponse:
    response = ua.FindServersResponse()
    response.Servers = ctx.iserver.find_servers(params, sockname=ctx.channel.sockname)
    return response


async def register_server(ctx: ServiceContext, server: ua.RegisteredServer) -> ua.RegisterServerResponse:
    if not ctx.iserver.accept_server_registrations:
        raise ServiceError(ua.StatusCodes.BadServiceUnsupported)
    authorize_register_server(ctx.channel.security, server)
    ctx.iserver.register_server(server)
    return ua.RegisterServerResponse()


async def register_server2(ctx: ServiceContext, params: ua.RegisterServer2Parameters) -> ua.RegisterServer2Response:
    if not ctx.iserver.accept_server_registrations:
        raise ServiceError(ua.StatusCodes.BadServiceUnsupported)
    authorize_register_server(ctx.channel.security, params.Server)
    ctx.iserver.register_server2(params)
    return ua.RegisterServer2Response()


async def create_session(ctx: ServiceContext, params: ua.CreateSessionParameters) -> ua.CreateSessionResponse:
    response = ua.CreateSessionResponse()
    response.Parameters = await ctx.iserver.session_manager.create_session(ctx.channel, params, ctx.channel.sockname)
    return response


async def activate_session(ctx: ServiceContext, params: ua.ActivateSessionParameters) -> ua.ActivateSessionResponse:
    response = ua.ActivateSessionResponse()
    response.Parameters = await ctx.iserver.session_manager.activate_session(
        ctx.channel, ctx.header.AuthenticationToken, params
    )
    return response


async def close_session(ctx: ServiceContext, delete_subscriptions: bool) -> ua.CloseSessionResponse:
    await ctx.iserver.session_manager.close_session(ctx.channel, ctx.header.AuthenticationToken, delete_subscriptions)
    return ua.CloseSessionResponse()


async def cancel(ctx: ServiceContext, params: ua.CancelParameters) -> ua.CancelResponse:
    response = ua.CancelResponse()
    response.Parameters.CancelCount = ctx.active_session.cancel_publish_requests(params.RequestHandle)
    return response


async def read(ctx: ServiceContext, params: ua.ReadParameters) -> ua.ReadResponse:
    response = ua.ReadResponse()
    response.Results = await ctx.active_session.services.read(params)
    return response


async def write(ctx: ServiceContext, params: ua.WriteParameters) -> ua.WriteResponse:
    response = ua.WriteResponse()
    response.Results = await ctx.active_session.services.write(params)
    return response


async def history_read(ctx: ServiceContext, params: ua.HistoryReadParameters) -> ua.HistoryReadResponse:
    response = ua.HistoryReadResponse()
    response.Results = await ctx.active_session.services.history_read(params)
    return response


async def browse(ctx: ServiceContext, params: ua.BrowseParameters) -> ua.BrowseResponse:
    response = ua.BrowseResponse()
    response.Results = await ctx.active_session.services.browse(params)
    return response


async def translate_browse_paths(
    ctx: ServiceContext, params: ua.TranslateBrowsePathsToNodeIdsParameters
) -> ua.TranslateBrowsePathsToNodeIdsResponse:
    response = ua.TranslateBrowsePathsToNodeIdsResponse()
    response.Results = await ctx.active_session.services.translate_browsepaths_to_nodeids(params.BrowsePaths)
    return response


async def register_nodes(ctx: ServiceContext, params: ua.RegisterNodesParameters) -> ua.RegisterNodesResponse:
    response = ua.RegisterNodesResponse()
    response.Parameters.RegisteredNodeIds = await ctx.active_session.services.register_nodes(params.NodesToRegister)
    return response


async def unregister_nodes(ctx: ServiceContext, params: ua.UnregisterNodesParameters) -> ua.UnregisterNodesResponse:
    await ctx.active_session.services.unregister_nodes(params.NodesToUnregister)
    return ua.UnregisterNodesResponse()


async def call(ctx: ServiceContext, params: ua.CallParameters) -> ua.CallResponse:
    response = ua.CallResponse()
    response.Results = await ctx.active_session.services.call(params.MethodsToCall)
    return response


async def add_nodes(ctx: ServiceContext, params: ua.AddNodesParameters) -> ua.AddNodesResponse:
    response = ua.AddNodesResponse()
    response.Results = await ctx.active_session.services.add_nodes(params.NodesToAdd)
    return response


async def delete_nodes(ctx: ServiceContext, params: ua.DeleteNodesParameters) -> ua.DeleteNodesResponse:
    response = ua.DeleteNodesResponse()
    response.Results = await ctx.active_session.services.delete_nodes(params)
    return response


async def add_references(ctx: ServiceContext, params: ua.AddReferencesParameters) -> ua.AddReferencesResponse:
    response = ua.AddReferencesResponse()
    response.Results = await ctx.active_session.services.add_references(params.ReferencesToAdd)
    return response


async def delete_references(ctx: ServiceContext, params: ua.DeleteReferencesParameters) -> ua.DeleteReferencesResponse:
    response = ua.DeleteReferencesResponse()
    response.Parameters.Results = await ctx.active_session.services.delete_references(params.ReferencesToDelete)
    return response


async def create_subscription(
    ctx: ServiceContext, params: ua.CreateSubscriptionParameters
) -> ua.CreateSubscriptionResponse:
    session = ctx.active_session
    response = ua.CreateSubscriptionResponse()
    response.Parameters = await session.services.create_subscription(
        params, session.forward_publish_response, request_callback=session.get_publish_request
    )
    return response


async def modify_subscription(
    ctx: ServiceContext, params: ua.ModifySubscriptionParameters
) -> ua.ModifySubscriptionResponse:
    response = ua.ModifySubscriptionResponse()
    response.Parameters = ctx.active_session.services.modify_subscription(params)
    return response


async def set_publishing_mode(
    ctx: ServiceContext, params: ua.SetPublishingModeParameters
) -> ua.SetPublishingModeResponse:
    response = ua.SetPublishingModeResponse()
    response.Parameters.Results = await ctx.active_session.services.set_publishing_mode(params)
    return response


async def delete_subscriptions(
    ctx: ServiceContext, params: ua.DeleteSubscriptionsParameters
) -> ua.DeleteSubscriptionsResponse:
    session = ctx.active_session
    response = ua.DeleteSubscriptionsResponse()
    response.Results = await session.services.delete_subscriptions(params.SubscriptionIds)
    if not session.subscription_ids():
        session.flush_publish_queue(ua.StatusCodes.BadNoSubscription)
    return response


async def republish(ctx: ServiceContext, params: ua.RepublishParameters) -> ua.RepublishResponse:
    response = ua.RepublishResponse()
    response.NotificationMessage = ctx.active_session.services.republish(params)
    return response


async def transfer_subscriptions(
    ctx: ServiceContext, params: ua.TransferSubscriptionsParameters
) -> ua.TransferSubscriptionsResponse:
    response = ua.TransferSubscriptionsResponse()
    response.Parameters.Results = await ctx.active_session.services.transfer_subscriptions(params)
    return response


async def publish(ctx: ServiceContext, params: ua.PublishParameters) -> None:
    session = ctx.active_session
    subscription_count, results = session.services.publish(params.SubscriptionAcknowledgements)
    request = PublishRequestData(requesthdr=ctx.header, seqhdr=ctx.seqhdr, results=results, channel=ctx.channel)
    await session.enqueue_publish(request, subscription_count)


async def create_monitored_items(
    ctx: ServiceContext, params: ua.CreateMonitoredItemsParameters
) -> ua.CreateMonitoredItemsResponse:
    response = ua.CreateMonitoredItemsResponse()
    response.Results = await ctx.active_session.services.create_monitored_items(params)
    return response


async def modify_monitored_items(
    ctx: ServiceContext, params: ua.ModifyMonitoredItemsParameters
) -> ua.ModifyMonitoredItemsResponse:
    response = ua.ModifyMonitoredItemsResponse()
    response.Results = await ctx.active_session.services.modify_monitored_items(params)
    return response


async def set_monitoring_mode(
    ctx: ServiceContext, params: ua.SetMonitoringModeParameters
) -> ua.SetMonitoringModeResponse:
    response = ua.SetMonitoringModeResponse()
    response.Parameters.Results = await ctx.active_session.services.set_monitoring_mode(params)
    return response


async def set_triggering(ctx: ServiceContext, params: ua.SetTriggeringParameters) -> ua.SetTriggeringResponse:
    response = ua.SetTriggeringResponse()
    response.Parameters = await ctx.active_session.services.set_triggering(params)
    return response


async def delete_monitored_items(
    ctx: ServiceContext, params: ua.DeleteMonitoredItemsParameters
) -> ua.DeleteMonitoredItemsResponse:
    response = ua.DeleteMonitoredItemsResponse()
    response.Results = await ctx.active_session.services.delete_monitored_items(params)
    return response


def build_service_table() -> list[ServiceEntry]:
    sessionless: dict[str, Any] = {"requires": Requires.NoSession, "permission": Permission.Unchecked}
    return [
        entry("GetEndpoints", ua.GetEndpointsParameters, get_endpoints, **sessionless),
        entry("FindServers", ua.FindServersParameters, find_servers, **sessionless),
        entry("RegisterServer", ua.RegisteredServer, register_server, **sessionless),
        entry("RegisterServer2", ua.RegisterServer2Parameters, register_server2, **sessionless),
        entry("CreateSession", ua.CreateSessionParameters, create_session, **sessionless),
        entry("ActivateSession", ua.ActivateSessionParameters, activate_session, **sessionless),
        entry("CloseSession", Primitives.Boolean.unpack, close_session, **sessionless),
        entry("Cancel", ua.CancelParameters, cancel, permission=Permission.Anonymous),
        entry(
            "Read",
            ua.ReadParameters,
            read,
            operations=OperationBound("NodesToRead", "max_nodes_per_read"),
            permission=Permission.Anonymous,
        ),
        entry(
            "Write",
            ua.WriteParameters,
            write,
            operations=OperationBound("NodesToWrite", "max_nodes_per_write"),
            permission=Permission.User,
        ),
        entry(
            "HistoryRead",
            ua.HistoryReadParameters,
            history_read,
            operations=OperationBound(
                "NodesToRead", "max_nodes_per_history_read_data", "max_nodes_per_history_read_events"
            ),
            permission=Permission.Anonymous,
        ),
        entry(
            "Browse",
            ua.BrowseParameters,
            browse,
            operations=OperationBound("NodesToBrowse", "max_nodes_per_browse"),
            permission=Permission.Anonymous,
        ),
        entry(
            "TranslateBrowsePathsToNodeIds",
            ua.TranslateBrowsePathsToNodeIdsParameters,
            translate_browse_paths,
            operations=OperationBound("BrowsePaths", "max_nodes_per_translate_browse_paths"),
            permission=Permission.Anonymous,
        ),
        entry(
            "RegisterNodes",
            ua.RegisterNodesParameters,
            register_nodes,
            operations=OperationBound("NodesToRegister", "max_nodes_per_register_nodes"),
            permission=Permission.Anonymous,
        ),
        entry(
            "UnregisterNodes",
            ua.UnregisterNodesParameters,
            unregister_nodes,
            operations=OperationBound("NodesToUnregister", "max_nodes_per_register_nodes"),
            permission=Permission.Anonymous,
        ),
        entry(
            "Call",
            ua.CallParameters,
            call,
            operations=OperationBound("MethodsToCall", "max_nodes_per_method_call"),
            permission=Permission.User,
        ),
        entry(
            "AddNodes",
            ua.AddNodesParameters,
            add_nodes,
            operations=OperationBound("NodesToAdd", "max_nodes_per_node_management"),
            permission=Permission.Admin,
        ),
        entry(
            "DeleteNodes",
            ua.DeleteNodesParameters,
            delete_nodes,
            operations=OperationBound("NodesToDelete", "max_nodes_per_node_management"),
            permission=Permission.Admin,
        ),
        entry(
            "AddReferences",
            ua.AddReferencesParameters,
            add_references,
            operations=OperationBound("ReferencesToAdd", "max_nodes_per_node_management"),
            permission=Permission.Admin,
        ),
        entry(
            "DeleteReferences",
            ua.DeleteReferencesParameters,
            delete_references,
            operations=OperationBound("ReferencesToDelete", "max_nodes_per_node_management"),
            permission=Permission.Admin,
        ),
        entry(
            "CreateSubscription", ua.CreateSubscriptionParameters, create_subscription, permission=Permission.Anonymous
        ),
        entry(
            "ModifySubscription", ua.ModifySubscriptionParameters, modify_subscription, permission=Permission.Anonymous
        ),
        entry(
            "SetPublishingMode",
            ua.SetPublishingModeParameters,
            set_publishing_mode,
            operations=OperationBound("SubscriptionIds", None),
            permission=Permission.Anonymous,
        ),
        entry(
            "DeleteSubscriptions",
            ua.DeleteSubscriptionsParameters,
            delete_subscriptions,
            operations=OperationBound("SubscriptionIds", None),
            permission=Permission.Anonymous,
        ),
        entry("Republish", ua.RepublishParameters, republish, permission=Permission.Anonymous),
        entry(
            "TransferSubscriptions",
            ua.TransferSubscriptionsParameters,
            transfer_subscriptions,
            operations=OperationBound("SubscriptionIds", None),
            permission=Permission.Anonymous,
        ),
        entry("Publish", ua.PublishParameters, publish, permission=Permission.Anonymous),
        entry(
            "CreateMonitoredItems",
            ua.CreateMonitoredItemsParameters,
            create_monitored_items,
            operations=OperationBound("ItemsToCreate", "max_monitored_items_per_call"),
            permission=Permission.Anonymous,
        ),
        entry(
            "ModifyMonitoredItems",
            ua.ModifyMonitoredItemsParameters,
            modify_monitored_items,
            operations=OperationBound("ItemsToModify", "max_monitored_items_per_call"),
            permission=Permission.Anonymous,
        ),
        entry(
            "SetMonitoringMode",
            ua.SetMonitoringModeParameters,
            set_monitoring_mode,
            operations=OperationBound("MonitoredItemIds", "max_monitored_items_per_call"),
            permission=Permission.Anonymous,
        ),
        entry("SetTriggering", ua.SetTriggeringParameters, set_triggering, permission=Permission.Anonymous),
        entry(
            "DeleteMonitoredItems",
            ua.DeleteMonitoredItemsParameters,
            delete_monitored_items,
            operations=OperationBound("MonitoredItemIds", "max_monitored_items_per_call"),
            permission=Permission.Anonymous,
        ),
    ]

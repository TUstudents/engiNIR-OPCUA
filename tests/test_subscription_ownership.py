import pytest

from enginir_opcua import ua

from .harness import TwoSessions


async def test_srv4_bob_cannot_delete_alice_subscription(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.1.2: a Subscription is only reachable from the Session it is assigned to."""
    sub = await two_sessions.alice.create_subscription(100, None)
    assert sub.subscription_id is not None
    results = await two_sessions.bob.delete_subscriptions([sub.subscription_id])
    assert results[0].value == ua.StatusCodes.BadSubscriptionIdInvalid
    assert sub.subscription_id in two_sessions.server.iserver.subscription_service.subscriptions
    results = await two_sessions.alice.delete_subscriptions([sub.subscription_id])
    assert results[0].is_good()


async def test_srv4_bob_cannot_add_monitored_items_to_alice_subscription(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.1.2: a Subscription is only reachable from the Session it is assigned to."""
    sub = await two_sessions.alice.create_subscription(100, None)
    params = ua.CreateMonitoredItemsParameters()
    params.SubscriptionId = sub.subscription_id
    params.TimestampsToReturn = ua.TimestampsToReturn.Both
    item = ua.MonitoredItemCreateRequest()
    item.ItemToMonitor.NodeId = ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime)
    item.ItemToMonitor.AttributeId = ua.AttributeIds.Value
    item.MonitoringMode = ua.MonitoringMode.Reporting
    item.RequestedParameters.ClientHandle = 1
    params.ItemsToCreate = [item]
    with pytest.raises(ua.uaerrors.BadSubscriptionIdInvalid):
        await two_sessions.bob.uaclient.create_monitored_items(params)


async def test_srv4_bob_cannot_change_publishing_mode_of_alice_subscription(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.1.2: a Subscription is only reachable from the Session it is assigned to."""
    sub = await two_sessions.alice.create_subscription(100, None)
    params = ua.SetPublishingModeParameters(PublishingEnabled=False, SubscriptionIds=[sub.subscription_id])
    results = await two_sessions.bob.uaclient.set_publishing_mode(params)
    assert results[0].value == ua.StatusCodes.BadSubscriptionIdInvalid

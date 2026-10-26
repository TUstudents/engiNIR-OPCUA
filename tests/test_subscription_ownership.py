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


async def test_srv4_per_session_subscription_limit(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.2.3: CreateSubscription fails with Bad_TooManySubscriptions at the limit of the session."""
    two_sessions.server.iserver.max_subscriptions_per_session = 2
    first = await two_sessions.alice.create_subscription(100, None)
    await two_sessions.alice.create_subscription(100, None)
    with pytest.raises(ua.uaerrors.BadTooManySubscriptions):
        await two_sessions.alice.create_subscription(100, None)
    other = await two_sessions.bob.create_subscription(100, None)
    assert other.subscription_id is not None
    await first.delete()
    again = await two_sessions.alice.create_subscription(100, None)
    assert again.subscription_id is not None

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock

import pytest

from enginir_opcua import ua
from enginir_opcua.server.internal_server import InternalServer

SESSION = ua.NodeId(1, 1)


@pytest.fixture
async def iserver() -> AsyncIterator[InternalServer]:
    server = InternalServer()
    yield server
    for sub in list(server.subscription_service.subscriptions.values()):
        await sub.stop()
    server.subscription_service.subscriptions.clear()


def create_params(interval: float = 100, lifetime: int = 30, keepalive: int = 10) -> ua.CreateSubscriptionParameters:
    return ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=interval,
        RequestedLifetimeCount=lifetime,
        RequestedMaxKeepAliveCount=keepalive,
        MaxNotificationsPerPublish=0,
        PublishingEnabled=True,
        Priority=0,
    )


async def create(iserver: InternalServer, params: ua.CreateSubscriptionParameters) -> ua.CreateSubscriptionResult:
    return await iserver.subscription_service.create_subscription(
        params, AsyncMock(), SESSION, request_callback=lambda _id: None
    )


@pytest.mark.parametrize("requested", [0.0, -5.0, float("nan"), 1.0])
async def test_srv11_publishing_interval_below_the_minimum_is_revised_up(
    iserver: InternalServer, requested: float
) -> None:
    """Part 4, 5.14.2.2: the server revises the interval to the fastest one it supports."""
    result = await create(iserver, create_params(interval=requested))
    assert result.RevisedPublishingInterval == iserver.min_publishing_interval_ms


async def test_srv11_publishing_interval_is_clamped_to_the_maximum(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the server revises the interval to the slowest one it supports."""
    result = await create(iserver, create_params(interval=1e9, lifetime=3, keepalive=1))
    assert result.RevisedPublishingInterval == iserver.max_publishing_interval_ms


async def test_srv33_keepalive_zero_becomes_one(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: a keep-alive count of 0 is revised to the smallest supported count."""
    result = await create(iserver, create_params(keepalive=0))
    assert result.RevisedMaxKeepAliveCount == 1


async def test_srv33_lifetime_is_at_least_three_times_keepalive(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the lifetime count is revised to at least three times the keep-alive count."""
    result = await create(iserver, create_params(lifetime=1, keepalive=5))
    assert result.RevisedLifetimeCount == 15


async def test_srv33_interval_times_lifetime_is_capped(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the server may lower the lifetime so an abandoned subscription does not live for days."""
    iserver.max_subscription_lifetime_ms = 60_000
    result = await create(iserver, create_params(interval=1000, lifetime=1000, keepalive=2))
    assert result.RevisedLifetimeCount == 60
    assert result.RevisedLifetimeCount * result.RevisedPublishingInterval <= 60_000


async def test_srv33_lifetime_cap_lowers_keepalive_when_three_times_it_does_not_fit(iserver: InternalServer) -> None:
    """Part 4, 5.14.2.2: the lifetime count stays at least three times the keep-alive count."""
    iserver.max_subscription_lifetime_ms = 60_000
    result = await create(iserver, create_params(interval=10_000, lifetime=1000, keepalive=100))
    assert result.RevisedLifetimeCount >= 3 * result.RevisedMaxKeepAliveCount
    assert result.RevisedLifetimeCount * result.RevisedPublishingInterval <= 60_000


async def test_srv11_modify_applies_revised_values(iserver: InternalServer) -> None:
    """Part 4, 5.14.3.2: ModifySubscription revises and applies the new parameters."""
    created = await create(iserver, create_params(interval=100, lifetime=30, keepalive=10))
    modify = ua.ModifySubscriptionParameters(
        SubscriptionId=created.SubscriptionId,
        RequestedPublishingInterval=0,
        RequestedLifetimeCount=1,
        RequestedMaxKeepAliveCount=0,
        MaxNotificationsPerPublish=7,
        Priority=9,
    )
    result = iserver.subscription_service.modify_subscription(modify, SESSION)
    assert result.RevisedPublishingInterval == iserver.min_publishing_interval_ms
    assert result.RevisedMaxKeepAliveCount == 1
    assert result.RevisedLifetimeCount == 3
    sub = iserver.subscription_service.subscriptions[created.SubscriptionId]
    assert sub.data.RevisedPublishingInterval == result.RevisedPublishingInterval
    assert sub.max_notifications_per_publish == 7
    assert sub.priority == 9

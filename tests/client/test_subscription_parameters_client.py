"""Requested and revised parameters of the client Subscription."""

from __future__ import annotations

import time

import pytest

from enginir_opcua import ua
from enginir_opcua.common.subscription import Subscription, subscription_parameters
from tests.subscription_rig import FakeSession


@pytest.mark.parametrize("period", [50, 100, 1000])
def test_cli10_counts_follow_the_3x_rule(period: int) -> None:
    """Part 4, 5.14.2.2: the lifetime is at least three times the keep-alive; keep-alive about 10 s."""
    params = subscription_parameters(period)
    assert params.RequestedLifetimeCount >= 3 * params.RequestedMaxKeepAliveCount
    assert params.RequestedMaxKeepAliveCount * period == pytest.approx(10_000, abs=period)
    assert params.RequestedLifetimeCount * period >= 300_000
    assert params.MaxNotificationsPerPublish == 0


def test_cli10_keep_alive_is_limited_to_a_quarter_of_the_session_timeout() -> None:
    """Part 4, 5.14.2.2: a keep-alive must arrive well within the Session timeout."""
    params = subscription_parameters(100, session_timeout=20_000)
    assert params.RequestedMaxKeepAliveCount * 100 <= 5_000


def test_cli10_period_zero_is_sent_as_zero() -> None:
    """Part 4, 5.14.2.2: an interval of 0 asks for the fastest one the server has."""
    params = subscription_parameters(0)
    assert params.RequestedPublishingInterval == 0
    assert params.RequestedMaxKeepAliveCount >= 1
    assert params.RequestedLifetimeCount >= 3 * params.RequestedMaxKeepAliveCount


@pytest.mark.parametrize("keep_alive,lifetime", [(10, 29), (5, 1), (1000, 2999)])
def test_cli10_explicit_counts_that_break_the_3x_rule_are_refused(keep_alive: int, lifetime: int) -> None:
    """Part 4, 5.14.2.2: the client refuses a lifetime below three keep-alives before sending anything."""
    with pytest.raises(ValueError):
        subscription_parameters(100, keep_alive_count=keep_alive, lifetime_count=lifetime)


def test_cli10_explicit_counts_are_kept() -> None:
    params = subscription_parameters(100, keep_alive_count=7, lifetime_count=30)
    assert (params.RequestedMaxKeepAliveCount, params.RequestedLifetimeCount) == (7, 30)


async def test_cli10_real_server_keep_alive_cadence(opc) -> None:
    """Part 4, 5.14.1.1: with the derived counts the revised keep-alive interval is about 10 s."""
    if opc.opc is opc.server:
        pytest.skip("same check for the in-process server is not needed")
    session = opc.opc.uaclient.session
    sub = Subscription(session, subscription_parameters(100))
    await sub.init()
    assert sub.revised is not None
    assert sub.revised.publishing_interval * sub.revised.max_keep_alive_count == pytest.approx(10_000, abs=200)
    await sub.delete()


async def test_com32_revised_values_are_stored() -> None:
    """Part 4, 5.14.2.2: the Subscription keeps what the server revised, next to what it asked for."""
    session = FakeSession()
    session.revise = lambda p: ua.CreateSubscriptionResult(
        RevisedPublishingInterval=500.0, RevisedLifetimeCount=900, RevisedMaxKeepAliveCount=30
    )
    sub = Subscription(session, subscription_parameters(100))  # type: ignore[arg-type]
    await sub.init()
    assert sub.revised is not None
    assert (sub.revised.publishing_interval, sub.revised.lifetime_count, sub.revised.max_keep_alive_count) == (
        500.0,
        900,
        30,
    )
    assert sub.parameters.RequestedPublishingInterval == 100


async def test_cli10_one_correction_only() -> None:
    """Part 4, 5.14.2.2: a revised keep-alive above the limit is corrected with one Modify, never a loop."""
    session = FakeSession()
    session.revise = lambda p: ua.CreateSubscriptionResult(
        RevisedPublishingInterval=10_000.0, RevisedLifetimeCount=600, RevisedMaxKeepAliveCount=100
    )
    sub = Subscription(session, subscription_parameters(100))  # type: ignore[arg-type]
    await sub.init()
    assert len(session.modified) == 1
    modified = session.modified[0]
    assert modified.RequestedPublishingInterval == 10_000.0
    assert modified.RequestedMaxKeepAliveCount * 10_000 <= 60_000
    assert modified.RequestedLifetimeCount >= 3 * modified.RequestedMaxKeepAliveCount
    assert sub.revised is not None
    assert sub.revised.max_keep_alive_count == modified.RequestedMaxKeepAliveCount


async def test_com32_update_stores_the_result_not_the_request() -> None:
    """Part 4, 5.13.3: the stored values are the revised ones."""
    session = FakeSession()
    sub = Subscription(session, subscription_parameters(100))  # type: ignore[arg-type]
    await sub.init()
    params = ua.ModifySubscriptionParameters(
        SubscriptionId=sub.subscription_id, RequestedPublishingInterval=250.0, RequestedLifetimeCount=5,
        RequestedMaxKeepAliveCount=4,
    )  # fmt: skip
    await sub.update(params)
    assert session.modified[0].RequestedLifetimeCount == 12
    assert sub.revised is not None
    assert sub.revised.lifetime_count == 12
    assert sub.parameters.RequestedLifetimeCount == 12


async def test_com72_never_answered_subscription_becomes_stale() -> None:
    """Part 4, 5.14.1.1: no message at all within the keep-alive time is a dead Subscription."""
    session = FakeSession()
    sub = Subscription(session, subscription_parameters(100, keep_alive_count=10, lifetime_count=30))  # type: ignore[arg-type]
    await sub.init()
    assert sub.last_publish_at is None
    assert not sub.is_stale(1.5)
    sub._created_at = time.monotonic() - 100
    assert sub.is_stale(1.5)


async def test_com32_stale_uses_revised_values() -> None:
    """Part 4, 5.14.2.2: a server that raises the interval does not make the Subscription stale."""
    session = FakeSession()
    session.revise = lambda p: ua.CreateSubscriptionResult(
        RevisedPublishingInterval=10_000.0, RevisedLifetimeCount=300, RevisedMaxKeepAliveCount=10
    )
    sub = Subscription(session, subscription_parameters(100, keep_alive_count=10, lifetime_count=30))  # type: ignore[arg-type]
    await sub.init()
    sub.last_publish_at = time.monotonic() - 5
    assert not sub.is_stale(1.5)
    sub.last_publish_at = time.monotonic() - 200
    assert sub.is_stale(1.5)

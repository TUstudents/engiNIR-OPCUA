"""The value logic of the limit alarms (OPC 10000-9, 5.8.18 to 5.8.23). Pure functions, no address space."""

from __future__ import annotations

from collections.abc import Mapping

HIGH_SIDE = ("HighHigh", "High")
LOW_SIDE = ("LowLow", "Low")
TIERS = ("HighHigh", "High", "Low", "LowLow")


def validate_limits(
    limits: Mapping[str, float], deadbands: Mapping[str, float], *, deviation: bool = False, exclusive: bool = True
) -> None:
    unknown = (set(limits) | set(deadbands)) - set(TIERS)
    if unknown:
        raise ValueError(f"Unknown limit names: {sorted(unknown)}")
    if not limits:
        raise ValueError("A limit alarm needs at least one limit")
    if not exclusive and "High" not in limits and "Low" not in limits:
        raise ValueError("A non-exclusive limit alarm needs HighLimit or LowLimit")
    if any(value < 0 for value in deadbands.values()):
        raise ValueError("Deadbands cannot be negative")
    high, high_high, low, low_low = (limits.get(name) for name in ("High", "HighHigh", "Low", "LowLow"))
    deadband = {name: deadbands.get(name, 0.0) for name in TIERS}
    if high_high is not None and high is not None and not high_high - deadband["HighHigh"] > high:
        raise ValueError("HighHighLimit - HighHighDeadband must be above HighLimit")
    if high is not None and low is not None and not high - deadband["High"] > low:
        raise ValueError("HighLimit - HighDeadband must be above LowLimit")
    if high is not None and low is not None and not low + deadband["Low"] < high:
        raise ValueError("LowLimit + LowDeadband must be below HighLimit")
    if low is not None and low_low is not None and not low_low + deadband["LowLow"] < low:
        raise ValueError("LowLowLimit + LowLowDeadband must be below LowLimit")
    if high_high is not None and high is None and low is not None and not high_high - deadband["HighHigh"] > low:
        raise ValueError("HighHighLimit - HighHighDeadband must be above LowLimit")
    if low_low is not None and low is None and high is not None and not low_low + deadband["LowLow"] < high:
        raise ValueError("LowLowLimit + LowLowDeadband must be below HighLimit")
    if deviation:
        if any(limits[name] == 0 for name in limits):
            raise ValueError("Deviation limits cannot be zero")
        if any(limits[name] < 0 for name in HIGH_SIDE if name in limits):
            raise ValueError("High deviation limits must be positive")
        if any(limits[name] > 0 for name in LOW_SIDE if name in limits):
            raise ValueError("Low deviation limits must be negative")


def tier_holds(tier: str, value: float, limits: Mapping[str, float], deadbands: Mapping[str, float], was: bool) -> bool:
    limit = limits.get(tier)
    if limit is None:
        return False
    band = deadbands.get(tier, 0.0) if was else 0.0
    if tier in HIGH_SIDE:
        return value > limit - band if was else value > limit
    return value < limit + band if was else value < limit


def exclusive_tier(
    value: float, limits: Mapping[str, float], deadbands: Mapping[str, float], current: str | None
) -> str | None:
    for side in (HIGH_SIDE, LOW_SIDE):
        for tier in side:
            if tier_holds(tier, value, limits, deadbands, current == tier):
                return tier
    return None


def non_exclusive_states(
    value: float, limits: Mapping[str, float], deadbands: Mapping[str, float], current: Mapping[str, bool]
) -> dict[str, bool]:
    return {
        tier: tier_holds(tier, value, limits, deadbands, current.get(tier, False)) for tier in TIERS if tier in limits
    }


def tier_severity(active_tiers: list[str], severities: Mapping[str, int], default: int) -> int:
    for tier in ("HighHigh", "LowLow", "High", "Low"):
        if tier in active_tiers and tier in severities:
            return severities[tier]
    return default

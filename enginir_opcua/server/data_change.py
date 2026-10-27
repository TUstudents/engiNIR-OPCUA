from __future__ import annotations

import math
from typing import Any

from enginir_opcua import ua

NUMERIC_TYPES = frozenset(
    {
        ua.VariantType.SByte,
        ua.VariantType.Byte,
        ua.VariantType.Int16,
        ua.VariantType.UInt16,
        ua.VariantType.Int32,
        ua.VariantType.UInt32,
        ua.VariantType.Int64,
        ua.VariantType.UInt64,
        ua.VariantType.Float,
        ua.VariantType.Double,
    }
)


def _status_value(code: ua.StatusCode | None) -> int:
    return 0 if code is None else code.value


def _same_scalar(first: Any, second: Any) -> bool:
    if isinstance(first, float) and isinstance(second, float) and math.isnan(first) and math.isnan(second):
        return True
    return bool(first == second)


def values_equal(first: ua.Variant | None, second: ua.Variant | None) -> bool:
    if first is None or second is None:
        return first is None and second is None
    if first.VariantType != second.VariantType or first.Dimensions != second.Dimensions:
        return False
    if isinstance(first.Value, list) and isinstance(second.Value, list):
        return len(first.Value) == len(second.Value) and all(
            _same_scalar(a, b) for a, b in zip(first.Value, second.Value)
        )
    return _same_scalar(first.Value, second.Value)


def is_numeric(value: ua.Variant | None) -> bool:
    return value is not None and value.VariantType in NUMERIC_TYPES


def _differs_by_more(first: Any, second: Any, band: float) -> bool:
    if isinstance(first, float) and isinstance(second, float) and math.isnan(first) != math.isnan(second):
        return True
    if isinstance(first, float) and isinstance(second, float) and math.isnan(first):
        return False
    return abs(second - first) > band


def exceeds_deadband(last: ua.Variant, sample: ua.Variant, band: float) -> bool:
    if last.VariantType != sample.VariantType or last.Dimensions != sample.Dimensions:
        return True
    if isinstance(last.Value, list) and isinstance(sample.Value, list):
        if len(last.Value) != len(sample.Value):
            return True
        return any(_differs_by_more(a, b, band) for a, b in zip(last.Value, sample.Value))
    if isinstance(last.Value, list) or isinstance(sample.Value, list):
        return True
    return _differs_by_more(last.Value, sample.Value, band)


def deadband_width(flt: ua.DataChangeFilter, eu_range: tuple[float, float] | None) -> float:
    if flt.DeadbandType == ua.DeadbandType.Percent:
        if eu_range is None:
            return 0.0
        return flt.DeadbandValue / 100.0 * (eu_range[1] - eu_range[0])
    return float(flt.DeadbandValue)


def data_change_passes(
    last: ua.DataValue | None,
    sample: ua.DataValue,
    flt: ua.DataChangeFilter | None,
    eu_range: tuple[float, float] | None,
) -> bool:
    if last is None:
        return True
    if _status_value(last.StatusCode) != _status_value(sample.StatusCode):
        return True
    trigger = ua.DataChangeTrigger.StatusValue if flt is None else flt.Trigger
    if trigger == ua.DataChangeTrigger.Status:
        return False
    if _value_changed(last.Value, sample.Value, flt, eu_range):
        return True
    return trigger == ua.DataChangeTrigger.StatusValueTimestamp and (
        last.SourceTimestamp != sample.SourceTimestamp or last.SourcePicoseconds != sample.SourcePicoseconds
    )


def _value_changed(
    last: ua.Variant | None,
    sample: ua.Variant | None,
    flt: ua.DataChangeFilter | None,
    eu_range: tuple[float, float] | None,
) -> bool:
    if values_equal(last, sample):
        return False
    if flt is None or flt.DeadbandType == ua.DeadbandType.None_ or last is None or sample is None:
        return True
    if not (is_numeric(last) and is_numeric(sample)):
        return True
    return exceeds_deadband(last, sample, deadband_width(flt, eu_range))

"""
High level method related functions
"""

from __future__ import annotations

import inspect
import logging
from functools import wraps
from typing import Any
from weakref import WeakKeyDictionary

import enginir_opcua
from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession
from enginir_opcua.common.ua_utils import INTEGER_RANGES, data_type_to_variant_type

_logger = logging.getLogger(__name__)

_input_arguments: WeakKeyDictionary[Any, dict[ua.NodeId, list[tuple[ua.VariantType, int]] | None]] = WeakKeyDictionary()

_FLOATS = (ua.VariantType.Float, ua.VariantType.Double)


async def call_method(
    parent: enginir_opcua.Node,
    methodid: ua.NodeId | ua.QualifiedName | str,
    *args: Any,
    timeout: float | None = None,
) -> Any:
    """
    Call an OPC-UA method. methodid is browse name of child method or the
    nodeid of method as a NodeId object
    arguments are variants or python object convertible to variants.
    which may be of different types
    returns a list of values or a single value depending on the output of the method
    : param: parent `Node`
    """
    result = await call_method_full(parent, methodid, *args, timeout=timeout)

    if len(result.OutputArguments) == 0:
        return None
    if len(result.OutputArguments) == 1:
        return result.OutputArguments[0]
    return result.OutputArguments


async def call_method_full(
    parent: enginir_opcua.Node,
    methodid: ua.NodeId | ua.QualifiedName | str,
    *args: Any,
    timeout: float | None = None,
) -> ua.CallMethodResult:
    """
    Call an OPC-UA method. methodid is browse name of child method or the
    nodeid of method as a NodeId object
    arguments are variants or python object convertible to variants.
    which may be of different types
    returns a CallMethodResult object with converted OutputArguments
    : param: parent `Node`
    """
    if isinstance(methodid, str | ua.uatypes.QualifiedName):
        methodid = (await parent.get_child(methodid)).nodeid
    elif hasattr(methodid, "nodeid"):
        methodid = methodid.nodeid

    arguments = await convert_arguments(parent.session, methodid, args)
    result = await _call_method(parent.session, parent.nodeid, methodid, arguments, timeout)
    if result.OutputArguments is None:
        result.OutputArguments = []
    result.OutputArguments = [var.Value for var in result.OutputArguments]
    return result


async def _call_method(
    session: AbstractSession,
    parentnodeid: ua.NodeId,
    methodid: ua.NodeId,
    arguments: list[ua.Variant],
    timeout: float | None = None,
) -> ua.CallMethodResult:
    """
    :param server: `UaClient` or `InternalSession`
    :param parentnodeid:
    :param methodid:
    :param arguments:
    :return:
    """
    request = ua.CallMethodRequest()
    request.ObjectId = parentnodeid
    request.MethodId = methodid
    request.InputArguments = arguments
    methodstocall = [request]
    results = await (session.call(methodstocall) if timeout is None else session.call(methodstocall, timeout=timeout))  # type: ignore[call-arg]
    res = results[0]
    if not res.StatusCode.is_good():
        error = ua.UaStatusCodeError(res.StatusCode.value)
        error.input_argument_results = res.InputArgumentResults  # type: ignore[attr-defined]
        raise error
    return res


def forget_input_arguments(session: Any) -> None:
    _input_arguments.pop(session, None)


async def _declared_inputs(session: AbstractSession, methodid: ua.NodeId) -> list[tuple[ua.VariantType, int]] | None:
    cache = _input_arguments.setdefault(session, {})
    if methodid in cache:
        return cache[methodid]
    declared: list[tuple[ua.VariantType, int]] | None
    try:
        method = enginir_opcua.Node(session, methodid)
        arguments = await (await method.get_child(ua.QualifiedName("InputArguments", 0))).read_value()
        declared = [
            (await data_type_to_variant_type(enginir_opcua.Node(session, argument.DataType)), argument.ValueRank)
            for argument in arguments or []
        ]
    except (ua.UaError, ConnectionError, TimeoutError):
        _logger.debug("The input arguments of %s are not readable; guessing the types", methodid, exc_info=True)
        return None
    cache[methodid] = declared
    return declared


async def convert_arguments(session: AbstractSession, methodid: ua.NodeId, args: tuple[Any, ...]) -> list[ua.Variant]:
    """Variants for the arguments of a call, typed by the InputArguments of the method."""
    declared = await _declared_inputs(session, methodid)
    if declared is None:
        return to_variant(*args)
    if len(args) > len(declared):
        raise ua.UaStatusCodeError(ua.StatusCodes.BadTooManyArguments)
    return [
        arg if isinstance(arg, ua.Variant) else _convert_argument(arg, variant_type, rank, index)
        for index, (arg, (variant_type, rank)) in enumerate(zip(args, declared))
    ]


def _convert_argument(value: Any, variant_type: ua.VariantType, rank: int, index: int) -> ua.Variant:
    is_array = rank >= 1
    if variant_type is ua.VariantType.Variant:
        return ua.Variant(value)
    if is_array and variant_type is ua.VariantType.Byte and isinstance(value, bytes | bytearray):
        return ua.Variant(bytes(value), ua.VariantType.ByteString)
    if is_array:
        if not isinstance(value, list | tuple):
            raise TypeError(f"Argument {index} must be a list for the declared array of {variant_type.name}")
        return ua.Variant([_convert_scalar(item, variant_type, index) for item in value], variant_type)
    if rank == ua.ValueRank.Scalar or not isinstance(value, list | tuple):
        return ua.Variant(_convert_scalar(value, variant_type, index), variant_type)
    return ua.Variant(list(value), variant_type)


def _convert_scalar(value: Any, variant_type: ua.VariantType, index: int) -> Any:
    if variant_type in INTEGER_RANGES:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise TypeError(f"Argument {index} must be an integer for {variant_type.name}, got {value!r}")
        if isinstance(value, float) and not value.is_integer():
            raise TypeError(f"Argument {index} has a fraction and cannot be {variant_type.name}: {value!r}")
        low, high = INTEGER_RANGES[variant_type]
        if not low <= value <= high:
            raise TypeError(f"Argument {index} is outside the range of {variant_type.name}: {value!r}")
        return int(value)
    if variant_type in _FLOATS:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise TypeError(f"Argument {index} must be a number for {variant_type.name}, got {value!r}")
        return float(value)
    if variant_type is ua.VariantType.Boolean and not isinstance(value, bool):
        raise TypeError(f"Argument {index} must be a bool, got {value!r}")
    if variant_type is ua.VariantType.String and not isinstance(value, str):
        raise TypeError(f"Argument {index} must be a str, got {value!r}")
    if variant_type is ua.VariantType.ByteString and not isinstance(value, bytes | bytearray):
        raise TypeError(f"Argument {index} must be bytes, got {value!r}")
    return value


def uamethod(func: Any) -> Any:
    """
    Method decorator to automatically convert
    arguments and output to and from variants
    """

    if inspect.iscoroutinefunction(func):

        @wraps(func)
        async def wrapper(parent: Any, *args: Any) -> Any:
            func_args = _format_call_inputs(parent, *args)
            result = await func(*func_args)
            return _format_call_outputs(result)

    else:

        @wraps(func)
        def wrapper(parent: Any, *args: Any) -> Any:
            func_args = _format_call_inputs(parent, *args)
            result = func(*func_args)
            return _format_call_outputs(result)

    return wrapper


def _format_call_inputs(parent: Any, *args: Any) -> tuple[Any, ...]:
    if isinstance(parent, ua.NodeId):
        return (parent, *[arg.Value for arg in args])
    self = parent
    parent = args[0]
    args = args[1:]
    return (self, parent, *[arg.Value for arg in args])


def _format_call_outputs(result: Any) -> Any:
    if result is None:
        return []
    if isinstance(result, ua.CallMethodResult):
        result.OutputArguments = to_variant(*result.OutputArguments)
        return result
    if isinstance(result, ua.StatusCode):
        return result
    if isinstance(result, tuple):
        return to_variant(*result)
    return to_variant(result)


def to_variant(*args: Any) -> list[ua.Variant]:
    """Create a list of ua.Variants from a given iterable of arguments."""
    uaargs: list[ua.Variant] = []
    for arg in args:
        if not isinstance(arg, ua.Variant):
            arg = ua.Variant(arg)
        uaargs.append(arg)
    return uaargs

import argparse
import asyncio
import code
import contextlib
import getpass
import importlib
import logging
import math
import os
import sys
import threading
import traceback
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from enginir_opcua import Client, Node, Server, ua, uamethod
from enginir_opcua.config import ServerConfig
from enginir_opcua.crypto import security_policies, uacrypto
from enginir_opcua.crypto.uacrypto import certificate_thumbprint
from enginir_opcua.server.user_managers import PermissiveUserManager
from enginir_opcua.sync import Client as SyncClient
from enginir_opcua.sync import SyncNode, ThreadLoop
from enginir_opcua.ua.uaerrors import UaError, UaStatusCodeError

PASSWORD_VARIABLE = "ENGINIR_OPCUA_PASSWORD"
PROGRAM = "enginir-opcua"
LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
DEFAULT_URL = "opc.tcp://localhost:4840"
DEMO_URL = "opc.tcp://127.0.0.1:4840"
ROOT_NODE = "i=84"
SERVER_OBJECT = "i=2253"
EXPECTED_ERRORS = (OSError, TimeoutError, UaError)


class ToolError(Exception):
    pass


class UsageError(ToolError):
    pass


def clean(text: object) -> str:
    return "".join(
        char
        if char in (" ", "\t") or char.isprintable()
        else (f"\\x{ord(char):02x}" if ord(char) < 256 else f"\\u{ord(char):04x}")
        for char in str(text)
    )


def say(text: object = "") -> None:
    print(clean(text))


def warn(text: object) -> None:
    print(clean(text), file=sys.stderr)


def shown_url(url: str) -> str:
    """The URL without the password of its user info, for messages."""
    parsed = urlparse(url)
    if parsed.password is None:
        return url
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    user = f"{parsed.username}@" if parsed.username else ""
    return parsed._replace(netloc=f"{user}{host}").geturl()


def _status_name(status: ua.StatusCode | None) -> str:
    return status.name if status is not None else "Good"


def _parse_bool(text: str) -> bool:
    lowered = text.strip().lower()
    if lowered in ("true", "1"):
        return True
    if lowered in ("false", "0"):
        return False
    raise ValueError("expected true, false, 1 or 0")


def _int_parser(low: int, high: int) -> Callable[[str], int]:
    def parse(text: str) -> int:
        stripped = text.strip()
        try:
            value = int(stripped, 10)
        except ValueError:
            value = int(stripped, 0)
        if not low <= value <= high:
            raise ValueError(f"expected a value from {low} to {high}")
        return value

    return parse


def parse_time(text: str) -> datetime:
    try:
        moment = datetime.fromisoformat(text.strip())
    except ValueError:
        raise ToolError(
            f"cannot read {text!r} as a time; use YYYY-MM-DD[ HH:MM[:SS]] with an optional Z or +hh:mm"
        ) from None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment


def str_to_datetime(s: str | None, default: datetime | None = None) -> datetime:
    if not s:
        return default if default is not None else datetime.now(UTC)
    return parse_time(s)


def _parse_bytes(text: str) -> bytes:
    digits = text.strip().replace(" ", "").replace(":", "")
    if digits.lower().startswith("0x"):
        digits = digits[2:]
    return bytes.fromhex(digits)


def _parse_status(text: str) -> ua.StatusCode:
    with contextlib.suppress(ValueError):
        return ua.StatusCode(int(text.strip(), 0))
    return ua.StatusCode(text.strip())


def _parse_localized(text: str) -> ua.LocalizedText:
    return ua.LocalizedText(text)


@dataclass(frozen=True)
class _Type:
    variant_type: ua.VariantType
    parse: Callable[[str], Any]


_INT_RANGES = {
    "sbyte": (ua.VariantType.SByte, -(2**7), 2**7 - 1),
    "byte": (ua.VariantType.Byte, 0, 2**8 - 1),
    "int16": (ua.VariantType.Int16, -(2**15), 2**15 - 1),
    "uint16": (ua.VariantType.UInt16, 0, 2**16 - 1),
    "int32": (ua.VariantType.Int32, -(2**31), 2**31 - 1),
    "uint32": (ua.VariantType.UInt32, 0, 2**32 - 1),
    "int64": (ua.VariantType.Int64, -(2**63), 2**63 - 1),
    "uint64": (ua.VariantType.UInt64, 0, 2**64 - 1),
}

TYPES: dict[str, _Type] = {
    "bool": _Type(ua.VariantType.Boolean, _parse_bool),
    **{name: _Type(vtype, _int_parser(low, high)) for name, (vtype, low, high) in _INT_RANGES.items()},
    "float": _Type(ua.VariantType.Float, float),
    "double": _Type(ua.VariantType.Double, float),
    "string": _Type(ua.VariantType.String, str),
    "datetime": _Type(ua.VariantType.DateTime, parse_time),
    "guid": _Type(ua.VariantType.Guid, uuid.UUID),
    "bytestring": _Type(ua.VariantType.ByteString, _parse_bytes),
    "xmlelement": _Type(ua.VariantType.XmlElement, ua.XmlElement),
    "nodeid": _Type(ua.VariantType.NodeId, ua.NodeId.from_string),
    "expandednodeid": _Type(ua.VariantType.ExpandedNodeId, ua.ExpandedNodeId.from_string),
    "qualifiedname": _Type(ua.VariantType.QualifiedName, ua.QualifiedName.from_string),
    "localizedtext": _Type(ua.VariantType.LocalizedText, _parse_localized),
    "statuscode": _Type(ua.VariantType.StatusCode, _parse_status),
}
ALIASES = {"xml": "xmlelement", "browsename": "qualifiedname"}
TYPE_CHOICES = ["guess", *TYPES, *ALIASES]
TYPE_NAME_OF = {entry.variant_type: name for name, entry in TYPES.items()}


def _convert(text: str, name: str, locale: str | None) -> Any:
    try:
        if name == "localizedtext" and locale:
            return ua.LocalizedText(Text=text, Locale=locale)
        return TYPES[name].parse(text)
    except ToolError:
        raise
    except (ValueError, TypeError, UaError) as exc:
        raise ToolError(f"cannot read {text!r} as {name}: {exc}") from None


def _guess_name(text: str) -> str:
    if text in ("true", "True", "false", "False"):
        return "bool"
    for name in ("int64", "double"):
        try:
            TYPES[name].parse(text)
        except ValueError:
            continue
        return name
    return "string"


def variant_from_text(
    text: str,
    datatype: str = "guess",
    *,
    array: bool = False,
    separator: str = ",",
    locale: str | None = None,
) -> ua.Variant:
    name = ALIASES.get(datatype.lower(), datatype.lower())
    if name != "guess" and name not in TYPES:
        raise ToolError(f"unknown data type {datatype!r}")
    items = (text.split(separator) if text != "" else []) if array else [text]
    if name == "guess":
        name = _guess_name(items[0]) if items else "string"
    values = [_convert(item, name, locale) for item in items]
    return ua.Variant(values if array else values[0], TYPES[name].variant_type)


def parse_attribute(text: str) -> ua.AttributeIds:
    try:
        return ua.AttributeIds(int(text, 0))
    except ValueError:
        pass
    for member in ua.AttributeIds:
        if member.name.lower() == text.lower():
            return member
    raise UsageError(f"unknown attribute {text!r}")


def add_client_options(parser: argparse.ArgumentParser, security: bool = True) -> None:
    parser.add_argument(
        "-u",
        "--url",
        default=DEFAULT_URL,
        metavar="URL",
        help=f"URL of the OPC UA server; opc.tcp:// is added when missing. Default: {DEFAULT_URL}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        metavar="SECONDS",
        help="Timeout of each request to the server, in seconds. Default: 4",
    )
    if not security:
        return
    parser.add_argument(
        "--security",
        default="",
        metavar="STRING",
        help="Security settings: Policy,Mode,certificate,private_key[,server_certificate], for example"
        " Basic256Sha256,SignAndEncrypt,cert.der,pk.pem,server.der; with --pki-dir only Policy,Mode."
        " Default: no security",
    )
    parser.add_argument(
        "--pki-dir",
        metavar="DIR",
        help="PKI directory with the certificate, key and trusted certificates of this client",
    )
    parser.add_argument("--user", help="User name for authentication. Overrides the user name in the URL.")
    parser.add_argument(
        "--ask-password",
        action="store_true",
        help="Ask for the password on the terminal. Without it the password is taken from the environment"
        f" variable {PASSWORD_VARIABLE} when that is set. Either overrides the password in the URL.",
    )


def add_node_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-n", "--nodeid", metavar="NODE", help="NodeId of the node (for example: i=85 or ns=2;s=Name)")
    parser.add_argument(
        "-p",
        "--path",
        metavar="BROWSEPATH",
        help="Comma separated browse path to the node, starting at NODE or at the Root object"
        " (for example: 0:Objects,2:MyObject,2:MyVariable)",
    )


def add_value_options(parser: argparse.ArgumentParser, default: str) -> None:
    choices = ["auto", *TYPE_CHOICES] if default == "auto" else TYPE_CHOICES
    auto = "auto reads the DataType of the node. " if default == "auto" else ""
    parser.add_argument(
        "-t",
        "--datatype",
        default=default,
        type=str.lower,
        choices=choices,
        help=f"Data type of the value. {auto}guess takes true/false as Boolean, a whole number as Int64,"
        f" another number as Double, anything else as String. Default: {default}",
    )
    parser.add_argument(
        "-l",
        "--list",
        "--array",
        dest="array",
        action="store_true",
        help="The value is a list, split at the separator (a string may then not contain it)",
    )
    parser.add_argument("--separator", default=",", metavar="CHAR", help="Separator of a list. Default: ,")
    parser.add_argument("--locale", metavar="LOCALE", help="Locale of a localizedtext value, for example en-US")


def _password_from(args: argparse.Namespace) -> str | None:
    if args.ask_password:
        return getpass.getpass("Password: ")
    return os.environ.get(PASSWORD_VARIABLE)


async def configure_client(client: Client, args: argparse.Namespace) -> None:
    if args.user:
        client.set_user(args.user)
    password = _password_from(args)
    if password:
        client.set_password(password)
    if args.pki_dir:
        await client.set_pki_directory(args.pki_dir, create=False)
    if args.pki_dir and args.security:
        policy_name, _, mode_name = args.security.partition(",")
        policy = getattr(security_policies, f"SecurityPolicy{policy_name}", None)
        modes = {"Sign": ua.MessageSecurityMode.Sign, "SignAndEncrypt": ua.MessageSecurityMode.SignAndEncrypt}
        if policy is None or mode_name not in modes:
            raise UsageError("with --pki-dir, --security takes Policy,Mode, for example Basic256Sha256,SignAndEncrypt")
        await client.set_security(policy, mode=modes[mode_name])
    else:
        await client.set_security_string(args.security)


def normalise_url(args: argparse.Namespace) -> None:
    if args.url and "://" not in args.url:
        logging.getLogger(__name__).info("Adding default scheme %s to URL %s", ua.OPC_TCP_SCHEME, args.url)
        args.url = ua.OPC_TCP_SCHEME + "://" + args.url
    if urlparse(args.url).password:
        warn(
            "warning: a password in the URL is visible in the process list and in the shell history;"
            f" use --ask-password or the variable {PASSWORD_VARIABLE}"
        )


async def with_client(args: argparse.Namespace, work: Callable[[Client], Awaitable[int]]) -> int:
    client = Client(args.url, timeout=args.timeout, auto_reconnect=getattr(args, "auto_reconnect", False))
    await configure_client(client, args)
    try:
        await client.connect()
        return await work(client)
    finally:
        await client.disconnect()


async def resolve_node(client: Client, args: argparse.Namespace, default: str | None = None) -> Node:
    nodeid = args.nodeid or default
    if nodeid is None and not args.path:
        raise UsageError("a NodeId (-n) or a browse path (-p) is required")
    node = client.get_node(nodeid or ROOT_NODE)
    if args.path:
        elements = [element for element in args.path.split(",") if element]
        if node.nodeid == ua.NodeId(84, 0) and elements and elements[0] == "0:Root":
            elements = elements[1:]
        if elements:
            node = await node.get_child(elements)
    return node


async def convert_for_node(node: Node, args: argparse.Namespace) -> ua.Variant:
    datatype = args.datatype
    if datatype == "auto":
        variant_type = await node.read_data_type_as_variant_type()
        datatype = TYPE_NAME_OF.get(variant_type, "")
        if not datatype:
            raise ToolError(f"the node has the type {variant_type.name}, which can't be written from text")
    return variant_from_text(args.value, datatype, array=args.array, separator=args.separator, locale=args.locale)


async def _read(client: Client, args: argparse.Namespace) -> int:
    node = await resolve_node(client, args)
    data_value = await node.read_attribute(
        parse_attribute(args.attribute), raise_on_bad_status=args.datatype != "datavalue"
    )
    if args.datatype == "python":
        say(data_value.Value.Value if data_value.Value is not None else None)
    elif args.datatype == "variant":
        say(data_value.Value)
    else:
        say(data_value)
    return 0


async def _write(client: Client, args: argparse.Namespace) -> int:
    node = await resolve_node(client, args)
    variant = await convert_for_node(node, args)
    await node.write_attribute(parse_attribute(args.attribute), ua.DataValue(variant))
    return 0


async def _choose_method(node: Node, args: argparse.Namespace) -> Any:
    if args.method is not None:
        if args.method.startswith(("i=", "s=", "ns=", "nsu=")):
            return ua.NodeId.from_string(args.method)
        return args.method
    methods = await node.get_methods()
    if not methods:
        raise ToolError("the node has no methods and no method was given")
    if len(methods) > 1:
        names = [(await candidate.read_browse_name()).to_string() for candidate in methods]
        raise UsageError(f"the node has several methods ({', '.join(names)}); choose one with -m")
    return methods[0]


async def _call(client: Client, args: argparse.Namespace) -> int:
    node = await resolve_node(client, args)
    texts = list(args.arguments)
    if getattr(args, "legacy_comma_split", False) and len(texts) == 1:
        texts = texts[0].split(",")
    variants = [
        variant_from_text(text, args.datatype, array=args.array, separator=args.separator, locale=args.locale)
        for text in texts
    ]
    values = [variant.Value for variant in variants] if args.datatype == "guess" else variants
    result = await node.call_method(await _choose_method(node, args), *values)
    outputs = result if isinstance(result, list | tuple) else [] if result is None else [result]
    for output in outputs:
        say(output)
    return 0


def _row(cells: Sequence[object]) -> str:
    return " ".join(f"{clean(cell):{30 if index == 0 else 25}}" for index, cell in enumerate(cells)).rstrip()


async def _read_for_listing(node: Node) -> Any:
    try:
        return await node.read_value()
    except UaStatusCodeError as err:
        return f"Bad (0x{err.code:x})"
    except UaError:
        warn(f"Warning: Error reading {node.nodeid}, retrying...")
        try:
            return await node.read_value()
        except UaStatusCodeError as err:
            return f"Bad (0x{err.code:x})"
        except UaError as err:
            return f"Error: {err}"


async def _long_cells(node: Node) -> list[object]:
    try:
        attributes = await node.read_attributes([ua.AttributeIds.DataType, ua.AttributeIds.Value])
    except UaError as err:
        return ["", "", f"Error: {err}"]
    data_type = attributes[0].Value.Value if attributes[0].Value is not None else None
    value = attributes[1].Value.Value if attributes[1].Value is not None else _status_name(attributes[1].StatusCode)
    return [data_type.to_string() if data_type is not None else "", attributes[1].ServerTimestamp, value]


async def _list_children(node: Node, depth: int, layout: str, indent: str = "") -> None:
    if not indent:
        headers = {
            "name": ["DisplayName", "NodeId"],
            "value": ["DisplayName", "NodeId", "BrowseName", "Value"],
            "long": ["DisplayName", "NodeId", "BrowseName", "DataType", "Timestamp", "Value"],
        }[layout]
        say(_row(headers))
        say()
    for description in await node.get_children_descriptions():
        child = Node(node.session, description.NodeId)
        cells: list[object] = [description.DisplayName.to_string(), description.NodeId.to_string()]
        if layout != "name":
            cells.append(description.BrowseName.to_string())
            if description.NodeClass == ua.NodeClass.Variable:
                cells += await _long_cells(child) if layout == "long" else [await _read_for_listing(child)]
        say(indent + _row(cells))
        if depth > 1:
            await _list_children(child, depth - 1, layout, indent + "  ")


async def _ls(client: Client, args: argparse.Namespace) -> int:
    node = await resolve_node(client, args, default=ROOT_NODE)
    say(f"Browsing node {node} at {shown_url(args.url)}")
    say()
    await _list_children(node, args.depth, args.format)
    return 0


def _event_line(event: Any) -> str:
    if hasattr(event, "event"):
        return " ".join(str(getattr(event.event, name, "")) for name in ("Time", "SourceName", "Message", "Severity"))
    if hasattr(event, "notification"):
        return f"status {event.notification.Status.name}"
    notification = event.data.monitored_item.Value
    moment = notification.SourceTimestamp or notification.ServerTimestamp
    return f"{moment} {event.node.nodeid.to_string()} {event.value} {_status_name(notification.StatusCode)}"


async def _subscribe(client: Client, args: argparse.Namespace) -> int:
    node = await resolve_node(client, args, default=SERVER_OBJECT if args.eventtype == "event" else None)
    seen = 0
    scope = asyncio.timeout(args.duration)
    try:
        async with scope:
            async with await client.create_subscription(args.interval) as subscription:
                if args.eventtype == "datachange":
                    await subscription.subscribe_data_change(node)
                else:
                    await subscription.subscribe_events(node)
                warn("Type Ctrl-C to exit")
                async for event in subscription:
                    say(_event_line(event))
                    seen += 1
                    if args.count and seen >= args.count:
                        break
    except TimeoutError:
        if not scope.expired():
            raise
    return 0


async def _history(client: Client, args: argparse.Namespace) -> int:
    node = await resolve_node(client, args)
    now = datetime.now(UTC)
    start = str_to_datetime(args.start, now - timedelta(days=1))
    end = str_to_datetime(args.end, now)
    say(f"Reading the history of node {node} at {shown_url(args.url)}; start at {start}, end at {end}")
    say()
    if args.events:
        for event in await node.read_event_history(start, end, numvalues=args.limit):
            say(event)
        return 0
    say("{0:30} {1:10} {2}".format("Source timestamp", "Status", "Value"))
    for data_value in await node.read_raw_history(start, end, numvalues=args.limit):
        value = data_value.Value.Value if data_value.Value is not None else None
        say("{0:30} {1:10} {2}".format(str(data_value.SourceTimestamp), _status_name(data_value.StatusCode), value))
    return 0


async def _generate_structs(client: Client, args: argparse.Namespace) -> int:
    node = await resolve_node(client, args)
    generators, _ = await client.load_type_definitions([node])
    generators[0].save_to_file(args.output, True)
    return 0


def application_to_strings(app: Any) -> list[tuple[str, Any]]:
    result = [("Application URI", app.ApplicationUri)]
    optionals = [
        ("Product URI", app.ProductUri),
        ("Application Name", app.ApplicationName.to_string()),
        ("Application Type", str(app.ApplicationType)),
        ("Gateway Server URI", app.GatewayServerUri),
        ("Discovery Profile URI", app.DiscoveryProfileUri),
    ]
    result += [(name, value) for name, value in optionals if value]
    result += [("Discovery URL", url) for url in app.DiscoveryUrls or []]
    return result


def cert_to_string(der: bytes | None) -> str:
    if not der:
        return "[no certificate]"
    from .crypto import uacrypto

    return uacrypto.x509_to_string(uacrypto.x509_from_der(der))


def endpoint_to_strings(ep: Any) -> list[tuple[str, Any]]:
    result = [("Endpoint URL", ep.EndpointUrl)]
    result += application_to_strings(ep.Server)
    result += [
        ("Server Certificate", cert_to_string(ep.ServerCertificate)),
        ("Security Mode", str(ep.SecurityMode)),
        ("Security Policy URI", ep.SecurityPolicyUri),
    ]
    for token in ep.UserIdentityTokens:
        result += [("User policy", token.PolicyId), ("  Token type", str(token.TokenType))]
        if token.IssuedTokenType or token.IssuerEndpointUrl:
            result += [
                ("  Issued Token type", token.IssuedTokenType),
                ("  Issuer Endpoint URL", token.IssuerEndpointUrl),
            ]
        if token.SecurityPolicyUri:
            result.append(("  Security Policy URI", token.SecurityPolicyUri))
    result += [("Transport Profile URI", ep.TransportProfileUri), ("Security Level", ep.SecurityLevel)]
    return result


def network_to_strings(record: Any) -> list[tuple[str, Any]]:
    return [
        ("Record Id", record.RecordId),
        ("Server Name", record.ServerName),
        ("Discovery URL", record.DiscoveryUrl),
        ("Server Capabilities", ",".join(record.ServerCapabilities or [])),
    ]


def _print_block(title: str, rows: list[tuple[str, Any]]) -> None:
    say(title)
    for name, value in rows:
        say(f"  {name}: {value}")
    say()


async def _discover(args: argparse.Namespace) -> int:
    client = Client(args.url, timeout=args.timeout)
    say(f"Performing discovery at {shown_url(args.url)}")
    say()
    if args.network:
        try:
            result = await client.connect_and_find_servers_on_network()
        except UaStatusCodeError as err:
            if err.code != ua.StatusCodes.BadServiceUnsupported:
                raise
            warn("FindServersOnNetwork is not supported by this server")
        else:
            for index, record in enumerate(result.Servers, start=1):
                _print_block(f"Server on network {index}:", network_to_strings(record))
    for index, server in enumerate(await client.connect_and_find_servers(), start=1):
        _print_block(f"Server {index}:", application_to_strings(server))
    for index, endpoint in enumerate(await client.connect_and_get_server_endpoints(), start=1):
        _print_block(f"Endpoint {index}:", endpoint_to_strings(endpoint))
    return 0


def open_shell(namespace: dict[str, Any], banner: str = "") -> None:
    try:
        embed = importlib.import_module("IPython").embed
    except ImportError:
        code.interact(banner=banner, local=dict(namespace))
        return
    embed(user_ns=dict(namespace), banner1=banner)


def _shell(args: argparse.Namespace) -> int:
    client = SyncClient(args.url, timeout=args.timeout)
    try:
        client.tloop.post(configure_client(client.aio_obj, args))
        if args.certificate:
            client.load_client_certificate(args.certificate)
        if args.private_key:
            client.load_private_key(args.private_key)
        client.connect()
        namespace: dict[str, Any] = {
            "client": client,
            "root": client.nodes.root,
            "objects": client.nodes.objects,
            "ua": ua,
        }
        if args.nodeid or args.path:
            namespace["mynode"] = SyncNode(client.tloop, client.tloop.post(resolve_node(client.aio_obj, args)))
        open_shell(namespace, f"Names: {', '.join(namespace)}")
    finally:
        client.disconnect()
    return 0


@dataclass
class _DemoServer:
    server: Server
    ticker: asyncio.Task[None] | None = None
    nodes: dict[str, Node] = field(default_factory=dict)


async def _populate(server: Server, demo: _DemoServer) -> None:
    @uamethod
    def multiply(parent: Any, x: float, y: float) -> float:
        return x * y

    idx = await server.register_namespace("urn:enginir:opcua:examples")
    myobj = await server.nodes.objects.add_object(idx, "MyObject")
    writable = await myobj.add_variable(idx, "MyWritableVariable", 6.7)
    await writable.set_writable()
    demo.nodes["variable"] = await myobj.add_variable(idx, "MyVariable", 6.7)
    demo.nodes["array"] = await myobj.add_variable(idx, "MyVarArray", [6.7, 7.9])
    await myobj.add_property(idx, "MyProperty", "I am a property")
    await myobj.add_method(
        idx, "MyMethod", multiply, [ua.VariantType.Double, ua.VariantType.Int64], [ua.VariantType.Double]
    )


async def _tick(demo: _DemoServer) -> None:
    count = 0
    while True:
        await asyncio.sleep(1)
        await demo.nodes["variable"].write_value(math.sin(count / 10))
        await demo.nodes["array"].write_value([math.sin(count / 10), math.sin(count / 100)])
        count += 1


async def _start_demo_server(args: argparse.Namespace) -> _DemoServer:
    if args.config:
        return await _start_configured_server(args)
    server = Server(user_manager=PermissiveUserManager() if args.accept_all_logins else None, allow_no_security=True)
    server.allow_plaintext_password = args.accept_all_logins
    await server.init()
    server.set_endpoint(args.url)
    if args.pki_dir:
        await server.set_pki_directory(args.pki_dir)
        certificate = server.iserver.certificate
        if certificate is not None:
            warn(
                f"PKI directory {args.pki_dir}: application certificate, thumbprint "
                f"{certificate_thumbprint(uacrypto.der_from_x509(certificate)).hex()}"
            )
    if args.certificate:
        await server.load_certificate(args.certificate)
    if args.private_key:
        await server.load_private_key(args.private_key)
    server.disable_clock(args.disable_clock)
    server.set_server_name("engiNIR OPC UA Example Server")
    for path in args.xml or []:
        await server.import_xml(path)
    demo = _DemoServer(server)
    if args.populate:
        await _populate(server, demo)
    await server.start()
    if args.populate:
        demo.ticker = asyncio.get_running_loop().create_task(_tick(demo))
    return demo


async def _start_configured_server(args: argparse.Namespace) -> _DemoServer:
    server = Server(config=ServerConfig.from_toml(args.config))
    await server.init()
    server.disable_clock(args.disable_clock)
    for path in args.xml or []:
        await server.import_xml(path)
    demo = _DemoServer(server)
    if args.populate:
        await _populate(server, demo)
    await server.start()
    if args.populate:
        demo.ticker = asyncio.get_running_loop().create_task(_tick(demo))
    return demo


def _check_config_options(args: argparse.Namespace) -> None:
    conflicting = [
        name
        for name, given in (
            ("--url", args.url != DEMO_URL),
            ("--certificate", bool(args.certificate)),
            ("--private-key", bool(args.private_key)),
            ("--pki-dir", bool(args.pki_dir)),
            ("--accept-all-logins", args.accept_all_logins),
        )
        if given
    ]
    if conflicting:
        raise UsageError(f"--config replaces {', '.join(conflicting)}; put these settings in the file")


def _server(args: argparse.Namespace) -> int:
    if args.config:
        _check_config_options(args)
        config = ServerConfig.from_toml(args.config)
        warn(f"Serving {config.endpoint} with the {config.profile} profile from {args.config}.")
    logins = (
        " INSECURE: --accept-all-logins accepts every user name and password and lets anonymous users write."
        if args.accept_all_logins
        else ""
    )
    populate = " --populate adds a writable variable and a method." if args.populate else ""
    if not args.config:
        warn(
            f"This is a demo server. It offers an endpoint without security at {shown_url(args.url)}"
            f" and, by default, accepts only anonymous read-only sessions.{logins}{populate}"
            " Do not use it to expose real data on a network you do not trust."
        )
    with ThreadLoop(timeout=None) as tloop:
        demo = tloop.post(_start_demo_server(args))
        try:
            if args.shell:
                namespace: dict[str, Any] = {
                    "server": demo.server,
                    "run": tloop.post,
                    "root": SyncNode(tloop, demo.server.nodes.root),
                    "objects": SyncNode(tloop, demo.server.nodes.objects),
                    "ua": ua,
                }
                open_shell(namespace, f"Names: {', '.join(namespace)}")
            else:
                threading.Event().wait()
        finally:
            tloop.post(demo.server.stop(), timeout=10)
    return 0


@dataclass(frozen=True)
class Command:
    name: str
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    run: Callable[[argparse.Namespace], int]
    aliases: tuple[str, ...] = ()
    until_stopped: bool = False
    client_options: bool = True
    security_options: bool = True


COMMANDS: dict[str, Command] = {}


def register(command: Command) -> None:
    COMMANDS[command.name] = command


def _client_command(
    work: Callable[[Client, argparse.Namespace], Awaitable[int]],
) -> Callable[[argparse.Namespace], int]:
    def run(args: argparse.Namespace) -> int:
        return asyncio.run(with_client(args, lambda client: work(client, args)))

    return run


def _read_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument(
        "-a",
        "--attribute",
        default="Value",
        metavar="ATTRIBUTE",
        help="Attribute to read: its name or number. Default: Value",
    )
    parser.add_argument(
        "-t",
        "--datatype",
        default="python",
        choices=["python", "variant", "datavalue"],
        help="What to print: the Python value, the Variant or the whole DataValue. Default: python",
    )


def _write_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument("value", metavar="VALUE", help="Value to be written")
    parser.add_argument(
        "-a",
        "--attribute",
        default="Value",
        metavar="ATTRIBUTE",
        help="Attribute to write: its name or number. Default: Value",
    )
    add_value_options(parser, "auto")


def _call_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument("arguments", nargs="*", metavar="ARG", help="Input arguments of the method, one per ARG")
    parser.add_argument(
        "-m",
        "--method",
        metavar="NAME",
        help="Browse name or NodeId of the method. Default: the only method of the node",
    )
    add_value_options(parser, "guess")


def _ls_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument("-d", "--depth", type=int, default=1, metavar="N", help="Browse depth, at least 1. Default: 1")
    parser.add_argument(
        "--format",
        choices=["name", "value", "long"],
        default="value",
        help="Columns to print: names, names and values, or long with data type and timestamp. Default: value",
    )
    parser.add_argument(
        "-l",
        dest="long_format",
        nargs="?",
        const=3,
        type=int,
        metavar="N",
        help="Long listing (old form: -l 0, 1 or 3)",
    )


def _subscribe_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument(
        "-t",
        "--eventtype",
        default="datachange",
        choices=["datachange", "event"],
        help="Subscribe to data changes or to events. Default: datachange",
    )
    parser.add_argument(
        "--interval", type=float, default=500, metavar="MILLISECONDS", help="Publishing interval in ms. Default: 500"
    )
    parser.add_argument("--count", type=int, default=0, metavar="N", help="Stop after N notifications")
    parser.add_argument("--duration", type=float, metavar="SECONDS", help="Stop after this many seconds")
    parser.add_argument("--auto-reconnect", action="store_true", help="Reconnect when the connection is lost")


def _history_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument(
        "--start",
        "--starttime",
        dest="start",
        metavar="TIME",
        help="Start time, YYYY-MM-DD[ HH:MM[:SS]], UTC unless a zone is given. Default: now minus one day",
    )
    parser.add_argument(
        "--end", "--endtime", dest="end", metavar="TIME", help="End time, as the start time. Default: now"
    )
    parser.add_argument("-e", "--events", action="store_true", help="Read event history instead of values")
    parser.add_argument(
        "-l", "--limit", type=int, default=10, metavar="N", help="Maximum number of values. Default: 10"
    )


def _discover_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-n", "--network", action="store_true", help="Also send a FindServersOnNetwork request to the server"
    )


def _shell_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument("-c", "--certificate", help="Client certificate")
    parser.add_argument("-k", "--private-key", "--private_key", dest="private_key", help="Client private key")


def _generate_arguments(parser: argparse.ArgumentParser) -> None:
    add_node_options(parser)
    parser.add_argument("-o", "--output", required=True, metavar="FILE", help="The Python file to generate")


def _server_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-u", "--url", default=DEMO_URL, metavar="URL", help=f"URL to listen on. Default: {DEMO_URL}")
    parser.add_argument(
        "-x", "--xml", action="append", metavar="XML_FILE", help="Nodeset XML file to import; repeatable"
    )
    parser.add_argument("-p", "--populate", action="store_true", help="Populate the address space with sample nodes")
    parser.add_argument(
        "-c", "--disable-clock", action="store_true", help="Disable the clock of the server, to see fewer writes"
    )
    parser.add_argument(
        "-s", "--shell", action="store_true", help="Open a Python shell instead of just serving; the server goes on"
    )
    parser.add_argument("--certificate", help="Server certificate")
    parser.add_argument("--private-key", "--private_key", dest="private_key", help="Server private key")
    parser.add_argument("--pki-dir", metavar="DIR", help="PKI directory of the server")
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Serve from a server configuration file (see enginir-opcua init server) instead of the demo settings;"
        " it excludes --url, --certificate, --private-key, --pki-dir and --accept-all-logins",
    )
    parser.add_argument(
        "--accept-all-logins",
        action="store_true",
        help="INSECURE: accept every user name and password, with Admin for admin, and let anonymous users write",
    )


def _run_ls(args: argparse.Namespace) -> int:
    if args.long_format is not None:
        args.format = {0: "name", 1: "value"}.get(args.long_format, "long")
    if args.depth < 1:
        raise UsageError("the depth must be at least 1")
    return _client_command(_ls)(args)


def _run_discover(args: argparse.Namespace) -> int:
    return asyncio.run(_discover(args))


for _command in (
    Command("read", "Read an attribute of a node, the value by default", _read_arguments, _client_command(_read)),
    Command("write", "Write an attribute of a node, the value by default", _write_arguments, _client_command(_write)),
    Command("call", "Call a method of a node", _call_arguments, _client_command(_call)),
    Command("ls", "Browse below a node and print the result", _ls_arguments, _run_ls, aliases=("browse",)),
    Command(
        "subscribe",
        "Subscribe to a node and print the notifications until stopped",
        _subscribe_arguments,
        _client_command(_subscribe),
        until_stopped=True,
    ),
    Command("history", "Read the history of a node", _history_arguments, _client_command(_history)),
    Command(
        "discover",
        "Discover servers and endpoints and print them",
        _discover_arguments,
        _run_discover,
        security_options=False,
    ),
    Command(
        "server",
        "Run a DEMO server: no security by default, anonymous sessions read-only",
        _server_arguments,
        _server,
        until_stopped=True,
        client_options=False,
    ),
    Command(
        "shell",
        "Connect to a server and open a Python shell with client, root, objects and mynode",
        _shell_arguments,
        _shell,
        until_stopped=True,
    ),
    Command(
        "generate-structs",
        "Generate a Python module from a (pre-1.04) structure dictionary of the server",
        _generate_arguments,
        _client_command(_generate_structs),
    ),
):
    register(_command)


def build_parser() -> argparse.ArgumentParser:
    from enginir_opcua import __version__

    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Look at and drive OPC UA servers: browse, read, write, call, subscribe, read history, discover,"
        " run a demo server.",
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    parser.add_argument("--log-level", dest="log_level", choices=LOG_LEVELS, default="WARNING", help="Log level")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    for command in COMMANDS.values():
        sub = subparsers.add_parser(
            command.name, aliases=list(command.aliases), help=command.help, description=command.help
        )
        if command.client_options:
            add_client_options(sub, command.security_options)
        command.add_arguments(sub)
        sub.add_argument(
            "--log-level",
            "-v",
            dest="log_level",
            choices=LOG_LEVELS,
            default=argparse.SUPPRESS,
            help="Log level. Default: WARNING",
        )
    return parser


def _command_of(args: argparse.Namespace) -> Command:
    for command in COMMANDS.values():
        if args.command == command.name or args.command in command.aliases:
            return command
    raise UsageError(f"unknown command {args.command}")


def main(argv: Sequence[str] | None = None, legacy_comma_split: bool = False) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), stream=sys.stderr, format="%(levelname)s: %(message)s")
    command = _command_of(args)
    args.legacy_comma_split = legacy_comma_split
    if hasattr(args, "url"):
        normalise_url(args)
    try:
        return command.run(args)
    except KeyboardInterrupt:
        return 0 if command.until_stopped else 130
    except UsageError as exc:
        parser.print_usage(sys.stderr)
        warn(f"{PROGRAM} {command.name}: error: {exc}")
        return 2
    except (ToolError, *EXPECTED_ERRORS) as exc:
        warn(f"{PROGRAM} {command.name}: error: {exc or type(exc).__name__}")
        if args.log_level == "DEBUG":
            traceback.print_exc()
        return 1


def cli() -> None:
    sys.exit(main())


def _translate_legacy_array(argv: list[str]) -> list[str]:
    translated: list[str] = []
    position = 0
    while position < len(argv):
        token = argv[position]
        following = argv[position + 1] if position + 1 < len(argv) else None
        if token in ("-l", "--list", "--array") and following in ("guess", "true", "false"):
            if following == "true":
                translated.append(token)
            position += 2
            continue
        translated.append(token)
        position += 1
    return translated


def _legacy(script: str, command: str) -> None:
    warn(f'{script} is deprecated and will be removed in 4.0.0; use "{PROGRAM} {command}"')
    argv = list(sys.argv[1:])
    if command in ("write", "call"):
        argv = _translate_legacy_array(argv)
    sys.exit(main([command, *argv], legacy_comma_split=command == "call"))


def uaread() -> None:
    _legacy("enginir-uaread", "read")


def uawrite() -> None:
    _legacy("enginir-uawrite", "write")


def uacall() -> None:
    _legacy("enginir-uacall", "call")


def uals() -> None:
    _legacy("enginir-uals", "ls")


def uabrowse() -> None:
    _legacy("enginir-uabrowse", "ls")


def uasubscribe() -> None:
    _legacy("enginir-uasubscribe", "subscribe")


def uahistoryread() -> None:
    _legacy("enginir-uahistoryread", "history")


def uadiscover() -> None:
    _legacy("enginir-uadiscover", "discover")


def uaserver() -> None:
    _legacy("enginir-uaserver", "server")


def uaclient() -> None:
    _legacy("enginir-uaclient", "shell")


def uageneratestructs() -> None:
    _legacy("enginir-uageneratestructs", "generate-structs")


from enginir_opcua import cli_setup  # noqa: E402,F401

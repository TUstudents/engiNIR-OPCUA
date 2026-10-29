from __future__ import annotations

from urllib.parse import ParseResult, urlparse

from .ua.uaerrors import ConfigurationError

MAX_PORT = 65_535


def parse_opc_tcp_url(url: str, setting: str = "endpoint") -> ParseResult:
    """Parse an opc.tcp URL and check scheme, host and port; errors name the setting."""
    if not isinstance(url, str):
        raise ConfigurationError(f"{setting}: expected a URL string, got {url!r}")
    parsed = urlparse(url)
    if parsed.scheme != "opc.tcp":
        raise ConfigurationError(f"{setting}: expected a URL that starts with opc.tcp://, got {url!r}")
    if not parsed.hostname:
        raise ConfigurationError(f"{setting}: the URL {url!r} has no host; write opc.tcp://host:port/path")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError(f"{setting}: the URL {url!r} must not carry a user name or password")
    try:
        port = parsed.port
    except ValueError:
        port = 0
    if port is not None and not 1 <= port <= MAX_PORT:
        raise ConfigurationError(f"{setting}: the port of {url!r} must be from 1 to {MAX_PORT}")
    return parsed

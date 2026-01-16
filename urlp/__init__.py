"""urlp - Lightweight URL parsing and building helpers.

This module provides the public API for URL parsing, building, and validation.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

__version__ = "0.2.0"

# Exceptions
from .exceptions import (
    InvalidURLError,
    URLpError,
    URLParseError,
    URLBuildError,
    UnsupportedSchemeError,
    HostValidationError,
    PortValidationError,
    QueryParsingError,
    FragmentEncodingError,
    UserInfoParsingError,
    MissingHostError,
)

# URL class and related
from .url import (
    URL,
    build_relative_reference,
    parse_relative_reference,
    round_trip_relative,
    set_audit_callback,
    get_audit_callback,
)

# Internal classes (for advanced use)
from ._parser import Parser
from ._builder import Builder
from ._validation import Validator

# Security
from ._security import validate_url_security

# Constants
from .constants import (
    MAX_URL_LENGTH,
    MAX_SCHEME_LENGTH,
    MAX_HOST_LENGTH,
    MAX_PATH_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_FRAGMENT_LENGTH,
    MAX_USERINFO_LENGTH,
    DEFAULT_DNS_TIMEOUT,
    PASSWORD_MASK,
)


# =============================================================================
# Public API Functions
# =============================================================================

def parse_url(
    url: str, *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False
) -> URL:
    """Parse URL with security checks enabled (SECURE BY DEFAULT).

    This is the recommended function for parsing URLs. It enables:
    - SSRF protection (blocks private IPs, localhost, etc.)
    - Double-encoding detection
    - Path traversal detection
    - Open redirect detection
    - Homograph attack detection

    For parsing URLs without security checks (e.g., internal/development URLs),
    use `parse_url_unsafe()` instead.

    Args:
        url: The URL string to parse.
        allow_custom_scheme: If True, allow non-standard schemes.
        check_dns: If True, also perform DNS resolution checks.

    Returns:
        An immutable URL object.

    Raises:
        InvalidURLError: If the URL fails any security check.
    """
    validate_url_security(url)
    parser = Parser()
    parser.custom_scheme = allow_custom_scheme
    return URL(url, parser=parser, strict=True, check_dns=check_dns)


def parse_url_unsafe(
    url: str, *,
    allow_custom_scheme: bool = False,
    strict: bool = False,
    debug: bool = False,
    check_dns: bool = False
) -> URL:
    """Parse a URL string WITHOUT security checks.

    WARNING: This function does not perform security validations by default.
    Use `parse_url()` instead for security-sensitive contexts.

    Only use this function when:
    - Parsing URLs from trusted sources
    - You need to allow private IPs or localhost
    - You're intentionally bypassing security checks

    Args:
        url: The URL string to parse.
        allow_custom_scheme: If True, allow non-standard schemes.
        strict: If True, enable SSRF protection.
        debug: If True, include raw input in exception traces.
        check_dns: If True, perform DNS resolution checks.

    Returns:
        An immutable URL object.
    """
    parser = Parser()
    parser.custom_scheme = allow_custom_scheme
    return URL(url, parser=parser, strict=strict, debug=debug, check_dns=check_dns)


def parse_url_strict(
    url: str, *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False
) -> URL:
    """Deprecated: Use parse_url() instead.

    This function is kept for backward compatibility but is now
    identical to parse_url() since secure parsing is the default.
    """
    return parse_url(url, allow_custom_scheme=allow_custom_scheme, check_dns=check_dns)


def build(
    scheme: str,
    host: str,
    *,
    port: Optional[int] = None,
    path: str = "/",
    query: Optional[str] = None,
    fragment: Optional[str] = None,
    userinfo: Optional[str] = None,
) -> str:
    """Build a URL string from components.

    Args:
        scheme: URL scheme (e.g., 'https', 'http')
        host: Hostname or IP address
        port: Optional port number
        path: URL path (defaults to '/')
        query: Optional query string (without '?')
        fragment: Optional fragment (without '#')
        userinfo: Optional userinfo (user:pass format)

    Returns:
        The composed URL string.
    """
    return Builder().compose({
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
        "userinfo": userinfo,
    })


def compose_url(components: Mapping[str, Any]) -> str:
    """Compose a URL from components dict.

    Args:
        components: Dict with keys: scheme, host, port, path, query, fragment, userinfo

    Returns:
        The composed URL string.
    """
    return Builder().compose(components)


# Aliases for convenience
parse = parse_url  # Alias: parse() -> parse_url()
parse_strict = parse_url  # Alias: parse_strict() -> parse_url() (same since secure is default)


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",
    # Primary API
    "parse_url",
    "parse_url_unsafe",
    "parse_url_strict",  # Deprecated alias for parse_url
    "build",
    "compose_url",
    # Aliases
    "parse",  # Alias for parse_url
    "parse_strict",  # Alias for parse_url
    # URL class
    "URL",
    # Exceptions
    "URLpError",
    "InvalidURLError",
    "URLParseError",
    "URLBuildError",
    "UnsupportedSchemeError",
    "HostValidationError",
    "PortValidationError",
    "QueryParsingError",
    "FragmentEncodingError",
    "UserInfoParsingError",
    "MissingHostError",
    # Relative URL helpers
    "parse_relative_reference",
    "build_relative_reference",
    "round_trip_relative",
    # Audit
    "set_audit_callback",
    "get_audit_callback",
    # Validation
    "Validator",
    # Constants
    "MAX_URL_LENGTH",
    "MAX_SCHEME_LENGTH",
    "MAX_HOST_LENGTH",
    "MAX_PATH_LENGTH",
    "MAX_QUERY_LENGTH",
    "MAX_FRAGMENT_LENGTH",
    "MAX_USERINFO_LENGTH",
    "DEFAULT_DNS_TIMEOUT",
    "PASSWORD_MASK",
]

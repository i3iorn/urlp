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

def parse(url: str, *, strict: bool = False, check_dns: bool = False) -> URL:
    """Parse a URL string into a URL object.

    Args:
        url: The URL string to parse.
        strict: If True, reject SSRF risks (private IPs, localhost, etc.)
        check_dns: If True, perform DNS resolution to detect DNS rebinding.

    Returns:
        An immutable URL object.

    Raises:
        URLParseError: If the URL cannot be parsed.
        InvalidURLError: If the URL is invalid or poses security risks.
    """
    return URL(url, strict=strict, check_dns=check_dns)


def parse_strict(url: str, *, check_dns: bool = False) -> URL:
    """Parse URL with all security checks enabled.

    This is the recommended function for security-sensitive contexts.
    It enables:
    - SSRF protection (blocks private IPs, localhost, etc.)
    - Double-encoding detection
    - Path traversal detection
    - Open redirect detection
    - Homograph attack detection

    Args:
        url: The URL string to parse.
        check_dns: If True, also perform DNS resolution checks.

    Returns:
        An immutable URL object.

    Raises:
        InvalidURLError: If the URL fails any security check.
    """
    validate_url_security(url)
    return URL(url, strict=True, check_dns=check_dns)


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


# =============================================================================
# Backward Compatibility
# =============================================================================

def parse_url(
    url: str, *,
    frozen: bool = False,
    allow_custom_scheme: bool = False,
    strict: bool = False,
    debug: bool = False,
    check_dns: bool = False
) -> URL:
    """Parse a URL string (backward compatibility).

    Prefer using `parse()` or `parse_strict()` instead.
    """
    parser = Parser()
    parser.custom_scheme = allow_custom_scheme
    return URL(url, parser=parser, strict=strict, debug=debug, check_dns=check_dns)


def parse_url_strict(
    url: str, *,
    frozen: bool = True,
    allow_custom_scheme: bool = False,
    check_dns: bool = False
) -> URL:
    """Parse URL with security defaults (backward compatibility).

    Prefer using `parse_strict()` instead.
    """
    validate_url_security(url)
    parser = Parser()
    parser.custom_scheme = allow_custom_scheme
    return URL(url, parser=parser, strict=True, check_dns=check_dns)


def compose_url(components: Mapping[str, Any]) -> str:
    """Compose a URL from components dict (backward compatibility).

    Prefer using `build()` instead.
    """
    return Builder().compose(components)


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",
    # New API
    "parse",
    "parse_strict",
    "build",
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
    # Backward compatibility
    "parse_url",
    "parse_url_strict",
    "compose_url",
]

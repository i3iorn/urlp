"""urlp - Lightweight, secure, and RFC-compliant URL parsing and building.

Quick start:
    >>> from urlp import parse_url, build
    >>> url = parse_url("https://example.com/path?query=value")
    >>> url.host
    'example.com'
    >>> build("https", "example.com", path="/api", query="v=1")
    'https://example.com/api?v=1'

Main entry points:
    - parse_url: Secure parsing with SSRF, phishing, and traversal protection
    - parse_url_unsafe: Parsing without security checks (trusted sources only)
    - build: Build a URL string from components
    - compose_url: Build a URL string from a dict of components
    - URL: Immutable URL object with manipulation methods
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

__version__ = "0.3.0"

# Exceptions (only essential ones exported)
from .exceptions import (
    InvalidURLError,
    URLpError,
    URLParseError,
    URLBuildError,
)

# URL class and audit callbacks
from .url import URL, set_audit_callback, get_audit_callback

# Internal imports (used by public functions, not re-exported)
from ._parser import Parser
from ._builder import Builder
from ._security import validate_url_security


# =============================================================================
# Public API Functions
# =============================================================================

def parse_url(
    url: str, *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False,
    check_phishing: bool = False
) -> URL:
    """Parse URL with security checks enabled (SECURE BY DEFAULT).

    This is the recommended function for parsing URLs. It enables:
    - SSRF protection (blocks private IPs, localhost, etc.)
    - Double-encoding detection
    - Path traversal detection
    - Open redirect detection
    - Homograph attack detection
    - Phishing domain checks (if enabled) (https://phish.co.za/latest/ALL-phishing-domains.lst)

    For parsing URLs without security checks (e.g., internal/development URLs),
    use `parse_url_unsafe()` instead.

    Args:
        url: The URL string to parse.
        allow_custom_scheme: If True, allow non-standard schemes.
        check_dns: If True, also perform DNS resolution checks.
        check_phishing: If True, check for known phishing domains.

    Returns:
        An immutable URL object.

    Raises:
        InvalidURLError: If the URL fails any security check.
    """
    validate_url_security(url)
    parser = Parser()
    parser.custom_scheme = allow_custom_scheme
    return URL(url, parser=parser, strict=True, check_dns=check_dns, check_phishing=check_phishing)


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



def build(
    *scheme_and_host: str,
    port: Optional[int] = None,
    path: str = "/",
    query: Optional[str] = None,
    fragment: Optional[str] = None,
    userinfo: Optional[str] = None,
) -> str:
    """Build a URL string from components.

    Args:
        scheme_and_host: Variable arguments for scheme and host.
            If one argument is provided, it's treated as host only.
            If two or more arguments are provided, the first is scheme, second is host,
            remaining are ignored.
        port: Optional port number
        path: URL path (defaults to '/')
        query: Optional query string (without '?')
        fragment: Optional fragment (without '#')
        userinfo: Optional userinfo (user:pass format)

    Returns:
        The composed URL string.
    """
    if len(scheme_and_host) == 1:
        scheme = None
        host = scheme_and_host[0]
    elif len(scheme_and_host) >= 2:
        scheme, host, *_ = scheme_and_host
    else:
        raise URLBuildError("At least host must be provided to build a URL.")

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


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",
    # Primary API - Parsing
    "parse_url",
    "parse_url_unsafe",
    # Primary API - Building
    "build",
    "compose_url",
    # URL class
    "URL",
    # Exceptions
    "URLpError",
    "InvalidURLError",
    "URLParseError",
    "URLBuildError",
    # Audit callbacks
    "set_audit_callback",
    "get_audit_callback",
]

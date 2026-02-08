"""urlps - Lightweight, secure, and RFC-compliant URL parsing and building.

Quick start:
    >>> from urlps import parse_url, build
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
import importlib

__version__ = "0.4.0"

from urlps._audit import set_audit_callback, get_audit_callback
from urlps.exceptions import URLpError, InvalidURLError, URLParseError, URLBuildError
from urlps.url import URL



def parse_url(
    url: str, *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False,
    check_phishing: bool = False
) -> "URL":
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
    """
    from . import _security as _security
    from . import _parser as _parser
    from . import url as _url

    _security.validate_url_security(url)
    parser = _parser.Parser()
    parser.custom_scheme = allow_custom_scheme
    return _url.URL(url, parser=parser, strict=True, check_dns=check_dns, check_phishing=check_phishing)


def parse_url_unsafe(
    url: str, *,
    allow_custom_scheme: bool = False,
    strict: bool = False,
    debug: bool = False,
    check_dns: bool = False
) -> "URL":
    """Parse a URL string WITHOUT security checks.

    WARNING: This function does not perform security validations by default.
    Use `parse_url()` instead for security-sensitive contexts.
    """
    from . import _parser as _parser
    from . import url as _url

    parser = _parser.Parser()
    parser.custom_scheme = allow_custom_scheme
    return _url.URL(url, parser=parser, strict=strict, debug=debug, check_dns=check_dns)



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
    from . import _builder as _builder

    if len(scheme_and_host) == 1:
        scheme = None
        host = scheme_and_host[0]
    elif len(scheme_and_host) >= 2:
        scheme, host, *_ = scheme_and_host
    else:
        from .exceptions import URLBuildError
        raise URLBuildError("At least host must be provided to build a URL.")

    return _builder.Builder().compose({
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
    from . import _builder as _builder
    return _builder.Builder().compose(components)



def get_cache_info() -> dict:
    """Get statistics about all internal caches.

    Returns a dictionary with cache statistics for performance-critical functions:
    - Parser caches (path normalization)
    - Validation caches (scheme, host, IP validation)
    - Security caches (SSRF detection, mixed scripts)
    - Builder caches (percent encoding, query encoding)

    Returns:
        Dictionary mapping module names to their cache statistics.

    Example:
        >>> info = get_cache_info()
        >>> info['parser']['normalize_path']['hits']
        450
    """
    from . import _parser, _validation, _security, _builder

    return {
        'parser': _parser.get_cache_info(),
        'validation': _validation.Validator.get_cache_info(),
        'security': _security.get_cache_info(),
        'builder': {
            'percent_encode': _builder.Builder._percent_encode_cached.cache_info()._asdict()
                if hasattr(_builder.Builder._percent_encode_cached, 'cache_info') else None,
            'encode_for_query': _builder._encode_for_query.cache_info()._asdict()
                if hasattr(_builder._encode_for_query, 'cache_info') else None,
        }
    }


def clear_all_caches() -> dict:
    """Clear all internal caches and return previous sizes.

    This can be useful for:
    - Memory management in long-running applications
    - Testing to ensure fresh state
    - Resetting after processing a large batch of URLs

    Returns:
        Dictionary mapping module names to previous cache sizes.

    Example:
        >>> previous = clear_all_caches()
        >>> previous['parser']['normalize_path']
        127
    """
    from . import _parser, _validation, _security, _builder

    previous = {
        'parser': _parser.clear_caches(),
        'validation': _validation.Validator.clear_caches(),
        'security': _security.clear_caches(),
        'builder': {}
    }

    if hasattr(_builder.Builder._percent_encode_cached, 'cache_clear'):
        previous['builder']['percent_encode'] = _builder.Builder._percent_encode_cached.cache_info().currsize
        _builder.Builder._percent_encode_cached.cache_clear()

    if hasattr(_builder._encode_for_query, 'cache_clear'):
        previous['builder']['encode_for_query'] = _builder._encode_for_query.cache_info().currsize
        _builder._encode_for_query.cache_clear()

    return previous


__all__ = [
    "__version__",
    "parse_url",
    "parse_url_unsafe",
    "build",
    "compose_url",
    "URL",
    "URLpError",
    "InvalidURLError",
    "URLParseError",
    "URLBuildError",
    "set_audit_callback",
    "get_audit_callback",
    "get_cache_info",
    "clear_all_caches",
]

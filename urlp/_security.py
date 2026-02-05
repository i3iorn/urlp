"""Unified security checks for URL validation (SSRF, path traversal, homograph attacks)."""
from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from typing import Optional, Set, Tuple, Union
from urllib import request
from urllib.error import URLError
from urllib.parse import unquote

from .constants import BLOCKED_HOSTNAMES, DEFAULT_DNS_TIMEOUT
from ._patterns import PATTERNS


# =============================================================================
# IP Address Safety Checks
# =============================================================================

def _is_ip_safe(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if IP is safe (not private/reserved)."""
    return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local)


def _check_ipv4_private(host: str) -> bool:
    """Check if IPv4 address is private/reserved."""
    try:
        return not _is_ip_safe(ipaddress.IPv4Address(host))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _check_ipv6_private(host: str) -> bool:
    """Check if IPv6 address (bracketed) is private/reserved."""
    if not host.startswith("[") or not host.endswith("]"):
        return False
    try:
        inner = _strip_ipv6_brackets(host)
        return not _is_ip_safe(ipaddress.IPv6Address(inner))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _strip_ipv6_brackets(host: str) -> str:
    """Strip brackets and zone ID from IPv6 address."""
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
        if '%25' in host:
            host, _, _ = host.partition('%25')
    return host


# =============================================================================
# SSRF Detection Helpers
# =============================================================================

def _is_blocked_hostname(host_lower: str) -> bool:
    """Check if hostname is in the blocklist."""
    if host_lower in BLOCKED_HOSTNAMES:
        return True
    return host_lower.endswith('.local') or host_lower.endswith('.localhost') or host_lower.endswith('.internal')


def _is_ipv4_mapped_ipv6(host_lower: str) -> bool:
    """Check for IPv4-mapped IPv6 addresses."""
    return host_lower.startswith('[::ffff:')


def _parse_ip_octet(part: str) -> Optional[int]:
    """Parse IP octet in decimal, octal, or hex format."""
    part_lower = part.lower()
    try:
        if part_lower.startswith('0x'):
            return int(part_lower, 16)
        elif part.startswith('0') and len(part) > 1 and part.isdigit():
            return int(part, 8)
        elif part.isdigit():
            return int(part)
    except ValueError:
        pass
    return None


def _is_decimal_ip_private(host: str) -> bool:
    """Check decimal IP format (e.g., 2130706433 = 127.0.0.1)."""
    if not host.isdigit():
        return False
    try:
        decimal_ip = int(host)
        if 0 <= decimal_ip <= 0xFFFFFFFF:
            ip_str = '.'.join(str(b) for b in decimal_ip.to_bytes(4, 'big'))
            return not _is_ip_safe(ipaddress.IPv4Address(ip_str))
    except (ValueError, OverflowError, ipaddress.AddressValueError):
        pass
    return False


def _is_octal_hex_ip_private(host: str) -> bool:
    """Check octal/hex IP format (e.g., 0177.0.0.1)."""
    if '.' not in host:
        return False
    parts = host.split('.')
    if len(parts) != 4:
        return False
    octets = []
    for part in parts:
        octet = _parse_ip_octet(part)
        if octet is None:
            return False
        octets.append(octet)
    if not all(0 <= o <= 255 for o in octets):
        return False
    try:
        return not _is_ip_safe(ipaddress.IPv4Address('.'.join(str(o) for o in octets)))
    except (ValueError, ipaddress.AddressValueError):
        return False


# =============================================================================
# DNS Resolution Safety
# =============================================================================

def _check_direct_ip_safe(host: str) -> Optional[bool]:
    """Check if host is a direct IP and if it's safe. Returns None if not IP."""
    try:
        return _is_ip_safe(ipaddress.ip_address(host))
    except ValueError:
        return None


def _check_resolved_ips_safe(addr_info) -> bool:
    """Check if all resolved IPs are safe."""
    for family, socktype, proto, _, sockaddr in addr_info:
        try:
            if not _is_ip_safe(ipaddress.ip_address(sockaddr[0])):
                return False
        except ValueError:
            continue
    return True


def _verify_connection_safe(addr_info, timeout: float) -> bool:
    """Verify connection is safe against DNS rebinding."""
    if not addr_info:
        return True
    family, socktype, proto, _, sockaddr = addr_info[0]
    test_sock = socket.socket(family, socktype, proto)
    try:
        test_sock.settimeout(timeout)
        test_sock.connect(sockaddr)
        try:
            return _is_ip_safe(ipaddress.ip_address(test_sock.getpeername()[0]))
        except ValueError:
            return True
    except (socket.timeout, OSError):
        return True
    finally:
        test_sock.close()


# =============================================================================
# Public Security Check Functions
# =============================================================================

@lru_cache(maxsize=512)
def is_private_ip(host: str) -> bool:
    """Check if host is a private/reserved IP address."""
    if not isinstance(host, str):
        return False
    return _check_ipv4_private(host) or _check_ipv6_private(host)


@lru_cache(maxsize=512)
def is_ssrf_risk(host: str) -> bool:
    """Check if host poses SSRF risk (blocked hostnames, private IPs, etc.)."""
    if not isinstance(host, str) or not host:
        return False
    host_lower = host.lower().rstrip('.')
    return (_is_blocked_hostname(host_lower) or _is_ipv4_mapped_ipv6(host_lower) or
            _is_decimal_ip_private(host) or _is_octal_hex_ip_private(host) or is_private_ip(host))


def check_dns_rebinding(host: str, timeout: Optional[float] = None) -> bool:
    """Check if hostname resolves to safe (non-private) IPs."""
    if not isinstance(host, str) or not host:
        return False
    if timeout is None:
        timeout = DEFAULT_DNS_TIMEOUT
    host = _strip_ipv6_brackets(host)
    direct_result = _check_direct_ip_safe(host)
    if direct_result is not None:
        return direct_result
    try:
        addr_info = socket.getaddrinfo(host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not _check_resolved_ips_safe(addr_info):
            return False
        return _verify_connection_safe(addr_info, timeout)
    except (socket.gaierror, socket.timeout, OSError):
        return False

PHISHING_SET: Optional[Set[str]] = None

def check_against_phishing_db(host: str) -> bool:
    """Check if hostname is in known phishing database."""
    global PHISHING_SET
    if PHISHING_SET is None:
        PHISHING_SET = _download_phishing_db()
    if not isinstance(host, str):
        return False
    host_lower = host.lower().rstrip('.')
    return host_lower in PHISHING_SET


def refresh_phishing_db() -> int:
    """Refresh the phishing database cache.

    Forces a re-download of the phishing database from the remote source.
    This is useful for long-running applications that need fresh data.

    Returns:
        The number of hostnames in the refreshed database.

    Example:
        >>> refresh_phishing_db()
        12345
    """
    global PHISHING_SET
    PHISHING_SET = _download_phishing_db()
    return len(PHISHING_SET)


def get_phishing_db_info() -> dict:
    """Get information about the current phishing database cache.

    Returns:
        Dict containing:
            - loaded: Whether the database has been loaded
            - size: Number of hostnames in the database (0 if not loaded)
    """
    return {
        "loaded": PHISHING_SET is not None,
        "size": len(PHISHING_SET) if PHISHING_SET is not None else 0,
    }


def _download_phishing_db() -> Set[str]:
    """Download and return a set of known phishing hostnames."""
    PHISHING_DB_URL = "https://phish.co.za/latest/ALL-phishing-domains.lst"
    try:
        response = request.urlopen(PHISHING_DB_URL, timeout=DEFAULT_DNS_TIMEOUT)
        if response.status != 200:
            return set()
        content = response.read().decode('utf-8', errors='ignore')
        hostnames = {line.strip().lower() for line in content.splitlines() if line.strip()}
        return hostnames
    except (URLError, socket.timeout, OSError, ValueError):
        return set()


def has_mixed_scripts(host: str) -> bool:
    """Detect potential homograph attacks using mixed Unicode scripts."""
    if not isinstance(host, str):
        return False
    try:
        import unicodedata
        scripts: Set[str] = set()
        tracked = frozenset({'LATIN', 'CYRILLIC', 'GREEK', 'ARMENIAN', 'HEBREW',
                            'ARABIC', 'THAI', 'HANGUL', 'HIRAGANA', 'KATAKANA', 'CJK'})
        for char in host:
            if char.isalpha():
                name = unicodedata.name(char, '')
                if name:
                    script = name.split()[0]
                    if script in tracked:
                        scripts.add(script)
        return len(scripts) > 1
    except (ValueError, KeyError):
        return False


def has_double_encoding(value: str) -> bool:
    """Detect potential double-encoding attacks."""
    if not isinstance(value, str):
        return False
    return bool(PATTERNS["double_encode"].search(value))


def has_path_traversal(path: str) -> bool:
    """Detect path traversal attempts (.., null bytes, encoded variants)."""
    if not isinstance(path, str):
        return False
    if '..' in path or '\x00' in path:
        return True
    try:
        decoded = unquote(path)
        if '..' in decoded or '\x00' in decoded:
            return True
        if '..' in unquote(decoded):
            return True
    except (ValueError, UnicodeDecodeError):
        pass
    return False


def is_open_redirect_risk(path: str) -> bool:
    """Check if path could cause an open redirect (//, backslash)."""
    if not isinstance(path, str):
        return False
    return '\\' in path or path.startswith('//')


def extract_host_and_path(url: str) -> Tuple[str, str]:
    """Extract host and path portions from URL for security checks."""
    if '://' not in url:
        return "", ""
    after_scheme = url.split('://', 1)[1]
    if '/' in after_scheme:
        host_portion = after_scheme.split('/', 1)[0]
        path_portion = after_scheme[after_scheme.find('/'):]
    else:
        host_portion, path_portion = after_scheme, ""
    if '@' in host_portion:
        host_portion = host_portion.split('@', 1)[1]
    if ':' in host_portion and not host_portion.startswith('['):
        host_portion = host_portion.split(':', 1)[0]
    elif host_portion.startswith('[') and ']:' in host_portion:
        host_portion = host_portion.split(']:', 1)[0] + ']'
    if path_portion:
        path_portion = path_portion.split('?', 1)[0].split('#', 1)[0]
    return host_portion, path_portion


def validate_url_security(url: str) -> None:
    """Run comprehensive security validations. Raises InvalidURLError if issue detected."""
    from .exceptions import InvalidURLError
    if has_double_encoding(url):
        raise InvalidURLError("URL contains double-encoded characters.")
    if '://' not in url:
        return
    host, path = extract_host_and_path(url)
    if host and has_mixed_scripts(host):
        raise InvalidURLError("URL host contains mixed Unicode scripts.")
    if path:
        if has_path_traversal(path):
            raise InvalidURLError("URL path contains path traversal patterns.")
        if is_open_redirect_risk(path):
            raise InvalidURLError("URL path contains open redirect risk patterns.")


# Cache management
_CACHED_FUNCTIONS = [is_private_ip, is_ssrf_risk]


def get_cache_info() -> dict:
    """Get statistics about security check caches."""
    return {f.__wrapped__.__name__: {'hits': f.cache_info().hits, 'misses': f.cache_info().misses,
                         'maxsize': f.cache_info().maxsize, 'currsize': f.cache_info().currsize}
            for f in _CACHED_FUNCTIONS if hasattr(f, 'cache_info')}


def clear_caches() -> dict:
    """Clear all security caches and return previous sizes."""
    previous = {f.__wrapped__.__name__: f.cache_info().currsize for f in _CACHED_FUNCTIONS if hasattr(f, 'cache_info')}
    for f in _CACHED_FUNCTIONS:
        if hasattr(f, 'cache_clear'):
            f.cache_clear()
    return previous


__all__ = [
    "is_ssrf_risk", "is_private_ip", "check_dns_rebinding", "has_mixed_scripts",
    "has_double_encoding", "has_path_traversal", "is_open_redirect_risk",
    "extract_host_and_path", "validate_url_security", "get_cache_info", "clear_caches",
    "check_against_phishing_db", "refresh_phishing_db", "get_phishing_db_info",
]

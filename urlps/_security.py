"""Unified security checks for URL validation (SSRF, path traversal, homograph attacks)."""
from __future__ import annotations

import ipaddress
import socket
import unicodedata
from functools import lru_cache
from typing import Optional, Set, Tuple, Union
from urllib import request
from urllib.error import URLError
from urllib.parse import unquote

from .constants import BLOCKED_HOSTNAMES, DEFAULT_DNS_TIMEOUT, DANGEROUS_PORTS
from ._patterns import PATTERNS


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


@lru_cache(maxsize=512)
def has_mixed_scripts(host: str) -> bool:
    """Detect potential homograph attacks using mixed Unicode scripts.

    Performance: LRU cached and with fast-path for ASCII-only hosts.
    """
    if not isinstance(host, str):
        return False
    try:
        host.encode('ascii')
        return False
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass

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


def is_malicious_ipv6_zone_id(host: str) -> bool:
    """Check if IPv6 zone identifier contains malicious content.

    Zone identifiers should only contain alphanumeric characters, dash, underscore,
    dot, and tilde per RFC 6874.
    """
    if not isinstance(host, str):
        return False

    if '%25' not in host and '%' not in host:
        return False

    if not (host.startswith('[') and ']' in host):
        return False

    try:
        inner = host[1:host.index(']')]
        if '%25' in inner or '%' in inner:
            zone_id = inner.split('%25' if '%25' in inner else '%', 1)[1]
            if not zone_id:
                return True
            for char in zone_id:
                if not (char.isalnum() or char in '-_.~'):
                    return True
    except (ValueError, IndexError):
        return True

    return False


def has_parser_confusion(url: str) -> bool:
    """Detect ambiguous URLs that could be parsed differently by different parsers.

    Detects:
    - Multiple @ signs in authority (not counting @ within password)
    - Backslash in authority section
    - Mixed separators (forward slash + backslash)
    - Special characters before @ that might confuse parsers
    """
    if not isinstance(url, str):
        return False

    if '://' not in url:
        return False

    after_scheme = url.split('://', 1)[1]

    if '\\' in after_scheme:
        return True

    if '@' not in after_scheme:
        return False

    before_at_last = after_scheme.rsplit('@', 1)[0]

    if any(char in before_at_last for char in ['/', '#', '?']):
        return True

    if '@' in before_at_last:
        return True

    return False


def has_suspicious_punycode(host: str) -> bool:
    """Detect suspicious Punycode/IDN domains with confusable characters.

    Internationalized Domain Names (IDN) using Punycode encoding can be abused
    for phishing attacks via homograph attacks. This function detects:

    1. Mixed scripts in decoded IDN (e.g., Latin + Cyrillic)
    2. Confusable character combinations (e.g., 'rn' looks like 'm')
    3. Suspicious TLDs commonly used in phishing
    4. All-numeric domain names in non-ASCII
    5. Excessive use of dashes/hyphens (common in phishing)

    Args:
        host: The hostname to check (may be punycode-encoded or decoded)

    Returns:
        True if suspicious patterns are detected, False otherwise

    Examples:
        >>> has_suspicious_punycode("xn--pple-43d.com")  # аpple (Cyrillic 'а')
        True
        >>> has_suspicious_punycode("example.com")
        False
        >>> has_suspicious_punycode("раура1.com")  # paypal with Cyrillic
        True
    """
    if not isinstance(host, str) or not host:
        return False

    host_lower = host.lower()

    # Check if it's a punycode domain
    is_punycode = 'xn--' in host_lower

    # Decode punycode if present
    decoded_host = host_lower
    if is_punycode:
        try:
            # Decode each label separately
            labels = host_lower.split('.')
            decoded_labels = []
            for label in labels:
                if label.startswith('xn--'):
                    try:
                        decoded = label.encode('ascii').decode('idna')
                        decoded_labels.append(decoded)
                    except (UnicodeError, UnicodeDecodeError):
                        decoded_labels.append(label)
                else:
                    decoded_labels.append(label)
            decoded_host = '.'.join(decoded_labels)
        except (UnicodeError, UnicodeDecodeError, ValueError):
            # If decoding fails, it might be malformed
            return True

    # Check for mixed scripts (already implemented, but check decoded version)
    if has_mixed_scripts(decoded_host):
        return True

    # Extract TLD
    parts = decoded_host.split('.')
    if len(parts) < 2:
        return False

    tld = parts[-1]
    domain = parts[-2] if len(parts) >= 2 else ''

    # Suspicious TLDs commonly used in phishing
    # These are legitimate TLDs but frequently abused
    suspicious_tlds = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains
        'pw', 'top', 'work', 'click', 'link',  # Cheap domains
        'xyz', 'loan', 'win', 'bid', 'racing',
        'download', 'stream', 'science', 'accountant',
    }

    # If it's punycode with a suspicious TLD, flag it
    if is_punycode and tld in suspicious_tlds:
        return True

    # Check for confusable character combinations
    # These are character pairs that look very similar
    confusable_pairs = [
        ('rn', 'm'),  # rn looks like m
        ('vv', 'w'),  # vv looks like w
        ('cl', 'd'),  # cl looks like d in some fonts
        ('l1', 'l1'),  # l and 1 look similar
        ('0o', '0o'),  # 0 and o look similar
    ]

    # Check domain name (not TLD) for confusables
    for pair in confusable_pairs:
        if pair[0] in domain:
            # Check if it might be intentionally confusing
            # e.g., "paypa1" (using 1 instead of l)
            return True

    # Check for excessive hyphens (common in phishing)
    # Legitimate domains rarely have more than 2 hyphens
    if domain.count('-') > 2:
        return True

    # Check for suspicious patterns: mixing ASCII digits with non-ASCII letters
    has_digits = any(c.isdigit() for c in domain)
    has_non_ascii = False
    try:
        domain.encode('ascii')
    except (UnicodeEncodeError, UnicodeDecodeError):
        has_non_ascii = True

    if has_digits and has_non_ascii:
        # Common phishing pattern: раура1.com (mixing Cyrillic with digits)
        return True

    # Check for all-numeric domain in non-ASCII
    # This is highly suspicious
    if has_non_ascii:
        # Remove common punctuation
        domain_no_punct = domain.replace('-', '').replace('_', '')
        if domain_no_punct and all(c.isdigit() for c in domain_no_punct if c.isalnum()):
            return True

    # Check for known brand impersonation patterns
    # Common brands that are frequently targeted
    common_brands = [
        'paypal', 'google', 'amazon', 'apple', 'microsoft',
        'facebook', 'twitter', 'instagram', 'netflix', 'ebay',
        'bank', 'secure', 'login', 'account', 'verify',
    ]

    # If domain contains a brand name and non-ASCII, it's suspicious
    if has_non_ascii:
        for brand in common_brands:
            # Check if brand appears with possible character substitution
            # This is a simplified check
            if brand in decoded_host.lower():
                return True

    return False


def has_query_injection(query_string: str) -> bool:
    """Detect potential XSS/injection patterns in query strings.

    Query parameters are a common injection vector for various attacks:
    - Cross-Site Scripting (XSS): <script>, onerror=, javascript:
    - SQL Injection: UNION SELECT, OR 1=1, DROP TABLE
    - Command Injection: |, &&, ;, $(...)
    - LDAP Injection: *, )(, |
    - XML Injection: <!, CDATA, DOCTYPE

    This function detects common injection patterns but should NOT be used
    as the sole defense. Always use proper input validation, output encoding,
    and parameterized queries/prepared statements.

    Args:
        query_string: The query string portion of a URL (without leading ?)

    Returns:
        True if suspicious patterns are detected, False otherwise

    Examples:
        >>> has_query_injection("q=<script>alert(1)</script>")
        True
        >>> has_query_injection("name=John&age=25")
        False
        >>> has_query_injection("id=1' OR '1'='1")
        True
    """
    if not isinstance(query_string, str) or not query_string:
        return False

    # Normalize to lowercase for pattern matching
    query_lower = query_string.lower()

    # Also check a version with spaces normalized for patterns that might use whitespace
    # to evade detection (e.g., "UNION  SELECT" or "UNION%20SELECT")
    query_normalized = query_lower.replace('%20', ' ').replace('%09', ' ').replace('%0a', ' ')
    # Collapse multiple spaces
    while '  ' in query_normalized:
        query_normalized = query_normalized.replace('  ', ' ')

    # XSS patterns
    xss_patterns = [
        '<script', '</script', 'javascript:', 'onerror=', 'onload=',
        'onclick=', 'onmouseover=', '<iframe', '<object', '<embed',
        'vbscript:', 'data:text/html', '<img', 'src=', '<body',
        'onfocus=', 'onblur=', '<svg', 'onanimation', '<input',
    ]

    # SQL injection patterns
    sql_patterns = [
        'union select', 'union all select', "' or '", '" or "',
        "' or 1=1", '" or 1=1', "' and '", '" and "', "' and 1=1", '" and 1=1',
        'drop table', 'delete from', 'insert into', 'update set',
        '--', '/*', '*/', 'exec(', 'execute(', 'xp_cmdshell', 'sp_executesql',
        'sleep(', 'waitfor', 'benchmark(',
    ]

    # Command injection patterns
    cmd_patterns = [
        '$(', '`', '&&', '||', '; rm', ';rm ', ';cat ', '|cat', '|nc',
        '/bin/', '/etc/passwd', '/etc/shadow', 'cmd.exe', 'powershell',
    ]

    # LDAP injection patterns
    ldap_patterns = ['*)(', '(|', '(&', '(cn=*)']

    # XML/XXE patterns
    xml_patterns = ['<!entity', '<!doctype', '<![cdata[', '<?xml']

    # Path traversal in query (additional check)
    traversal_patterns = ['../', '..\\', '%2e%2e/', '%2e%2e\\', '%2e%2e%2f', '%2e%2e%5c']

    # Check all patterns in both original and normalized versions
    all_patterns = xss_patterns + sql_patterns + cmd_patterns + ldap_patterns + xml_patterns + traversal_patterns

    for pattern in all_patterns:
        if pattern in query_lower or pattern in query_normalized:
            return True

    # Check for encoded variations of dangerous characters
    # These might bypass simple filters but indicate potential injection
    encoded_patterns = [
        '%3c',  # <
        '%3e',  # >
        '%27',  # '
        '%22',  # "
        '%3b',  # ;
        '%7c',  # |
        '%26%26',  # &&
        '%7c%7c',  # ||
    ]

    for pattern in encoded_patterns:
        if pattern in query_lower:
            # Additional check: look for suspicious context
            # (e.g., %3cscript is suspicious, %3cvalue%3e might be legitimate)
            if pattern in ['%3c', '%3e']:  # < and >
                # Check if followed by common XSS keywords
                idx = query_lower.find(pattern)
                if idx != -1 and idx + len(pattern) < len(query_lower):
                    following = query_lower[idx + len(pattern):idx + len(pattern) + 10]
                    if any(kw in following for kw in ['script', 'iframe', 'object', 'svg', 'body', 'img']):
                        return True
            elif pattern in ['%27', '%22']:  # ' and "
                # Check for SQL-like patterns around quotes
                idx = query_lower.find(pattern)
                if idx != -1:
                    context = query_lower[max(0, idx - 10):min(len(query_lower), idx + 20)]
                    if any(kw in context for kw in ['or', 'and', 'union', 'select', '1=1']):
                        return True
            else:
                # Other encoded chars are suspicious enough on their own
                return True

    return False


def has_credentials(url: str) -> bool:
    """Detect URLs containing credentials (userinfo) in the authority component.

    URLs with embedded credentials pose security risks:
    - Credentials may be logged in plaintext
    - Browser history/cache exposure
    - Network logs and monitoring tools
    - Referrer header leakage
    - MITM attacks if transmitted over HTTP

    RFC 3986 allows userinfo (username:password@host) but it's deprecated
    for security reasons. Modern applications should use proper authentication
    mechanisms (OAuth, tokens, etc.) instead of embedding credentials in URLs.

    Args:
        url: The URL string to check

    Returns:
        True if credentials are detected, False otherwise

    Examples:
        >>> has_credentials("http://user:pass@example.com/path")
        True
        >>> has_credentials("http://example.com/path")
        False
        >>> has_credentials("ftp://admin@ftp.example.com")
        True
    """
    if not isinstance(url, str):
        return False

    # Must have a scheme to have authority component
    if '://' not in url:
        return False

    # Extract authority component (everything between :// and first / or end)
    after_scheme = url.split('://', 1)[1]

    # Split on first / to get authority
    if '/' in after_scheme:
        authority = after_scheme.split('/', 1)[0]
    else:
        authority = after_scheme.split('?', 1)[0].split('#', 1)[0]

    # Check for @ sign which indicates userinfo
    return '@' in authority


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


def is_dangerous_port(port: Optional[int], block_dangerous_ports: bool = False) -> bool:
    """Check if port is commonly exploited.

    Args:
        port: Port number to check
        block_dangerous_ports: If True, block ports in DANGEROUS_PORTS set

    Returns:
        True if port should be blocked, False otherwise
    """
    if not block_dangerous_ports or port is None:
        return False
    return port in DANGEROUS_PORTS


def normalize_url_unicode(url: str) -> str:
    """Normalize URL to NFC form to prevent normalization-based bypasses.

    This prevents "validate-then-normalize" vulnerabilities where attackers
    use Unicode tricks to bypass filters.
    """
    if not isinstance(url, str):
        return url
    try:
        return unicodedata.normalize('NFC', url)
    except (ValueError, TypeError):
        return url


def validate_url_security(url: str) -> None:
    """Run comprehensive security validations. Raises InvalidURLError if issue detected.

    Performance: Fast-path for pure ASCII URLs skips expensive Unicode checks.
    """
    from .exceptions import InvalidURLError

    url = normalize_url_unicode(url)

    is_ascii = True
    try:
        url.encode('ascii')
    except (UnicodeEncodeError, UnicodeDecodeError):
        is_ascii = False

    if has_double_encoding(url):
        raise InvalidURLError("URL contains double-encoded characters.")
    if has_parser_confusion(url):
        raise InvalidURLError("URL contains ambiguous syntax that could cause parser confusion.")
    if '://' not in url:
        return
    host, path = extract_host_and_path(url)
    if host and is_malicious_ipv6_zone_id(host):
        raise InvalidURLError("IPv6 zone identifier contains invalid characters.")
    if host and not is_ascii and has_mixed_scripts(host):
        raise InvalidURLError("URL host contains mixed Unicode scripts.")
    if path:
        if has_path_traversal(path):
            raise InvalidURLError("URL path contains path traversal patterns.")
        if is_open_redirect_risk(path):
            raise InvalidURLError("URL path contains open redirect risk patterns.")


_CACHED_FUNCTIONS = [is_private_ip, is_ssrf_risk, has_mixed_scripts]


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
    "has_parser_confusion", "is_malicious_ipv6_zone_id", "normalize_url_unicode",
    "is_dangerous_port", "extract_host_and_path", "validate_url_security",
    "get_cache_info", "clear_caches",
    "check_against_phishing_db", "refresh_phishing_db", "get_phishing_db_info",
    "has_credentials", "has_query_injection", "has_suspicious_punycode",
]

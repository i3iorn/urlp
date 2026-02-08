# Security Enhancement Proposals for urlps

## Current Security Status

✅ **Already Implemented:**
- SSRF protection (private IPs, localhost, loopback, link-local)
- Path traversal detection (including encoded variants)
- Double-encoding detection
- Homograph attack detection (mixed Unicode scripts)
- Open redirect detection (// and backslash)
- DNS rebinding protection (optional)
- Phishing domain checking (optional)
- Component length limits (DoS prevention)
- IPv4-mapped IPv6 detection
- Decimal/octal/hex IP format detection

## Proposed Enhancements

### Priority 1: High Impact, Low Complexity

#### 1. Parser Confusion Attack Prevention
**Threat:** URL parsing discrepancies between validators and consumers ([PortSwigger Research](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet))

**Current Gap:** Multiple `@` signs can confuse parsers (e.g., `http://foo@evil.com:80@127.0.0.1/`)

**Implementation:**
```python
def detect_parser_confusion(url: str) -> bool:
    """Detect ambiguous URLs that could be parsed differently."""
    if not isinstance(url, str):
        return False

    # Multiple @ signs (authority confusion)
    if url.count('@') > 1:
        return True

    # Backslash in authority section (Windows path confusion)
    if '://' in url:
        after_scheme = url.split('://', 1)[1]
        authority = after_scheme.split('/', 1)[0] if '/' in after_scheme else after_scheme
        if '\\' in authority:
            return True

    # Mixed separators (forward slash + backslash)
    if '://' in url and ('\\' in url.split('://', 1)[1]):
        return True

    # Credentials with special chars that might confuse parsers
    if '@' in url and any(char in url.split('@', 1)[0] for char in ['/', '\\', '#', '?']):
        return True

    return False
```

**Impact:** Prevents parser confusion bypasses that could lead to SSRF or security filter evasion.

---

#### 2. Dangerous URL Scheme Blocking
**Threat:** Protocol-level exploitation ([SSRF Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/server-side-request-forgery))

**Current Gap:** Only blocks `javascript:`, `data:`, `vbscript:` when `allow_custom_scheme=False`

**Additional Dangerous Schemes:**
- `jar:` - Java JAR file access (can access local files)
- `file:` - Direct filesystem access
- `gopher:` - Can send arbitrary TCP payloads
- `dict:` - DICT protocol (can probe internal services)
- `ftp:` - FTP protocol (less common but risky)
- `tftp:` - TFTP protocol
- `ldap:` / `ldaps:` - LDAP queries (information disclosure)

**Implementation:**
```python
DANGEROUS_SCHEMES = frozenset({
    "javascript", "data", "vbscript",  # Already blocked
    "jar", "file", "gopher", "dict",    # New additions
    "tftp", "ldap", "ldaps",
})

# Add to constants.py and update scheme validation
```

**Impact:** Prevents protocol-level exploitation and local file access attacks.

---

#### 3. IPv6 Zone Identifier Validation
**Threat:** RFC 6874 zone identifier abuse ([SSRF Defense Article](https://windshock.github.io/en/post/2025-06-25-ssrf-defense/))

**Current Gap:** IPv6 addresses with zone identifiers like `[fe80::1%eth0]` might bypass filters

**Implementation:**
```python
def validate_ipv6_zone_identifier(host: str) -> bool:
    """Validate that IPv6 zone identifiers don't contain malicious content."""
    if '%25' in host or '%' in host:
        # Extract zone identifier
        if host.startswith('[') and ']' in host:
            inner = host[1:host.index(']')]
            if '%25' in inner or '%' in inner:
                zone_id = inner.split('%25' if '%25' in inner else '%', 1)[1]
                # Zone identifiers should only contain alphanumeric, dash, underscore, dot
                if not all(c.isalnum() or c in '-_.~' for c in zone_id):
                    return False
    return True
```

**Impact:** Prevents zone identifier abuse to access internal network interfaces.

---

#### 4. Unicode Normalization Before Validation
**Threat:** Unicode normalization attacks ([Research Paper](https://dl.acm.org/doi/10.1145/3696410.3714675), [InstaTunnel Blog](https://instatunnel.my/blog/unicode-normalization-attacks-when-admin-admin))

**Current Gap:** Not normalizing before validation can allow bypasses

**Implementation:**
```python
import unicodedata

def normalize_url_unicode(url: str) -> str:
    """Normalize URL to NFC form before validation."""
    if not isinstance(url, str):
        return url
    try:
        # Normalize to NFC (Canonical Decomposition followed by Canonical Composition)
        normalized = unicodedata.normalize('NFC', url)
        return normalized
    except (ValueError, TypeError):
        return url

# Apply in validate_url_security() BEFORE any checks
```

**Impact:** Prevents "validate-then-normalize" vulnerabilities where attackers use Unicode tricks to bypass filters.

---

### Priority 2: Medium Impact

#### 5. Enhanced Port Validation
**Threat:** Commonly exploited ports can be used for SSRF attacks

**Implementation:**
```python
# Dangerous ports that should be blocked in strict mode
DANGEROUS_PORTS = frozenset({
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    445,   # SMB
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    9200,  # Elasticsearch
    27017, # MongoDB
    11211, # Memcached
})

def is_dangerous_port(port: int, strict: bool = False) -> bool:
    """Check if port is commonly exploited."""
    if strict:
        return port in DANGEROUS_PORTS
    return False
```

**Impact:** Prevents SSRF attacks targeting internal services on well-known ports.

---

#### 6. Credential Leakage Detection
**Threat:** URLs containing credentials can leak via logs, referrers, etc.

**Implementation:**
```python
def has_credentials_in_url(url: str) -> bool:
    """Detect if URL contains credentials (security anti-pattern)."""
    if '@' not in url or '://' not in url:
        return False

    after_scheme = url.split('://', 1)[1]
    if '@' not in after_scheme:
        return False

    userinfo = after_scheme.split('@', 1)[0]
    # Check if it looks like credentials (contains : or common patterns)
    if ':' in userinfo or len(userinfo) > 3:
        return True

    return False

# Option 1: Warn (log)
# Option 2: Block entirely in strict mode
# Option 3: Auto-strip credentials and warn
```

**Impact:** Prevents accidental credential exposure.

---

#### 7. Query Parameter Injection Detection
**Threat:** Malicious content in query parameters

**Implementation:**
```python
def has_malicious_query_patterns(query: str) -> bool:
    """Detect potentially malicious patterns in query strings."""
    if not isinstance(query, str):
        return False

    malicious_patterns = [
        '<script',     # XSS
        'javascript:',  # XSS
        'on error',    # XSS event handler
        'onerror',     # XSS event handler
        '../',         # Path traversal
        '..\\',        # Path traversal (Windows)
        'file://',     # File scheme
        'data:',       # Data URI
    ]

    query_lower = query.lower()
    return any(pattern in query_lower for pattern in malicious_patterns)
```

**Impact:** Early detection of XSS and injection attempts.

---

#### 8. Enhanced Punycode/IDN Validation
**Threat:** Advanced homograph attacks beyond mixed scripts

**Implementation:**
```python
def has_confusable_characters(host: str) -> bool:
    """Detect visually confusable characters (beyond mixed scripts)."""
    # Common confusables
    confusable_pairs = [
        ('а', 'a'),  # Cyrillic a vs Latin a
        ('е', 'e'),  # Cyrillic e vs Latin e
        ('о', 'o'),  # Cyrillic o vs Latin o
        ('р', 'p'),  # Cyrillic r vs Latin p
        ('с', 'c'),  # Cyrillic s vs Latin c
        ('у', 'y'),  # Cyrillic u vs Latin y
        ('х', 'x'),  # Cyrillic h vs Latin x
        ('ı', 'i'),  # Turkish i vs Latin i
        ('ǀ', 'l'),  # Vertical line vs Latin l
        ('０', '0'), # Fullwidth 0 vs ASCII 0
    ]

    for cyrillic, latin in confusable_pairs:
        if cyrillic in host:
            return True

    return False

def has_suspicious_tld_combo(host: str) -> bool:
    """Detect suspicious TLD combinations."""
    # Common typosquatting patterns
    suspicious_patterns = [
        '.corn',  # Typo of .com
        '.cm',    # Typo of .com
        '.om',    # Typo of .com
        '.co',    # Can be legitimate but often typosquatting
    ]

    host_lower = host.lower()
    return any(host_lower.endswith(pattern) for pattern in suspicious_patterns)
```

**Impact:** Better protection against sophisticated phishing domains.

---

### Priority 3: Advanced Features

#### 9. Rate Limiting for DNS Checks
**Threat:** DoS via expensive DNS lookups

**Implementation:**
```python
from collections import defaultdict
from time import time

class DNSRateLimiter:
    def __init__(self, max_requests: int = 100, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self.requests = defaultdict(list)

    def can_check(self, host: str) -> bool:
        """Check if DNS lookup is allowed for this host."""
        now = time()
        # Clean old entries
        self.requests[host] = [t for t in self.requests[host] if now - t < self.window]

        if len(self.requests[host]) >= self.max_requests:
            return False

        self.requests[host].append(now)
        return True

# Global rate limiter instance
_dns_rate_limiter = DNSRateLimiter()
```

**Impact:** Prevents DoS attacks via repeated DNS checks.

---

#### 10. URL Canonical Form Validation
**Threat:** Ambiguous URLs that could be interpreted differently

**Implementation:**
```python
def is_canonical_url(url: str, parsed_url: URL) -> bool:
    """Check if URL is in canonical form (no ambiguities)."""
    # Reconstruct URL from parsed components
    canonical = parsed_url.as_string()

    # Normalize both for comparison
    url_normalized = url.lower().rstrip('/')
    canonical_normalized = canonical.lower().rstrip('/')

    # If they differ significantly, URL is ambiguous
    return url_normalized == canonical_normalized

def suggest_canonical_form(url: str) -> str:
    """Suggest canonical form of URL."""
    # Return canonicalized version
    return parse_url_unsafe(url).canonicalize().as_string()
```

**Impact:** Helps developers identify and fix ambiguous URLs.

---

## Implementation Priority

**Phase 1 (Immediate):**
1. Parser confusion detection
2. Dangerous scheme blocking expansion
3. IPv6 zone identifier validation

**Phase 2 (Short-term):**
4. Unicode normalization
5. Enhanced port validation
6. Credential leakage detection

**Phase 3 (Medium-term):**
7. Query parameter injection detection
8. Enhanced punycode validation
9. DNS rate limiting
10. Canonical form validation

## Testing Requirements

Each enhancement needs:
- Unit tests for bypass attempts
- Integration tests with existing security checks
- Performance benchmarks (especially for normalization)
- Documentation updates
- Security audit before release

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [SSRF Defense In-Depth](https://windshock.github.io/en/post/2025-06-25-ssrf-defense/)
- [URL Validation Bypass Cheat Sheet](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [ENS Normalization Security Research](https://dl.acm.org/doi/10.1145/3696410.3714675)
- [Unicode Normalization Attacks](https://instatunnel.my/blog/unicode-normalization-attacks-when-admin-admin)
- [HackTricks - URL Format Bypass](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)

## Backward Compatibility

All enhancements should be:
- Opt-in or behind feature flags initially
- Thoroughly tested for false positives
- Documented with migration guides
- Non-breaking for existing users

## Performance Considerations

- Unicode normalization adds ~5-10% overhead
- DNS rate limiting adds negligible overhead
- All new checks should be LRU cached where possible
- Consider adding `validate_paranoid()` mode for maximum security

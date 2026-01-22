# urlp

Lightweight URL parsing/building helpers with optional immutability controls and comprehensive security features. The library models RFC 3986 components, normalizes paths, percent-encodes where needed, and surfaces ergonomic helpers for working with userinfo/netloc metadata plus scheme-aware defaults.

**Security-focused features include:** SSRF protection, DNS rebinding detection, path traversal prevention, open redirect detection, homograph attack detection, double-encoding validation, and audit logging.

## Installation

```bash
pip install urlp
```

When hacking on the repo directly, create a virtual environment and install the local package in editable mode:

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -e .
```

## Highlights

- `Parser`, `Builder`, and `URL` classes for dissecting and composing URLs with validation.
- `URL.userinfo`, `.netloc`, and `.effective_port` expose the full authority state while keeping builder output canonical.
- `Parser.parse_netloc` and `URL.with_netloc()` allow focused authority updates without touching paths or queries.
- Scheme-specific defaults ensure absolute URLs emit `/` roots and infer well-known ports, while `SCHEMES_NO_PORT` guards against invalid combos.
- Relative-reference helpers (`parse_relative_reference`, `build_relative_reference`, `round_trip_relative`) round-trip scheme-less paths without applying path normalization.
- **Security Features:**
  - `strict` mode blocks SSRF risks (private IPs, localhost, link-local addresses)
  - `check_dns` flag detects DNS rebinding attacks via actual DNS resolution
  - Path traversal, open redirect, and double-encoding detection
  - Homograph attack prevention via mixed Unicode script detection
  - Audit logging callbacks for security monitoring
  - URL canonicalization for consistent security comparisons
  - Password masking to prevent credential leakage in logs

## Quick Start

Use the top-level helpers for common URL operations.

```python
from urlp import parse_url, parse_url_unsafe, build

# parse_url is SECURE BY DEFAULT - blocks SSRF risks, path traversal, etc.
url = parse_url("https://api.example.com/data?token=abc#section")
assert url.host == "api.example.com"
assert url.query_params == [("token", "abc")]

# This WILL RAISE an error (localhost blocked by default):
# parse_url("http://localhost/admin")  # InvalidURLError!

# Use parse_url_unsafe when you need to allow private IPs/localhost
internal_url = parse_url_unsafe("http://localhost:8080/api")
assert internal_url.host == "localhost"

# Build a URL string from components
url_str = build(
    "https",
    "example.com",
    port=8443,
    path="/api/data",
    query="x=1&x=2",
    fragment="section",
)
assert url_str == "https://example.com:8443/api/data?x=1&x=2#section"

# URLs are immutable - use with_* methods for modifications
url = parse_url("https://example.com/path")
new_url = url.with_host("other.com").with_port(8080)
print(new_url)  # https://other.com:8080/path
print(url)      # https://example.com/path (unchanged)
```

### Security by Default

`parse_url()` is secure by default and will reject:
- Private IPs (192.168.x.x, 10.x.x.x, 172.16.x.x)
- Localhost and loopback addresses
- Link-local addresses (169.254.x.x)
- `.local` and `.internal` domains
- Path traversal patterns (`../`)
- Double-encoded characters
- Mixed Unicode scripts (homograph attacks)

Use `parse_url_unsafe()` only when you explicitly need to allow these patterns.


## Usage

```python
from urlp import parse_url, parse_url_unsafe, parse_relative_reference, build_relative_reference

# parse_url is secure by default
url = parse_url("https://user:pass@example.com:8080/download?token=abc")
print(url.netloc)             # user:pass@example.com:8080
print(url.effective_port)     # 8080

# URLs are immutable - with_* methods return new URL objects
url2 = url.with_netloc("admin@example.com")
print(url2.as_string())       # https://admin@example.com/download?token=abc
print(url.as_string())        # Original unchanged

# Modify multiple components
url3 = url.with_host("other.com").with_port(443).with_path("/api")
print(url3.as_string())       # https://user:pass@other.com/api?token=abc

# Query parameter helpers
url4 = url.with_query_param("new", "value")
url5 = url.without_query_param("token")

# For internal/development URLs, use parse_url_unsafe
dev_url = parse_url_unsafe("http://localhost:3000/api")
internal = parse_url_unsafe("http://192.168.1.100/metrics")

# Relative references
parts = parse_relative_reference("./assets/logo.svg?cache=bust#hero")
rebuilt = build_relative_reference(parts["path"], query=parts["query"], fragment=parts["fragment"])
```

## Usage Examples and Edge Case Handling

### Basic Usage

```python
from urlp import parse_url, build

# Parse a standard URL
url = parse_url("https://user:pass@example.com:8080/download?token=abc")
print(url.netloc)             # user:pass@example.com:8080
print(url.effective_port)     # 8080

# Build a URL string from components
url_str = build(
    "https",
    "example.com",
    port=8443,
    path="/api/data",
    query="x=1&x=2",
    fragment="section",
)
print(url_str)  # https://example.com:8443/api/data?x=1&x=2#section
```

### Edge Case Handling

#### 1. Invalid Host
```python
from urlp import parse_url, HostValidationError
try:
    parse_url("https://exa$mple.com/")
except HostValidationError as e:
    print(f"Host error: {e}")
```

#### 2. Invalid Port
```python
from urlp import parse_url, PortValidationError
try:
    parse_url("https://example.com:abc/")
except PortValidationError as e:
    print(f"Port error: {e}")
```

#### 3. Path Traversal
```python
from urlp import parse_url, InvalidURLError
try:
    parse_url("https://example.com/../../etc/passwd")
except InvalidURLError as e:
    print(f"Path traversal blocked: {e}")
```

#### 4. Double-Encoded Characters
```python
from urlp import parse_url, InvalidURLError
try:
    parse_url("https://example.com/%252e%252e/")
except InvalidURLError as e:
    print(f"Double-encoding blocked: {e}")
```

#### 5. Mixed Unicode Scripts (Homograph Attack)
```python
from urlp import parse_url, InvalidURLError
try:
    parse_url("https://exаmple.com/")  # Note: Cyrillic 'а'
except InvalidURLError as e:
    print(f"Homograph attack blocked: {e}")
```

#### 6. Empty or Non-String Input
```python
from urlp import parse_url, InvalidURLError
try:
    parse_url("")
except InvalidURLError as e:
    print(f"Empty input blocked: {e}")
try:
    parse_url(12345)
except InvalidURLError as e:
    print(f"Non-string input blocked: {e}")
```

#### 7. Query Parameter Edge Cases
```python
from urlp import parse_url
url = parse_url("https://example.com/?a=1&&b=2")
print(url.query_params)  # [('a', '1'), ('b', '2')]
url2 = parse_url("https://example.com/?=value")  # Raises InvalidURLError
```

#### 8. IPv6 and IDNA Handling
```python
from urlp import parse_url
url = parse_url("http://[2001:db8::1]:8080/")
print(url.host)  # [2001:db8::1]
url_idna = parse_url("http://xn--e1afmkfd.xn--p1ai/")
print(url_idna.host)  # xn--e1afmkfd.xn--p1ai
```

#### 9. SSRF and Security Edge Cases
```python
from urlp import parse_url, InvalidURLError
for test_url in [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://192.168.1.1/",
    "http://[::1]/",
    "http://printer.local/",
]:
    try:
        parse_url(test_url)
    except InvalidURLError as e:
        print(f"Blocked SSRF risk: {test_url} -> {e}")
```

## Security Features

urlp includes comprehensive security features to protect against common URL-based attacks.

### Quick Security Setup

`parse_url()` is secure by default - no special setup needed:

```python
from urlp import parse_url, InvalidURLError

try:
    url = parse_url(user_input)
    # URL is validated and safe to use
except InvalidURLError as e:
    print(f"Rejected URL: {e}")
```

Security checks enabled by default:
- SSRF protection (blocks private IPs, localhost, link-local)
- Path traversal detection
- Open redirect detection  
- Double-encoding detection
- Homograph attack detection (mixed Unicode scripts)
- Returns immutable URL

### SSRF Protection (`strict` mode)

Server-Side Request Forgery (SSRF) attacks trick servers into making requests to internal resources. The `parse_url()` function blocks these by default:

```python
from urlp import parse_url, parse_url_unsafe, InvalidURLError

# These will raise InvalidURLError with parse_url():
parse_url("http://localhost/admin")           # Blocked: localhost
parse_url("http://127.0.0.1/")                # Blocked: loopback IP
parse_url("http://192.168.1.1/")              # Blocked: private IP
parse_url("http://10.0.0.1/")                 # Blocked: private IP  
parse_url("http://[::1]/")                    # Blocked: IPv6 loopback
parse_url("http://169.254.1.1/")              # Blocked: link-local
parse_url("http://printer.local/")            # Blocked: .local domain
parse_url("http://[::ffff:127.0.0.1]/")       # Blocked: IPv4-mapped IPv6

# Safe URLs work normally:
url = parse_url("https://api.example.com/data")

# Use parse_url_unsafe with strict=True if you need selective SSRF checks:
url = parse_url_unsafe("http://192.168.1.1/", strict=True)  # Blocked
url = parse_url_unsafe("http://192.168.1.1/")               # Allowed
```

### DNS Rebinding Protection (`check_dns` flag)

DNS rebinding attacks use hostnames that resolve to internal IPs. Enable `check_dns=True` to perform actual DNS resolution:

```python
from urlp import parse_url

# Performs DNS lookup to verify host resolves to public IP
url = parse_url("https://api.example.com/", check_dns=True)

# This would fail if evil.com resolves to 127.0.0.1:
# parse_url("http://evil.example.com/", check_dns=True)
```

**Note:** `check_dns` performs network I/O (DNS lookup). Use only when necessary. The default timeout is 2 seconds.

### Validation Methods

The `Validator` class provides methods for checking specific attack patterns:

```python
from urlp import Validator

# SSRF risk detection (comprehensive)
Validator.is_ssrf_risk("localhost")           # True
Validator.is_ssrf_risk("192.168.1.1")         # True
Validator.is_ssrf_risk("example.com")         # False

# DNS rebinding check (performs actual lookup)
Validator.resolve_host_safe("example.com")    # True (resolves to public IP)
Validator.resolve_host_safe("127.0.0.1")      # False (private IP)

# Path traversal detection
Validator.has_path_traversal("../../../etc/passwd")  # True
Validator.has_path_traversal("%2e%2e/secret")        # True (encoded)
Validator.has_path_traversal("/normal/path")         # False

# Open redirect detection
Validator.is_open_redirect_risk("//evil.com")        # True
Validator.is_open_redirect_risk("/path\\to")         # True (backslash)
Validator.is_open_redirect_risk("/normal/path")      # False

# Double-encoding detection (bypass attempts)
Validator.has_double_encoding("%252F")               # True (%2F encoded)
Validator.has_double_encoding("%2F")                 # False (single encoding)

# Homograph attack detection (mixed scripts)
Validator.has_mixed_scripts("exаmple")               # True (Cyrillic 'а')
Validator.has_mixed_scripts("example")               # False (pure Latin)

# Private IP detection
Validator.is_private_ip("192.168.1.1")               # True
Validator.is_private_ip("8.8.8.8")                   # False
```

### URL Canonicalization

Canonicalize URLs for consistent security comparisons:

```python
from urlp import parse_url

url = parse_url("HTTP://EXAMPLE.COM:80/path?z=1&a=2")
canonical = url.canonicalize()

print(canonical.scheme)   # "http" (lowercase)
print(canonical.host)     # "example.com" (lowercase)
print(canonical.port)     # None (default port removed)
print(canonical.query)    # "a=2&z=1" (sorted)
print(canonical.frozen)   # True
```

### Semantic URL Comparison

Compare URLs by meaning, not just string representation:

```python
from urlp import parse_url

url1 = parse_url("HTTP://EXAMPLE.COM:80/path?b=2&a=1")
url2 = parse_url("http://example.com/path?a=1&b=2")

# String comparison would fail:
assert url1.as_string() != url2.as_string()

# Semantic comparison succeeds:
assert url1.is_semantically_equal(url2)  # True!
```

### Password Masking

Prevent credential leakage in logs:

```python
from urlp import parse_url

url = parse_url("https://admin:secret123@api.example.com/")

# Default: shows password
print(url.as_string())  
# https://admin:secret123@api.example.com/

# Masked: safe for logging
print(url.as_string(mask_password=True))
# https://admin:***@api.example.com/
```

### Audit Logging

Monitor URL parsing for security auditing:

```python
from urlp import parse_url, set_audit_callback
import logging

def audit_url_parsing(raw_url, parsed_url, exception):
    if exception:
        logging.warning(f"Failed to parse URL: {exception}")
    else:
        logging.info(f"Parsed URL to host: {parsed_url.host}")

set_audit_callback(audit_url_parsing)

# All subsequent parse_url calls will trigger the callback
url = parse_url("https://example.com/")
```

### Cache Management

Clear validation caches after processing untrusted input:

```python
from urlp import Validator

# Get cache statistics
stats = Validator.get_cache_info()
print(stats['is_valid_host'])  # {'hits': 10, 'misses': 5, 'maxsize': 512, 'currsize': 5}

# Clear all caches (frees memory, resets state)
previous_sizes = Validator.clear_caches()
```

### Component Length Limits

urlp enforces length limits to prevent DoS attacks:

| Component | Max Length |
|-----------|------------|
| URL (total) | 1 MB |
| Scheme | 16 chars |
| Host | 253 chars |
| Path | 8,192 chars |
| Query | 65,536 chars |
| Fragment | 8,192 chars |
| Userinfo | 256 chars |

## Design Notes

- `Parser.parse()` sets `parser.query_pairs` and emits a serialized query string; both representations stay in sync for round-trips.
- IPv6 literals, IDNA hosts, and scheme-specific port validation mirror the logic inside `Parser._parse_host()` and `_validate_scheme_port()`.
- `Builder.compose()` prefers `query_pairs` over `query` and will percent-encode fragments using `FRAGMENT_SAFE`.
- Empty query strings (`?`) stay distinguishable from absent queries, so downstream caches can tell "no query" vs "empty query".

## Running Tests

```powershell
cd C:\Users\micro\Code\Projects\urlp
$env:PYTHONPATH="C:\Users\micro\Code\Projects\urlp"
pytest
```

## API Surface

| Component | Purpose |
| --- | --- |
| `urlp.URL` | High-level immutable URL value object with `userinfo`, `netloc`, `with_*` helpers, and serialization via `as_string()`. |
| `urlp.parse_url` | Parse a URL string securely (SSRF protection enabled). Supports `allow_custom_scheme` and `check_dns` options. |
| `urlp.parse_url_unsafe` | Parse a URL without security checks. Use only for trusted input. Supports `allow_custom_scheme`, `strict`, `debug`, and `check_dns`. |
| `urlp.build` | Build a URL string from individual component arguments (scheme, host, port, path, query, fragment, userinfo). |
| `urlp.compose_url` | Compose a URL string from a components dict (wrapper around `Builder().compose`). |
| `urlp.parse_relative_reference` | Split a scheme-less reference into raw `path`, `query`, and `fragment` without normalization. |
| `urlp.build_relative_reference` | Compose a relative reference using raw segments so round-tripping preserves the original text. |
| `urlp.round_trip_relative` | Convenience helper to parse and rebuild the same relative string, useful for validation pipelines. |
| `urlp.Validator` | Static validation methods: `is_ssrf_risk`, `resolve_host_safe`, `has_path_traversal`, `is_open_redirect_risk`, `has_double_encoding`, `has_mixed_scripts`, `is_private_ip`, and cache management. |
| `urlp.set_audit_callback` | Set a callback function for URL parsing audit logging. |
| `urlp.get_audit_callback` | Get the current audit callback function. |

### URL Instance Methods

| Method | Purpose |
| --- | --- |
| `url.as_string(mask_password=False)` | Convert to string, optionally masking password in userinfo. |
| `url.canonicalize()` | Return a canonicalized copy (lowercase scheme/host, sorted query params, no default port). |
| `url.is_semantically_equal(other)` | Compare URLs by meaning after canonicalization. |
| `url.same_origin(other)` | Check if two URLs have the same origin (scheme + host + port). |
| `url.origin` | Property returning the origin string (e.g., `https://example.com`). |
| `url.copy(**overrides)` | Create a copy with optional component overrides. |
| `url.with_*()` | Functional update methods: `with_scheme`, `with_host`, `with_port`, `with_path`, `with_fragment`, `with_userinfo`, `with_netloc`. |


Note: Low-level classes `Parser` and `Builder` remain available but are considered internal-facing; prefer the facade.

## Comparison with urllib.parse

When should you use **urlp** instead of the standard library `urllib.parse`?

### Feature Comparison

| Feature | `urllib.parse` | `urlp` |
| --- | --- | --- |
| **Basic URL parsing** | ✓ | ✓ |
| **URL composition** | ✓ | ✓ |
| **Query string parsing** | ✓ (parse_qs, parse_qsl) | ✓ (built-in query_pairs) |
| **RFC 3986 compliance** | Partial | ✓ (strict) |
| **Path normalization** | Limited | ✓ (configurable) |
| **IPv6 validation** | ✓ | ✓ (enhanced) |
| **IDNA support** | ✓ | ✓ (built-in) |
| **Port validation** | Minimal | ✓ (scheme-aware) |
| **Userinfo/netloc helpers** | ✗ | ✓ (.userinfo, .netloc, .with_netloc()) |
| **Immutable URL objects** | ✗ | ✓ (with_* methods return new URLs) |
| **Relative URL handling** | ✓ (urljoin) | ✓ (parse_relative_reference) |
| **Exception hierarchy** | Single URLError | ✓ (specialized exceptions) |
| **SSRF protection** | ✗ | ✓ (strict mode) |
| **DNS rebinding detection** | ✗ | ✓ (check_dns flag) |
| **Path traversal detection** | ✗ | ✓ |
| **Open redirect detection** | ✗ | ✓ |
| **Homograph detection** | ✗ | ✓ (mixed scripts) |
| **Double-encoding detection** | ✗ | ✓ |
| **URL canonicalization** | ✗ | ✓ |
| **Password masking** | ✗ | ✓ |
| **Audit logging** | ✗ | ✓ |
| **Component length limits** | ✗ | ✓ |

### Use urllib.parse when:

- **Parsing is only occasionally needed** — stdlib adds zero dependencies
- **You only need basic parsing/joining** — urllib.parse is straightforward and proven
- **Working in constrained environments** — guaranteed to be available everywhere
- **Legacy code compatibility** — existing codebases already use it

### Use urlp when:

- **Security is important** — SSRF protection, path traversal detection, DNS rebinding checks, and more
- **You need RFC 3986 strict compliance** — urlp enforces the standard more strictly
- **Working with authority components** — `.userinfo`, `.netloc`, and `.with_netloc()` save tedious string splitting
- **Building immutable URL objects** — the `URL` class and `with_*` methods enable functional patterns
- **Validating URLs rigorously** — scheme-aware port validation, IPv6 literal checking, IDNA encoding
- **Preventing URL-based attacks** — use `parse_url()` or individual `Validator` methods
- **Round-tripping URLs accurately** — query string and fragment encoding is normalized and reversible
- **Path normalization matters** — automatic handling of `./`, `../`, and redundant `/` sequences
- **You want ergonomic query access** — `.query_pairs` provides parsed tuples alongside the query string
- **Audit logging is needed** — built-in callback support for security monitoring

### Performance Notes

For simple, one-off URL parsing tasks, `urllib.parse` is often slightly faster due to its minimal approach. However, urlp's validation and normalization add meaningful overhead only on complex URLs or in edge cases. For typical application workloads (parsing a few URLs per request), the difference is negligible and urlp's richer API often saves downstream validation logic.

When comparing:
- **Simple URL parsing:** urllib.parse is ~2–5% faster for basic cases
- **Complex URLs with all components:** Performance is comparable (~1–2% difference)
- **Authority manipulation:** urlp is much faster; urllib.parse requires regex/split/join
- **Query extraction:** Both are fast; urlp includes query_pairs by default

For most applications, **choose urlp if you need its ergonomic or validation features**, and choose `urllib.parse` if you want zero dependencies and fastest-possible simple parsing.

## Exceptions and validation

The library raises a small hierarchy of exceptions to help callers handle errors precisely:

- `InvalidURLError` — base compatibility exception for invalid URL inputs (all parsing/build errors inherit from this). Use this when you want a broad catch-all.
- `URLParseError` — problems during parsing (malformed input, missing required parts).
- `URLBuildError` — problems while composing/building a URL from components.
- `HostValidationError` / `PortValidationError` — more specific validation failures for authority components.
- `QueryParsingError`, `FragmentEncodingError`, `UserInfoParsingError`, `UnsupportedSchemeError`, and other narrow exception types exist for fine-grained handling.

Recommended handling patterns:

- If you only need to detect "invalid URL" cases, catch `InvalidURLError` (covers all failures).
- If you need specific remediation (e.g., prompt for a new host, re-prompt for a port), catch the more-specific exceptions listed above.

Example:

```python
from urlp import InvalidURLError, HostValidationError, parse_url

try:
    u = parse_url(user_input)
except HostValidationError:
    print("Please correct the host name.")
except InvalidURLError:
    print("Invalid URL — please try again.")
```

The package `__init__` exposes the most commonly useful exception classes so consumers can import them directly:

```python
from urlp import InvalidURLError, HostValidationError
```

For library authors: prefer handling the specific exceptions when possible; fall back to `InvalidURLError` for a broad catch-all.


## Publishing notes

When releasing, consider bumping the package version in `pyproject.toml` to reflect the change. This release includes significant security features:

- SSRF protection (enabled by default in `parse_url()`)
- DNS rebinding detection (`check_dns` flag)
- Path traversal, open redirect, and double-encoding detection
- Homograph attack prevention
- URL canonicalization and semantic comparison
- Password masking and audit logging
- Component length limits for DoS prevention

The repository includes comprehensive tests for all security features, validation edge cases, and IDNA handling.

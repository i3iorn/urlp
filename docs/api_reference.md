# urlp API Reference

This document provides a comprehensive reference for the user-facing API of the `urlp` package, including parameter types, return types, and exception details for all public functions and classes.

---

## Table of Contents
- [parse_url](#parse_url)
- [parse_url_unsafe](#parse_url_unsafe)
- [build](#build)
- [compose_url](#compose_url)
- [URL](#url)
- [Validator](#validator)
- [Exceptions](#exceptions)
- [Relative Reference Helpers](#relative-reference-helpers)
- [Audit Logging](#audit-logging)
- [Constants](#constants)

---

## parse_url

```python
def parse_url(
    url: str,
    *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False,
    check_phishing: bool = False
) -> URL
```

Parse a URL string securely with SSRF, path traversal, and phishing protection enabled by default.

**Parameters:**
- `url` (`str`): The URL string to parse.
- `allow_custom_scheme` (`bool`, optional): Allow non-standard schemes. Default: `False`.
- `check_dns` (`bool`, optional): Perform DNS rebinding checks. Default: `False`.
- `check_phishing` (`bool`, optional): Check for known phishing domains. Default: `False`.

**Returns:**
- `URL`: An immutable URL object.

**Raises:**
- `InvalidURLError`: If the URL is invalid or fails any security check.

---

## parse_url_unsafe

```python
def parse_url_unsafe(
    url: str,
    *,
    allow_custom_scheme: bool = False,
    strict: bool = False,
    debug: bool = False,
    check_dns: bool = False
) -> URL
```

Parse a URL string without security checks. Use only for trusted input.

**Parameters:**
- `url` (`str`): The URL string to parse.
- `allow_custom_scheme` (`bool`, optional): Allow non-standard schemes. Default: `False`.
- `strict` (`bool`, optional): Enable SSRF protection. Default: `False`.
- `debug` (`bool`, optional): Include raw input in exception traces. Default: `False`.
- `check_dns` (`bool`, optional): Perform DNS rebinding checks. Default: `False`.

**Returns:**
- `URL`: An immutable URL object.

**Raises:**
- `InvalidURLError`: If the URL is invalid (when `strict=True`).

---

## build

```python
def build(
    scheme: str,
    host: str,
    *,
    port: Optional[int] = None,
    path: str = "/",
    query: Optional[str] = None,
    fragment: Optional[str] = None,
    userinfo: Optional[str] = None,
) -> str
```

Build a URL string from individual components.

**Parameters:**
- `scheme` (`str`): URL scheme (e.g., 'https').
- `host` (`str`): Hostname or IP address.
- `port` (`Optional[int]`, optional): Port number.
- `path` (`str`, optional): URL path. Default: '/'.
- `query` (`Optional[str]`, optional): Query string (without '?').
- `fragment` (`Optional[str]`, optional): Fragment (without '#').
- `userinfo` (`Optional[str]`, optional): Userinfo (user:pass format).

**Returns:**
- `str`: The composed URL string.

**Raises:**
- `URLBuildError`: If the components are invalid.

---

## compose_url

```python
def compose_url(components: Mapping[str, Any]) -> str
```

Compose a URL string from a dictionary of components.

**Parameters:**
- `components` (`Mapping[str, Any]`): Dict with keys: scheme, host, port, path, query, fragment, userinfo.

**Returns:**
- `str`: The composed URL string.

**Raises:**
- `URLBuildError`: If the components are invalid.

---

## URL

### Constructor
```python
class URL:
    def __init__(
        url: str,
        *,
        parser: Optional[Parser] = None,
        builder: Optional[Builder] = None,
        strict: bool = False,
        debug: bool = False,
        check_dns: bool = False,
        check_phishing: bool = False,
    )
```

Immutable URL object. Use `.with_*()` methods to create modified copies.

**Parameters:**
- `url` (`str`): The URL string to parse.
- `parser` (`Optional[Parser]`, optional): Custom parser instance.
- `builder` (`Optional[Builder]`, optional): Custom builder instance.
- `strict` (`bool`, optional): Enable SSRF and security checks. Default: `False`.
- `debug` (`bool`, optional): Include raw input in exception traces. Default: `False`.
- `check_dns` (`bool`, optional): Perform DNS rebinding checks. Default: `False`.
- `check_phishing` (`bool`, optional): Check for known phishing domains. Default: `False`.

**Raises:**
- `URLParseError`: If the URL is invalid or fails security checks.

### Properties
- `scheme: Optional[str]`
- `host: Optional[str]`
- `port: Optional[int]`
- `userinfo: Optional[str]`
- `path: str`
- `query: Optional[str]`
- `fragment: Optional[str]`
- `query_params: List[Tuple[str, Optional[str]]]`
- `netloc: str`
- `effective_port: Optional[int]`
- `is_absolute: bool`
- `origin: str` (raises `InvalidURLError` if not absolute)

### Methods
- `copy(**overrides) -> URL`
- `with_scheme(scheme: Optional[str]) -> URL`
- `with_host(host: Optional[str]) -> URL`
- `with_port(port: Optional[int]) -> URL`
- `with_path(path: str) -> URL`
- `with_query(query: Optional[str]) -> URL`
- `with_fragment(fragment: Optional[str]) -> URL`
- `with_userinfo(userinfo: Optional[str]) -> URL`
- `with_netloc(netloc: str) -> URL`
- `with_query_param(key: str, value: Optional[str] = None) -> URL`
- `without_query_param(key: str) -> URL`
- `without_query() -> URL`
- `same_origin(other: URL) -> bool`
- `canonicalize() -> URL`
- `is_semantically_equal(other: URL) -> bool`
- `as_string(mask_password: bool = False) -> str`

**Raises:**
- Most methods may raise `InvalidURLError` or more specific exceptions if the operation is invalid.

---

## Validator

```python
class Validator:
    @staticmethod
    def is_ssrf_risk(host: str) -> bool
    @staticmethod
    def resolve_host_safe(host: str, timeout: Optional[float] = None) -> bool
    @staticmethod
    def has_path_traversal(path: str) -> bool
    @staticmethod
    def is_open_redirect_risk(path: str) -> bool
    @staticmethod
    def has_double_encoding(value: str) -> bool
    @staticmethod
    def has_mixed_scripts(host: str) -> bool
    @staticmethod
    def is_private_ip(host: str) -> bool
    @staticmethod
    def is_valid_scheme(scheme: str) -> bool
    @staticmethod
    def is_valid_host(host: str) -> bool
    @staticmethod
    def is_valid_ipv4(ip: str) -> bool
    @staticmethod
    def is_valid_ipv6(ip: str) -> bool
    @staticmethod
    def is_valid_port(port: Any) -> bool
    @staticmethod
    def is_valid_path(path: str) -> bool
    @staticmethod
    def is_valid_query_param(param: str) -> bool
    @staticmethod
    def is_valid_fragment(fragment: str) -> bool
    @staticmethod
    def is_ip_address(host: str) -> bool
    @classmethod
    def get_cache_info() -> Dict[str, Optional[Any]]
    @classmethod
    def clear_caches() -> Dict[str, int]
```

See the source or docstrings for parameter and return type details. All methods are pure except those that delegate to security checks.

---

## Exceptions

All exceptions inherit from `InvalidURLError` (for broad handling) or more specific subclasses:
- `InvalidURLError`
- `URLParseError`
- `URLBuildError`
- `HostValidationError`
- `PortValidationError`
- `QueryParsingError`
- `FragmentEncodingError`
- `UserInfoParsingError`
- `UnsupportedSchemeError`
- `RelativeReferenceError`
- `MissingHostError`
- `MissingPortError`

**All exceptions accept:**
- `message: str` (error message)
- `value: Any` (the value that caused the error, if available)
- `component: Optional[str]` (the URL component involved, if available)

---

## Relative Reference Helpers

- `parse_relative_reference(ref: str) -> Dict[str, Optional[str]]`
- `build_relative_reference(path: str, query: Optional[str] = None, fragment: Optional[str] = None) -> str`
- `round_trip_relative(ref: str) -> str`

---

## Audit Logging

- `set_audit_callback(callback: Callable[[str, Optional[URL], Optional[Exception]], None]) -> None`
- `get_audit_callback() -> Optional[Callable]`

---

## Constants

- `MAX_URL_LENGTH: int`
- `MAX_SCHEME_LENGTH: int`
- `MAX_HOST_LENGTH: int`
- `MAX_PATH_LENGTH: int`
- `MAX_QUERY_LENGTH: int`
- `MAX_FRAGMENT_LENGTH: int`
- `MAX_USERINFO_LENGTH: int`
- `DEFAULT_DNS_TIMEOUT: float`
- `PASSWORD_MASK: str`

---

For more details, see the README or inline docstrings in the codebase.

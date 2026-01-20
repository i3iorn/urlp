"""High-level URL representation with immutability support."""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from ._builder import Builder, QueryPairs
from ._audit import set_audit_callback, get_audit_callback, invoke_audit_callback
from ._relative import parse_relative_reference, build_relative_reference, round_trip_relative
from .constants import DEFAULT_PORTS, MAX_URL_LENGTH, PASSWORD_MASK
from .exceptions import InvalidURLError, URLParseError
from ._parser import Parser
from ._validation import Validator, is_valid_userinfo


class URL:
    """Immutable URL representation.

    URLs are immutable by default. Use `copy()` to create modified versions.
    """

    __slots__ = (
        'recognized_scheme', '_parser', '_builder', '_strict', '_debug',
        '_check_dns', '_scheme', '_userinfo', '_host', '_port', '_path',
        '_query', '_fragment', '_query_pairs', '_check_phishing'
    )

    def __init__(
        self, url: str, *,
        parser: Optional[Parser] = None,
        builder: Optional[Builder] = None,
        strict: bool = False,
        debug: bool = False,
        check_dns: bool = False,
        check_phishing: bool = False,
    ) -> None:
        if not isinstance(url, str):
            raise TypeError(f"URL must be a string, got {type(url).__name__}")
        if not isinstance(strict, bool):
            raise TypeError(f"strict must be a boolean, got {type(strict).__name__}")
        if not isinstance(debug, bool):
            raise TypeError(f"debug must be a boolean, got {type(debug).__name__}")
        if not isinstance(check_dns, bool):
            raise TypeError(f"check_dns must be a boolean, got {type(check_dns).__name__}")
        if not isinstance(check_phishing, bool):
            raise TypeError(f"check_phishing must be a boolean, got {type(check_phishing).__name__}")

        self._parser = parser if parser is not None else Parser()
        self._builder = builder if builder is not None else Builder()
        self._strict = strict
        self._debug = debug
        self._check_dns = check_dns
        self._check_phishing = check_phishing
        self.recognized_scheme: Optional[bool] = None

        self._parse_and_validate(url)

    def _parse_and_validate(self, url: str) -> None:
        """Parse URL and run security validations."""
        if not url.strip():
            raise URLParseError("A non-empty URL string is required.")
        if len(url) > MAX_URL_LENGTH:
            raise URLParseError("URL length exceeds maximum allowed size.")
        if not Validator.is_url_safe_string(url):
            raise URLParseError("URL contains invalid control characters.")

        try:
            parsed = self._parser.parse(url)
            self.recognized_scheme = self._parser.recognized_scheme
            self._apply_parsed(parsed)
            self._security_checks()
            invoke_audit_callback(url, self, None)
        except InvalidURLError as exc:
            invoke_audit_callback(url, None, exc)
            if not self._debug:
                raise type(exc)(str(exc)) from None
            raise
        except Exception as exc:
            invoke_audit_callback(url, None, exc)
            raise

    def _security_checks(self) -> None:
        """Run security validations on parsed URL."""
        if self._strict and self._host and Validator.is_ssrf_risk(self._host):
            raise InvalidURLError("Host poses SSRF risk and is disallowed in strict mode.")
        if self._check_dns and self._host and not Validator.resolve_host_safe(self._host):
            raise InvalidURLError("Host resolves to private/reserved IP address.")
        if self._check_phishing and self._host and Validator.is_phishing_domain(self._host):
            raise InvalidURLError("Host is identified as a phishing domain.")

    def _apply_parsed(self, components: Mapping[str, Optional[Any]]) -> None:
        """Apply parsed components to instance."""
        self._scheme = components.get("scheme")
        self._userinfo = components.get("userinfo")
        self._host = components.get("host")
        self._port = _normalize_port(components.get("port"))
        self._path = components.get("path") or ""
        self._query = components.get("query")
        self._fragment = components.get("fragment")
        # Use query_pairs from components if provided, otherwise from parser
        query_pairs = components.get("query_pairs")
        if query_pairs is not None:
            self._query_pairs = list(query_pairs)
        else:
            self._query_pairs = list(getattr(self._parser, "query_pairs", []))

    # =========================================================================
    # Read-only Properties
    # =========================================================================

    @property
    def scheme(self) -> Optional[str]:
        return self._scheme

    @property
    def host(self) -> Optional[str]:
        return self._host

    @property
    def port(self) -> Optional[int]:
        return self._port

    @property
    def userinfo(self) -> Optional[str]:
        return self._userinfo

    @property
    def path(self) -> str:
        return self._path

    @property
    def query(self) -> Optional[str]:
        return self._query

    @property
    def fragment(self) -> Optional[str]:
        return self._fragment

    @property
    def query_params(self) -> QueryPairs:
        """Return query parameters as list of (key, value) tuples."""
        return list(self._query_pairs)

    @property
    def netloc(self) -> str:
        """Return the network location (userinfo@host:port)."""
        return self._builder.build_netloc(
            self._userinfo, self._host, self._port, self._scheme
        )

    @property
    def effective_port(self) -> Optional[int]:
        """Return explicit port or scheme default."""
        if self._port is not None:
            return self._port
        return DEFAULT_PORTS.get(self._scheme.lower()) if self._scheme else None

    @property
    def is_absolute(self) -> bool:
        """Check if URL is absolute (has scheme and host)."""
        return self.scheme is not None and self.host is not None

    @property
    def origin(self) -> str:
        """Return the origin (scheme://host:port) for same-origin comparisons."""
        if not self._scheme or not self._host:
            raise InvalidURLError("Cannot compute origin for relative URL.")
        port = self.effective_port
        if port and self._scheme and DEFAULT_PORTS.get(self._scheme.lower()) == port:
            port = None
        if port:
            return f"{self._scheme}://{self._host}:{port}"
        return f"{self._scheme}://{self._host}"

    # =========================================================================
    # Immutable Update Methods (return new URL)
    # =========================================================================

    def copy(self, **overrides: Any) -> 'URL':
        """Create a copy with optional component overrides."""
        _validate_copy_overrides(overrides)
        components = self._to_dict()
        components.update(overrides)
        components["port"] = _normalize_port(components.get("port"))

        new_url = URL.__new__(URL)
        new_url.recognized_scheme = self.recognized_scheme
        new_url._parser = self._parser
        new_url._builder = self._builder
        new_url._strict = self._strict
        new_url._debug = self._debug
        new_url._check_dns = self._check_dns
        new_url._apply_parsed(components)
        return new_url

    def with_scheme(self, scheme: Optional[str]) -> 'URL':
        """Return new URL with different scheme."""
        return self.copy(scheme=scheme)

    def with_host(self, host: Optional[str]) -> 'URL':
        """Return new URL with different host."""
        return self.copy(host=host)

    def with_port(self, port: Optional[int]) -> 'URL':
        """Return new URL with different port."""
        return self.copy(port=port)

    def with_path(self, path: str) -> 'URL':
        """Return new URL with different path."""
        return self.copy(path=path)

    def with_query(self, query: Optional[str]) -> 'URL':
        """Return new URL with different query string."""
        return self.copy(query=query)

    def with_fragment(self, fragment: Optional[str]) -> 'URL':
        """Return new URL with different fragment."""
        return self.copy(fragment=fragment)

    def with_userinfo(self, userinfo: Optional[str]) -> 'URL':
        """Return new URL with different userinfo."""
        return self.copy(userinfo=userinfo)

    def with_netloc(self, netloc: str) -> 'URL':
        """Return new URL with different netloc."""
        parser = Parser()
        userinfo, host, port = parser.parse_netloc(netloc, require_host=bool(netloc))
        if port is None and self._scheme and host:
            port = DEFAULT_PORTS.get(self._scheme.lower())
        return self.copy(userinfo=userinfo, host=host, port=port)

    def with_query_param(self, key: str, value: Optional[str] = None) -> 'URL':
        """Return new URL with added query parameter."""
        new_query = self._builder.add_param(self._query, key, value)
        return self.copy(query=new_query)

    def without_query_param(self, key: str) -> 'URL':
        """Return new URL with query parameter removed."""
        new_query = self._builder.remove_param(self._query, key)
        return self.copy(query=new_query)

    def without_query(self) -> 'URL':
        """Return new URL without query string or fragment."""
        return self.copy(query=None, query_pairs=[], fragment=None)

    # =========================================================================
    # Comparison and Normalization
    # =========================================================================

    def same_origin(self, other: 'URL') -> bool:
        """Check if this URL has the same origin as another URL."""
        return self.origin == other.origin

    def canonicalize(self) -> 'URL':
        """Return a canonicalized copy of this URL."""
        canonical_scheme = self._scheme.lower() if self._scheme else None
        canonical_host = self._host.lower() if self._host else None
        canonical_port = self._port
        if canonical_scheme and canonical_port == DEFAULT_PORTS.get(canonical_scheme):
            canonical_port = None
        canonical_path = self._builder.normalize_path(self._path) if self._path else ""
        sorted_pairs = sorted(self._query_pairs, key=lambda x: (x[0], x[1] or ""))
        canonical_query = self._builder.serialize_query(sorted_pairs) if sorted_pairs else None

        new_url = self.copy(
            scheme=canonical_scheme, host=canonical_host,
            port=canonical_port, path=canonical_path, query=canonical_query,
        )
        new_url._query_pairs = sorted_pairs
        return new_url

    def is_semantically_equal(self, other: 'URL') -> bool:
        """Check semantic equality after normalization."""
        if not isinstance(other, URL):
            return False
        return self.canonicalize().as_string() == other.canonicalize().as_string()

    # =========================================================================
    # String Conversion
    # =========================================================================

    def as_string(self, *, mask_password: bool = False) -> str:
        """Return URL as string, optionally masking password."""
        components = self._to_dict()
        if mask_password and components.get("userinfo"):
            userinfo = components["userinfo"]
            if ":" in userinfo:
                username, _, _ = userinfo.partition(":")
                components["userinfo"] = f"{username}:{PASSWORD_MASK}"
        return self._builder.compose(components)

    def _to_dict(self) -> Dict[str, Any]:
        """Convert URL to dictionary of components."""
        return {
            "scheme": self._scheme, "userinfo": self._userinfo, "host": self._host,
            "port": self._port, "path": self._path, "query": self._query,
            "fragment": self._fragment, "query_pairs": list(self._query_pairs),
        }

    def __str__(self) -> str:
        return self.as_string()

    def __repr__(self) -> str:
        try:
            url = self.as_string()
        except InvalidURLError:
            url = "<invalid>"
        return f"URL('{url}')"

    def __hash__(self) -> int:
        return hash((self._scheme, self._userinfo, self._host, self._port,
                     self._path, self._query, self._fragment))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, URL):
            return NotImplemented
        return self.as_string() == other.as_string()



def _normalize_port(value: Optional[Any]) -> Optional[int]:
    """Normalize port value to int or None."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        if not value.isdigit():
            raise InvalidURLError("Port must be numeric.")
        candidate = int(value)
    elif isinstance(value, int):
        candidate = value
    else:
        raise InvalidURLError("Port must be an integer or numeric string.")
    if not 0 < candidate < 65536:
        raise InvalidURLError("Port must be between 1 and 65535.")
    return candidate


def _validate_copy_overrides(overrides: Dict[str, Any]) -> None:
    """Validate copy() override arguments."""
    valid_keys = {'scheme', 'host', 'port', 'path', 'query', 'fragment',
                  'userinfo', 'query_pairs'}
    invalid_keys = set(overrides.keys()) - valid_keys
    if invalid_keys:
        raise InvalidURLError(f"Invalid override(s): {', '.join(sorted(invalid_keys))}")
    for key in ('scheme', 'host', 'path', 'query', 'fragment'):
        if key in overrides and overrides[key] is not None:
            if not isinstance(overrides[key], str):
                raise InvalidURLError(f"{key} must be a string")
    if 'userinfo' in overrides and overrides['userinfo'] is not None:
        if not isinstance(overrides['userinfo'], str):
            raise InvalidURLError("userinfo must be a string")
        if not is_valid_userinfo(overrides['userinfo']):
            raise InvalidURLError("Invalid userinfo format.")


__all__ = [
    "URL", "set_audit_callback", "get_audit_callback",
    "parse_relative_reference", "build_relative_reference", "round_trip_relative",
]

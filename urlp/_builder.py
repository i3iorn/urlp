from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import quote, quote_plus, unquote_plus
from functools import lru_cache

from .constants import DEFAULT_PORTS, OfficialSchemes
from .exceptions import (
    URLBuildError,
    PortValidationError,
)
from ._patterns import PATTERNS

QueryPairs = List[Tuple[str, Optional[str]]]

# Use centralized pattern
_PERCENT_ENCODE_PATTERN = PATTERNS["percent_encode"]


class Builder:
    PATH_SAFE = "-._~!$&'()*+,;=:@%"
    QUERY_SAFE = "-._~:/?@!$&'()*+,;="
    FRAGMENT_SAFE = "-._~!$&'()*+,;=:@/?"

    def compose(self, components: Mapping[str, Any]) -> str:
        scheme = components.get("scheme")
        userinfo = components.get("userinfo")
        host = components.get("host")
        port = components.get("port")
        path = components.get("path") or ""
        fragment = components.get("fragment")
        query = components.get("query")
        query_pairs: QueryPairs = components.get("query_pairs") or []

        normalized_path = self.normalize_path(path)
        if not normalized_path and host:
            normalized_path = "/"
        serialized_query = query
        if query_pairs:
            serialized_query = self.serialize_query(query_pairs)

        url = ""
        if scheme:
            url += f"{scheme}://"
        netloc = self.build_netloc(userinfo, host, port, scheme)
        if netloc:
            url += netloc
        elif scheme and scheme.lower() not in {OfficialSchemes.FILE.value}:
            raise URLBuildError("Host is required when building absolute URLs.")

        url += normalized_path

        if serialized_query is not None:
            url += f"?{serialized_query}"
        if fragment:
            url += f"#{self.percent_encode(fragment, safe=self.FRAGMENT_SAFE)}"
        return url

    def build_netloc(self, userinfo: Optional[str], host: Optional[str], port: Optional[int], scheme: Optional[str]) -> str:
        if not host:
            if port is not None:
                raise PortValidationError("Port cannot be set without a host.", value=port, component="port")
            return userinfo or ""
        parts = []
        if userinfo:
            parts.append(f"{userinfo}@")
        parts.append(host)
        display_port = port
        if scheme and display_port is not None and DEFAULT_PORTS.get(scheme.lower()) == display_port:
            display_port = None
        if display_port is not None:
            parts.append(f":{display_port}")
        return "".join(parts)

    def normalize_path(self, path: Optional[str]) -> str:
        if path is None or path == "":
            return ""
        absolute = path.startswith("/")
        trailing_slash = path.endswith("/")

        # Check if path ends with "." or "./" which should result in trailing slash
        ends_with_dot_segment = path.endswith("/.") or path.endswith("/./")

        segments: List[str] = []
        for segment in path.split("/"):
            if not segment or segment == ".":
                continue
            elif segment == "..":
                if segments:
                    segments.pop()
            else:
                segments.append(self.percent_encode(segment, safe=self.PATH_SAFE))

        if not segments:
            return "/" if absolute else ""

        normalized = "/".join(segments)
        if absolute:
            normalized = "/" + normalized
        # Preserve trailing slash when originally present, or when path ends with "." segment
        if (trailing_slash or ends_with_dot_segment) and normalized != "/":
            normalized += "/"
        return normalized

    def percent_encode(self, value: str, *, safe: str) -> str:
        # Use urllib.quote to percent-encode then normalize percent-encoding to uppercase hex
        return self._percent_encode_cached(value, safe)

    @staticmethod
    @lru_cache(maxsize=1024)
    def _percent_encode_cached(value: str, safe: str) -> str:
        """Cached percent-encoding with uppercase hex normalization."""
        encoded = quote(value, safe=safe)
        # Uppercase percent-encodings to canonical form using pre-compiled pattern
        return _PERCENT_ENCODE_PATTERN.sub(lambda m: m.group(0).upper(), encoded)

    def parse_query(self, query: Optional[str]) -> QueryPairs:
        if query is None or query == "":
            return []
        pairs: QueryPairs = []
        for chunk in query.split("&"):
            if chunk == "":
                continue
            # Use partition for better performance
            key_raw, sep, value_raw = chunk.partition("=")
            key = unquote_plus(key_raw)
            if not key:
                raise URLBuildError("Query keys must be non-empty.", value=chunk, component="query")
            value = unquote_plus(value_raw) if sep else None
            pairs.append((key, value))
        return pairs

    def serialize_query(self, params: QueryPairs) -> str:
        """Serialize query pairs to a query string."""
        return Builder._serialize_query_impl(params, self.QUERY_SAFE)

    @staticmethod
    def serialize_query_static(params: QueryPairs) -> str:
        """Static method for serializing query pairs without instantiating Builder."""
        return Builder._serialize_query_impl(params, Builder.QUERY_SAFE)

    @staticmethod
    def _serialize_query_impl(params: QueryPairs, query_safe: str) -> str:
        """Shared implementation for query serialization."""
        if not params:
            return ""
        encoded: List[str] = []
        # Cache for percent-encoded keys/values
        encode_cache = {}
        def encode(val):
            if val in encode_cache:
                return encode_cache[val]
            encoded_val = quote_plus(val, safe=query_safe)
            encoded_val = _PERCENT_ENCODE_PATTERN.sub(lambda m: m.group(0).upper(), encoded_val)
            encode_cache[val] = encoded_val
            return encoded_val
        for key, value in params:
            encoded_key = encode(key)
            if value is None:
                encoded.append(encoded_key)
            else:
                encoded_value = encode(str(value))
                encoded.append(f"{encoded_key}={encoded_value}")
        return "&".join(encoded)

    def add_param(self, query: Optional[str], key: str, value: Optional[str] = None) -> str:
        pairs = self.parse_query(query)
        pairs.append((key, value))
        return self.serialize_query(pairs)

    def remove_param(self, query: Optional[str], key: str) -> str:
        pairs = [(k, v) for k, v in self.parse_query(query) if k != key]
        return self.serialize_query(pairs)

    def merge_params(self, query: Optional[str], updates: Mapping[str, Any]) -> str:
        pairs = self.parse_query(query)
        for key, value in updates.items():
            if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
                for child in value:
                    pairs.append((key, None if child is None else str(child)))
            else:
                pairs.append((key, None if value is None else str(value)))
        return self.serialize_query(pairs)


__all__ = [
    "Builder",
    "QueryPairs",
]

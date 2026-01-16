"""URL component dataclasses.

This module defines immutable dataclasses for URL components,
used throughout the library for structured data passing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Union

QueryPairs = List[Tuple[str, Optional[str]]]


@dataclass(frozen=True)
class ParseResult:
    """Result of parsing a URL string.

    This immutable dataclass contains all components extracted from a URL,
    making the parser stateless and thread-safe.
    """
    scheme: Optional[str] = None
    userinfo: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    query: Optional[str] = None
    fragment: Optional[str] = None
    query_pairs: QueryPairs = field(default_factory=list)
    recognized_scheme: Optional[bool] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for backward compatibility."""
        return {
            "scheme": self.scheme,
            "userinfo": self.userinfo,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
        }


@dataclass(frozen=True)
class URLComponents:
    """Components of a URL for building or manipulation.

    Unlike ParseResult, this can be used for constructing URLs
    with all components optional.
    """
    scheme: Optional[str] = None
    userinfo: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    query: Optional[str] = None
    fragment: Optional[str] = None
    query_pairs: QueryPairs = field(default_factory=list)

    def with_updates(self, **kwargs: Optional[str]) -> 'URLComponents':
        """Create a new URLComponents with specified fields updated."""

        scheme = kwargs["scheme"] or self.scheme
        userinfo = kwargs["userinfo"] or self.userinfo
        host = kwargs["host"] or self.host
        port = int(kwargs["port"] if "port" in kwargs else self.port)
        path = kwargs["path"] or self.path
        query = kwargs["query"] or self.query
        fragment = kwargs["fragment"] or self.fragment
        query_pairs = kwargs["query_pairs"] if "query_pairs" in kwargs else self.query_pairs
        return URLComponents(
            scheme=scheme,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            query_pairs=query_pairs,
        )


__all__ = ["ParseResult", "URLComponents", "QueryPairs"]

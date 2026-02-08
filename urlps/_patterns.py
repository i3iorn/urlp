"""Centralized regex patterns for URL parsing and validation.

All regex patterns used throughout the urlps library are defined here
for consistency and easier maintenance.
"""
from __future__ import annotations

import re
from typing import Dict, Pattern

# Pre-compiled regex patterns for URL component validation
PATTERNS: Dict[str, Pattern[str]] = {
    # Scheme validation: starts with letter, followed by letters/digits/+/-/.
    "scheme": re.compile(r"^[a-z][a-z0-9+\-.]{0,15}$"),

    # Hostname validation (DNS label format)
    "host": re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
    ),

    # IPv4 address format (basic structure check)
    "ipv4": re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"),

    # IPv6 address in brackets with optional zone ID
    "ipv6": re.compile(r"^\[([0-9a-fA-F:]+)(%25[A-Za-z0-9_.~-]+)?\]$"),

    # URL-safe string characters
    "url_safe_string": re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*$"),

    # Fragment validation (RFC 3986 compliant)
    "fragment": re.compile(
        r"^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?\[\]]|%[0-9A-Fa-f]{2})*$"
    ),

    # Control characters (for rejection)
    "control_chars": re.compile(r"[\s\x00-\x1F\x7F]"),

    # Percent-encoding pattern for normalization (uppercase hex)
    "percent_encode": re.compile(r"%[0-9a-fA-F]{2}"),

    # Double-encoding detection
    "double_encode": re.compile(r"%25[0-9A-Fa-f]{2}"),

    # Userinfo validation (backward compatibility)
    "userinfo": re.compile(r"^[^:@]+(?::[^@]*)?$"),
}


__all__ = ["PATTERNS"]

from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet, Set
import os
import warnings


class OfficialSchemes(Enum):
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    FTPS = "ftps"
    SFTP = "sftp"
    FILE = "file"
    WS = "ws"
    WSS = "wss"


DEFAULT_PORTS: Dict[str, int] = {
    OfficialSchemes.HTTP.value: 80,
    OfficialSchemes.HTTPS.value: 443,
    OfficialSchemes.FTP.value: 21,
    OfficialSchemes.FTPS.value: 990,
    OfficialSchemes.SFTP.value: 22,
    OfficialSchemes.WS.value: 80,
    OfficialSchemes.WSS.value: 443,
}

SCHEMES_NO_PORT: Set[str] = {OfficialSchemes.FILE.value}

# Official and unsafe schemes (moved from _parser.py)
OFFICIAL_SCHEMES: FrozenSet[str] = frozenset(s.value for s in OfficialSchemes)
UNSAFE_SCHEMES: FrozenSet[str] = frozenset({"javascript", "data", "vbscript"})

# Standard well-known ports (moved from _validation.py)
STANDARD_PORTS: FrozenSet[int] = frozenset([80, 443, 21, 22, 25, 110, 143, 53])

# Component length limits for security (tuned for 99.99% of URLs)
# These are intentionally conservative to reduce attack surface while
# still accommodating real-world usage (tracking, long query strings, etc.).
MAX_URL_LENGTH = 32 * 1024         # 32 KB total URL length
MAX_SCHEME_LENGTH = 16
MAX_HOST_LENGTH = 253              # Per DNS specification
MAX_PATH_LENGTH = 4 * 1024         # 4 KB
MAX_QUERY_LENGTH = 8 * 1024        # 8 KB
MAX_FRAGMENT_LENGTH = 1 * 1024     # 1 KB
MAX_USERINFO_LENGTH = 128          # 128 chars for userinfo
MAX_IPV6_STRING_LENGTH = 128       # Max length for bracketed IPv6 with zone ID

# Allow overriding the above max-lengths via environment variables.
# Each env var should contain a positive integer. Invalid values are ignored
# and a warning is emitted.
_ENV_OVERRIDES = {
    "MAX_URL_LENGTH": "URLPS_MAX_URL_LENGTH",
    "MAX_SCHEME_LENGTH": "URLPS_MAX_SCHEME_LENGTH",
    "MAX_HOST_LENGTH": "URLPS_MAX_HOST_LENGTH",
    "MAX_PATH_LENGTH": "URLPS_MAX_PATH_LENGTH",
    "MAX_QUERY_LENGTH": "URLPS_MAX_QUERY_LENGTH",
    "MAX_FRAGMENT_LENGTH": "URLPS_MAX_FRAGMENT_LENGTH",
    "MAX_USERINFO_LENGTH": "URLPS_MAX_USERINFO_LENGTH",
    "MAX_IPV6_STRING_LENGTH": "URLPS_MAX_IPV6_STRING_LENGTH",
}


def _apply_env_overrides() -> None:
    """Apply environment-variable overrides to module-level max-size constants.

    Environment variables are named like `URLPS_MAX_URL_LENGTH`. Values must be
    positive integers. Invalid or non-positive values are ignored with a warning.
    """
    for const_name, env_name in _ENV_OVERRIDES.items():
        val = os.getenv(env_name)
        if val is None:
            continue
        try:
            iv = int(val)
        except Exception:
            warnings.warn(f"Environment variable {env_name} value '{val}' is not an integer; ignoring.")
            continue
        if iv <= 0:
            warnings.warn(f"Environment variable {env_name} must be a positive integer; ignoring value {iv}.")
            continue
        # Set the module-level constant
        globals()[const_name] = iv


# Apply overrides at import time
_apply_env_overrides()

# Blocked hostnames for SSRF protection
# This is a blocklist of dangerous hostnames, not bind addresses
BLOCKED_HOSTNAMES: FrozenSet[str] = frozenset({  # nosec B104
    # Localhost variations
    "localhost",
    "localhost.localdomain",
    "localhost.",
    # IPv4 loopback and special addresses
    "127.0.0.1",
    "0.0.0.0",
    # IPv6 loopback
    "::1",
    "[::1]",
    "[::]",
    "[0:0:0:0:0:0:0:1]",
    "[0000:0000:0000:0000:0000:0000:0000:0001]",
    # Cloud metadata endpoints (AWS, GCP, Azure, etc.)
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "169.254.170.2",  # ECS metadata
    # Link-local
    "169.254.0.0",
    # Kubernetes
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
})

# DNS rebinding protection settings (improvement #4 round 2)
DEFAULT_DNS_TIMEOUT: float = 2.0

# Password masking placeholder (improvement #3 round 2)
PASSWORD_MASK: str = "***"


__all__ = [
    "OfficialSchemes",
    "DEFAULT_PORTS",
    "SCHEMES_NO_PORT",
    "OFFICIAL_SCHEMES",
    "UNSAFE_SCHEMES",
    "STANDARD_PORTS",
    "MAX_URL_LENGTH",
    "MAX_SCHEME_LENGTH",
    "MAX_HOST_LENGTH",
    "MAX_PATH_LENGTH",
    "MAX_QUERY_LENGTH",
    "MAX_FRAGMENT_LENGTH",
    "MAX_USERINFO_LENGTH",
    "MAX_IPV6_STRING_LENGTH",
    "BLOCKED_HOSTNAMES",
    "DEFAULT_DNS_TIMEOUT",
    "PASSWORD_MASK",
]

from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet, Set


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

# Component length limits for security (improvement #2)
MAX_URL_LENGTH = 1024 * 1024  # 1 MB
MAX_SCHEME_LENGTH = 16
MAX_HOST_LENGTH = 253  # Per DNS specification
MAX_PATH_LENGTH = 8192
MAX_QUERY_LENGTH = 65536
MAX_FRAGMENT_LENGTH = 8192
MAX_USERINFO_LENGTH = 256

# Blocked hostnames for SSRF protection
# This is a blocklist of dangerous hostnames, not bind addresses
BLOCKED_HOSTNAMES: frozenset[str] = frozenset({  # nosec B104
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
    "BLOCKED_HOSTNAMES",
    "DEFAULT_DNS_TIMEOUT",
    "PASSWORD_MASK",
]

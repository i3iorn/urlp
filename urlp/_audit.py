"""Thread-safe audit callback for URL parsing security logging."""
from __future__ import annotations

import threading
from typing import Optional, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from .url import URL

# Thread-safe audit callback for security logging
_audit_callback_lock = threading.Lock()
_audit_callback: Optional[Callable[[str, Optional['URL'], Optional[Exception]], None]] = None


def set_audit_callback(
    callback: Optional[Callable[[str, Optional['URL'], Optional[Exception]], None]]
) -> None:
    """Set a callback function for URL parsing audit logging.

    Thread Safety:
        This function is thread-safe. The callback reference is protected by a lock.
        The callback itself should be thread-safe if used in multi-threaded environments.

    Args:
        callback: The callback function, or None to disable auditing.
    """
    global _audit_callback
    with _audit_callback_lock:
        _audit_callback = callback


def get_audit_callback() -> Optional[Callable[[str, Optional['URL'], Optional[Exception]], None]]:
    """Get the current audit callback function (thread-safe)."""
    with _audit_callback_lock:
        return _audit_callback


def invoke_audit_callback(
    raw_url: str,
    parsed_url: Optional['URL'],
    exception: Optional[Exception]
) -> None:
    """Invoke the audit callback if set, in a thread-safe manner."""
    with _audit_callback_lock:
        callback = _audit_callback

    if callback is not None:
        try:
            callback(raw_url, parsed_url, exception)
        except Exception:
            # Don't let callback errors propagate and break URL parsing
            pass


__all__ = ["set_audit_callback", "get_audit_callback", "invoke_audit_callback"]

"""Thread-safe audit callback for URL parsing security logging."""
from __future__ import annotations

import threading
from typing import Optional, Callable, TYPE_CHECKING, Dict, Any

if TYPE_CHECKING:
    from .url import URL

# Thread-safe audit callback for security logging
_audit_callback_lock = threading.Lock()
_audit_callback: Optional[Callable[[str, Optional['URL'], Optional[Exception]], None]] = None

# Metrics for callback failures
_callback_failure_count: int = 0
_last_callback_error: Optional[Exception] = None


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
    global _callback_failure_count, _last_callback_error

    with _audit_callback_lock:
        callback = _audit_callback

    if callback is not None:
        try:
            callback(raw_url, parsed_url, exception)
        except Exception as e:
            # Don't let callback errors propagate and break URL parsing
            # but track them for diagnostics
            with _audit_callback_lock:
                _callback_failure_count += 1
                _last_callback_error = e


def get_callback_failure_metrics() -> Dict[str, Any]:
    """Get metrics about audit callback failures.

    Returns:
        Dict containing:
            - failure_count: Total number of callback invocation failures
            - last_error: The last exception raised by a callback, or None
    """
    with _audit_callback_lock:
        return {
            "failure_count": _callback_failure_count,
            "last_error": _last_callback_error,
        }


def reset_callback_failure_metrics() -> Dict[str, Any]:
    """Reset callback failure metrics and return previous values.

    Returns:
        Dict containing the metrics before reset.
    """
    global _callback_failure_count, _last_callback_error

    with _audit_callback_lock:
        previous = {
            "failure_count": _callback_failure_count,
            "last_error": _last_callback_error,
        }
        _callback_failure_count = 0
        _last_callback_error = None
        return previous


__all__ = [
    "set_audit_callback",
    "get_audit_callback",
    "invoke_audit_callback",
    "get_callback_failure_metrics",
    "reset_callback_failure_metrics",
]

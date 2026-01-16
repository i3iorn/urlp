# Exceptions (Public API)

This document lists the public exception classes exposed by the `urlp` package and gives recommended usage patterns.

## Public exceptions

All exceptions inherit from `InvalidURLError` for backwards compatibility unless otherwise noted.

- `URLpError` — base error for urlp (root class, not commonly caught).
- `InvalidURLError` — compatibility base for invalid URL inputs. Catch this to broadly handle URL-related errors.
- `URLParseError` — parsing-related failures.
- `URLBuildError` — building/composition failures.
- `UnsupportedSchemeError` — raised when a scheme forbids explicit ports or is otherwise unsupported.
- `HostValidationError` — invalid hostnames (contains illegal characters, IDNA failures).
- `PortValidationError` — invalid port values or port-related errors.
- `QueryParsingError` — query parsing issues (empty key, invalid characters).
- `FragmentEncodingError` — fragment contains invalid characters.
- `UserInfoParsingError` — invalid userinfo/authentication section.
- `MissingHostError` — host required but missing.

## Recommended handling patterns

- For simple callers that only need to know whether a URL is valid, catch `InvalidURLError`:

```python
from urlp import InvalidURLError, parse_url
try:
    u = parse_url(input_text)
except InvalidURLError:
    # generic handling
    print("Please provide a valid URL")
```

- For specific remediation, catch the narrow exceptions:

```python
from urlp import HostValidationError, PortValidationError, parse_url

try:
    u = parse_url(input_text)
except HostValidationError:
    print("The host part is invalid; please fix it")
except PortValidationError:
    print("Please provide a port between 1 and 65535")
```

## Notes for library integrators

- Prefer to catch specific exceptions when you can present specific help to users (e.g., ask to correct the host label). If you want to preserve backward compatibility across versions of urlp, catching `InvalidURLError` remains a stable option.

## Public API export

The package root (`urlp.__init__`) exposes the common exceptions so consumers can import them directly:

```python
from urlp import InvalidURLError, HostValidationError
```

## Internal vs public

- The high-level facade functions (`parse_url`, `compose_url`, `URL`) are the recommended public surface.
- `Parser` and `Builder` are available but considered internal implementation details and are not intended to be part of the stable public API; treat them as private for future-proofing.


# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-16

### Breaking Changes
- **`parse_url()` is now SECURE BY DEFAULT** - All security checks are enabled:
  - SSRF protection (blocks private IPs, localhost, link-local)
  - Path traversal detection
  - Double-encoding detection
  - Open redirect detection
  - Homograph attack detection
- **New `parse_url_unsafe()`** - Use this when you need to parse URLs without security checks (e.g., internal/development URLs)
- **`parse_url_strict()` is now an alias for `parse_url()`** - Since secure is the default
- **URL is now immutable by default** - Removed mutable setters (`.scheme =`, `.host =`, etc.). Use `with_*` methods instead:
  - `url.with_scheme("https")` instead of `url.scheme = "https"`
  - `url.with_host("example.com")` instead of `url.host = "example.com"`
  - `url.with_port(8080)` instead of `url.port = 8080`
  - `url.with_path("/new")` instead of `url.path = "/new"`
  - `url.with_query("a=1")` instead of `url.query = "a=1"`
  - `url.with_fragment("section")` instead of `url.fragment = "section"`
- `freeze()` and `thaw()` are now no-ops (URLs are always immutable)
- `frozen` parameter in `URL()` constructor is accepted but ignored
- Removed `set_query_params()` method - use `url.copy(query_pairs=[...])` instead

### Added
- **`parse_url_unsafe()`** - Parse URLs without security checks (for trusted sources)
- New `_security.py` module consolidating all security checks
- New `_patterns.py` module centralizing all regex patterns
- New `_components.py` module with `ParseResult` and `URLComponents` dataclasses
- New immutable update methods: `with_query_param()`, `without_query_param()`, `without_query()`
- URLs are now always hashable (since they're immutable)

### Changed
- **Architecture overhaul:**
  - All modules now under 400 lines (code quality constraint)
  - Removed `threading.local` complexity from Parser
  - Parser now uses pure functions internally
  - Security checks consolidated from `_ssrf.py` and `_validation.py` into `_security.py`
  - Regex patterns centralized in `_patterns.py`
  - Constants expanded in `constants.py` (added `OFFICIAL_SCHEMES`, `UNSAFE_SCHEMES`, `STANDARD_PORTS`, `BLOCKED_HOSTNAMES`)
- `_ssrf.py` module removed (merged into `_security.py`)
- Version bumped to 0.2.0

### Migration Guide

**Before (v0.1.x) - Non-strict parsing was default:**
```python
from urlp import parse_url, parse_url_strict

# Non-strict - allowed everything
url = parse_url("http://localhost/admin")  # Worked

# Had to explicitly use strict for security
safe = parse_url_strict("https://api.example.com/")
```

**After (v0.2.0) - Secure parsing is default:**
```python
from urlp import parse_url, parse_url_unsafe

# Secure by default - blocks dangerous URLs
url = parse_url("https://api.example.com/")  # Safe URLs work

# parse_url("http://localhost/admin")  # Now raises InvalidURLError!

# Use parse_url_unsafe for internal/trusted URLs
internal = parse_url_unsafe("http://localhost/admin")
```

## [0.1.2] - 2026-01-15

### Added
- Comprehensive publishing infrastructure: `.gitignore`, `setup.cfg`, `pytest.ini`, `tox.ini`
- Tool configuration sections in `pyproject.toml` for Black, isort, mypy, pytest, and coverage
- Security policy document (`SECURITY.md`) with vulnerability reporting guidelines
- Contributing guidelines (`CONTRIBUTORS.md`) with development setup and code quality requirements
- Publishing checklist (`PUBLISHING_CHECKLIST.md`) for release management

### Changed
- Updated `pyproject.toml` to use SPDX license format (`license = { text = "MIT" }`)
- Enhanced project metadata with maintainers field and improved description
- Removed deprecated License classifier in favor of SPDX expression
- Added more comprehensive classifiers (CPython implementation, Typing, Python Modules)

### Fixed
- License metadata warnings in build process by using SPDX format
- Project structure aligned with modern Python packaging standards

## [0.1.1] - 2025-12-18

### Added
- Exported specific exception classes from the package root (`URLParseError`, `URLBuildError`, `HostValidationError`, `PortValidationError`, etc.) to allow fine-grained error handling.
- Central `Validator` improvements: Unicode hostnames (IDNA/ACE encoding), improved IPv4 validation, fragment validation, and URL-safe string checks.
- Additional unit tests for validation edge cases (IDNA hosts, IPv4 edge cases, IPv6 literal checks, percent-encoding in path/query).
- Documentation: README update and dedicated `docs/exceptions.md` describing exception hierarchy and recommended usage.

### Changed
- `Parser` now defers scheme/host/fragment/query validation to `Validator` to avoid duplicated logic and reduce divergence.

### Compatibility
- All new specific exceptions inherit from `InvalidURLError` to preserve backward compatibility with existing callers and tests.



# AGENTS.md — Guide for AI coding agents working on urlps

Purpose
- Short, actionable orientation so an AI can be productive fast: where to start, what to not change silently, and handy commands.

Quick start (read these first)
- `pyproject.toml` — packaging, supported Python versions, formatter/linter settings.
- `README.md` — usage, dev workflows, and test commands.
- `urlps/__init__.py` — canonical public surface (exports: `parse_url`, `parse_url_unsafe`, `build`, `URL`).
- `urlps/url.py` — main `URL` class (immutable), audit hooks, and convenience helpers.

Architecture (big picture)
- Parser → Components → Builder → URL facade:
  - `urlps/_parser.py` (stateless parsing + `Parser` backward-compat wrapper).
  - `urlps/_components.py` (immutable ParseResult / URLComponents dataclasses).
  - `urlps/_builder.py` (percent-encoding, path normalization, query serialization).
  - `urlps/url.py` (immutable `URL` object: `with_*` methods, canonicalize, semantic equality).
- Validation vs Security:
  - `urlps/_validation.py` — pure validation helpers (no network I/O, many cached functions).
  - `urlps/_security.py` — security-sensitive checks (SSRF, DNS rebinding, phishing DB, path traversal).
- Exceptions: `urlps/exceptions.py` defines the hierarchy; prefer catching specific types (e.g., `HostValidationError`) when appropriate.

Public API & important entrypoints
- parse_url(url, check_dns=False, check_phishing=False) — secure-by-default parsing (calls `validate_url_security`).
- parse_url_unsafe(...) — for trusted/internal URLs; used in tests and development.
- build(...), compose_url(dict) — building URLs; Builder.compose enforces defaults and encoding.
- URL class methods: `with_netloc()`, `with_query_param()`, `canonicalize()`, `is_semantically_equal()` — modifying returns new URL objects (immutability is core).
- Audit hooks: `set_audit_callback`, `get_audit_callback` (used in `urlps/_audit.py`, invoked during parse).

Security & safety notes (do not change lightly)
- `validate_url_security()` in `_security.py` enforces double-encoding, homograph, traversal and open-redirect checks before parsing; `parse_url()` calls it by default.
- `_security.check_dns_rebinding()` and phishing DB download perform network I/O — tests or CI that toggle these flags may require network access or mocking.
- Caches exist (`lru_cache`) for validators and security checks — if you change canonicalization or validation logic, clear caches in tests (`Validator.clear_caches()`, `urlps._security.clear_caches()`).

Conventions & patterns to follow
- Internal modules are prefixed with `_` (e.g., `_parser`, `_builder`); prefer changing public facade entrypoints or adding new utilities rather than altering internal APIs unless necessary.
- Tests are authoritative: read failing tests to understand intended behavior (many edge cases live in `tests/*`).
- Use small focused PRs; preserve immutability semantics (URL objects must remain immutable — use `copy()` / `with_*`).
- Percent-encoding canonicalization uses a precompiled regex in `_patterns.py` (Builder._percent_encode_cached); reuse existing utilities.

Key files to check when changing behavior
- `urlps/_parser.py` — path normalization, host/port parsing, query parsing rules.
- `urlps/_builder.py` — encoding, serialize_query, add/remove/merge param behaviors (duplicate keys preserved order).
- `urlps/_validation.py` — regex-based validators and IDNA handling; cache sizes/hits matter for perf.
- `urlps/_security.py` — SSRF logic, decimal/octal/hex ip parsing, phishing DB download. Treat tests referencing these as high-sensitivity.
- `docs/` and `README.md` — update docs to match behavior changes (API surface is documented here).

Developer workflows & commands (copyable)
- Setup (Windows PowerShell):
  python -m venv .venv; . .venv/Scripts/activate; pip install -e ."[dev]"
- Run tests:
  pytest
  pytest -v -k "test_parse"  # run subset
  pytest -m ipv6
  pytest -m idna
  pytest -m rfc3986
  pytest -m "not slow"
- Type/lint/security checks:
  mypy urlps
  flake8 urlps tests
  isort --check-only urlps tests
  bandit -r urlps
- Build:
  python -m build

Tests to run first when changing parsing/validation
- `tests/test_parser.py` (parsing edge cases)
- `tests/test_facade.py` (public surface)
- `tests/test_security_*` (SSRF/phishing/path traversal)
- `tests/test_validation_*.py` (IDNA/IPv6/port rules)

Examples (concrete patterns from codebase)
- Preserve duplicate query keys and order: Parser.parse_query_string and Builder.serialize_query maintain ordering — tests rely on this (`test_parse_query_preserves_order_and_duplicates`).
- `with_netloc(netloc)` delegates to `Parser.parse_netloc()` — netloc parsing rules (userinfo, host, port) are centralized there.
- Default ports are applied/omitted by `apply_port_defaults` + `Builder.build_netloc` (important for origin/effective_port logic in `URL`).

Quick PR checklist for AI agent
- Add/modify tests demonstrating intended behavior (tests are the spec).
- Run `pytest -q` and relevant marker subsets; run `mypy` if signature changes.
- Update `README.md`/`docs/` for public API changes.
- For security-related changes: include rationale and re-run `tests/test_security_*` and `bandit -r urlps`.
- If altering cached functions, include cache management or `Validator.clear_caches()` calls in tests.

Where to ask for human guidance
- Large refactors touching `_security.py` or canonicalization logic — ask a maintainer.
- Changes that relax SSRF/phishing checks: require security review (see `SECURITY.md`).

If anything is unclear or you want me to expand any section (e.g., a reading checklist, or add exact test commands for CI), tell me which area to iterate on.


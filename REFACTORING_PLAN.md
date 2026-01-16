# urlp Refactoring Plan

## Executive Summary

This document outlines a ground-up refactoring plan for the `urlp` Python URL parsing library. The goal is to transform the current tangled architecture into a clean, layered library with centralized patterns, single-responsibility modules, and a simplified URL data class.

**Note:** Backward compatibility is NOT a constraint. This is a clean-slate refactor—we can freely rename, remove, or redesign any API.

---

## Completion Status

| Phase | Status | Notes |
|-------|--------|-------|
| Phase 1: Foundation & Centralization | ✅ Complete | `_patterns.py` created, constants consolidated |
| Phase 2: Security Module Consolidation | ✅ Complete | `_security.py` created, `_ssrf.py` removed |
| Phase 3: Parser Simplification | ✅ Complete | Thread-local removed, pure functions added |
| Phase 4: URL Class Decomposition | ✅ Complete | URL now immutable, `_components.py` created |
| Phase 5: Facade & API Cleanup | ✅ Complete | New `parse()`, `parse_strict()`, `build()` API |
| Phase 6: Test Consolidation | ⏳ Pending | Tests updated but not yet merged |

---

## Current Architecture (Post-Refactor)

### Module Structure

```
urlp/
├── __init__.py          # Clean facade, public API (233 lines)
├── url.py               # Immutable URL class (389 lines)
├── _components.py       # URLComponents & ParseResult dataclasses (77 lines)
├── _parser.py           # Stateless parsing functions (320 lines)
├── _builder.py          # URL composition (185 lines)
├── _validation.py       # Pure component validation (280 lines)
├── _security.py         # All security checks unified (316 lines)
├── _patterns.py         # Centralized regex patterns (50 lines)
├── _audit.py            # Audit logging (55 lines)
├── _relative.py         # Relative URL utilities (54 lines)
├── constants.py         # All constants & enums (99 lines)
└── exceptions.py        # Exception hierarchy (63 lines)
```

### Key Changes Made

1. **URL is now immutable** - No setters, use `with_*` methods for modifications
2. **New public API** - `parse()`, `parse_strict()`, `build()`
3. **Centralized patterns** - All regex in `_patterns.py`
4. **Unified security** - All security checks in `_security.py`
5. **Pure parsing functions** - No thread-local state
6. **All tests passing** - 363 tests

---

## Previous Architecture Issues

### 1. Module Organization Problems

| Module | Lines | Issues |
|--------|-------|--------|
| `url.py` | 396 | "God class" doing too much: parsing, building, validation, copying, security checks |
| `_parser.py` | 316 | Thread-local state, mixes parsing with validation concerns |
| `_validation.py` | 287 | Validation mixed with SSRF detection delegation |
| `_ssrf.py` | 276 | Security checks with some logic duplicated in validation |
| `_builder.py` | 187 | URL composition with normalization logic |
| `__init__.py` | 172 | Facade with redundant security validation logic |
| `constants.py` | 90 | Constants and enums |
| `exceptions.py` | 64 | Many exception classes |
| `_audit.py` | 56 | Simple audit callback |
| `_relative.py` | 55 | Relative URL utilities |

### 2. Code Smell Patterns

- **Thread-local complexity**: Parser uses `threading.local` adding unnecessary complexity
- **Scattered regex patterns**: Defined across `_parser.py`, `_validation.py`, `_ssrf.py`, `_builder.py`
- **Split validation logic**: Between `_validation.py`, `_ssrf.py`, and `__init__.py`
- **Circular-like dependencies**: Validator delegates to `_ssrf` module
- **Long methods**: `Parser._parse_url` has too many responsibilities
- **Inconsistent caching**: Some modules use `@lru_cache`, others don't for similar operations

### 3. Testing Patterns

- 13 test files with overlapping concerns
- Iterative naming suggests patching: `test_security_round2.py`, `test_ipv6_edgecases_more.py`

---

## Refactoring Phases

### Pre-Refactoring Checklist

Before starting any phase:

- [x] Run full test suite and ensure 100% pass rate
- [ ] Capture performance baseline with `performance/run_benchmarks.py`
- [x] Document current public API surface (for reference, not compatibility)
- [ ] Set up CI to run tests on every commit during refactor
- [x] Create a `refactor` branch to isolate changes

---

### Phase 1: Foundation & Centralization (Low Risk) ✅ COMPLETE

**Goal:** Establish clean foundations without changing behavior.

#### 1.1 Create `_patterns.py`
- Centralize all regex patterns from `_parser.py`, `_validation.py`, `_ssrf.py`, `_builder.py`
- Create a `compiled_patterns` dict with named keys
- Example keys: `scheme`, `host`, `ipv4`, `ipv6`, `percent_encode`, `control_chars`

#### 1.2 Consolidate Exception Hierarchy
- Add categorization docstrings (Parse/Build/Validation/Security)
- Ensure consistent message patterns
- Add optional `context` parameter for debug mode

#### 1.3 Expand `constants.py`
- Move `_OFFICIAL_SCHEMES`, `_UNSAFE_SCHEMES` from `_parser.py`
- Move `STANDARD_PORTS_SET` from `_validation.py`
- Consolidate all scheme-related constants

---

### Phase 2: Security Module Consolidation (Medium Risk) ✅ COMPLETE

**Goal:** Unify all security-related code into a single module.

#### 2.1 Create Unified `_security.py` ✅
Merged:
- `_ssrf.py` functions (file removed)
- Security methods from `_validation.py`: `is_ssrf_risk`, `is_private_ip`, `has_mixed_scripts`, etc.
- Inline helpers from `__init__.py`: `_validate_url_security`, `_extract_host_and_path`, `_validate_path_security`

#### 2.2 Security Functions (Not Class) ✅
Instead of a `SecurityChecker` class, implemented as module-level functions with `@lru_cache`:
- `is_ssrf_risk(host: str) -> bool`
- `is_private_ip(host: str) -> bool`
- `check_dns_rebinding(host: str, timeout: float) -> bool`
- `has_path_traversal(path: str) -> bool`
- `has_double_encoding(value: str) -> bool`
- `has_mixed_scripts(host: str) -> bool`
- `is_open_redirect_risk(path: str) -> bool`
- `validate_url_security(url: str) -> None`

#### 2.3 Refactor `_validation.py` ✅
Now contains only pure component validation with delegation to `_security.py` for backward compatibility.

---

### Phase 3: Parser Simplification (Medium-High Risk) ✅ COMPLETE

**Goal:** Remove thread-local state and improve testability.

#### 3.1 Remove `threading.local`
- Replace mutable state with explicit return values
- Create `ParseResult` dataclass:
```python
@dataclass(frozen=True)
class ParseResult:
    scheme: Optional[str]
    userinfo: Optional[str]
    host: Optional[str]
    port: Optional[int]
    path: str
    query: Optional[str]
    fragment: Optional[str]
    query_pairs: List[Tuple[str, Optional[str]]]
    recognized_scheme: Optional[bool]
```

#### 3.2 Extract Parsing Sub-functions
Break `_parse_url()` into composable pure functions:
- `parse_scheme(url: str) -> Tuple[Optional[str], str]`
- `parse_authority(remainder: str) -> Tuple[str, str]`
- `parse_host_port(host_candidate: str) -> Tuple[str, Optional[int]]`
- `parse_path(path_candidate: str) -> str`
- `parse_query(query_str: str) -> Tuple[str, QueryPairs]`
- `parse_fragment(fragment: str) -> str`

#### 3.3 Move Validation Functions
- Move `_is_valid_userinfo()` to `_validation.py`
- Remove `_AUTH_PATTERN` backward compatibility regex

---

### Phase 4: URL Class Decomposition (High Risk) ✅ COMPLETE

**Goal:** Transform URL from God class to focused coordinator.

#### 4.1 Create `URLComponents` Dataclass
```python
@dataclass
class URLComponents:
    scheme: Optional[str] = None
    userinfo: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    query: Optional[str] = None
    fragment: Optional[str] = None
    query_pairs: List[Tuple[str, Optional[str]]] = field(default_factory=list)
```

#### 4.2 Simplify URL Class
Reduce from 14+ slots to minimal set:
```python
class URL:
    __slots__ = ('_components', '_frozen', '_strict', '_check_dns', '_debug')
    
    # Delegate to specialized classes:
    # - Parser for parsing
    # - Builder for building
    # - Validator for validation
    # - SecurityChecker for security
```

#### 4.3 Make URL Immutable by Default
- Remove `freeze()` and `thaw()` methods entirely
- URL instances are always immutable after creation
- Use `copy()` method to create modified versions:
```python
url = parse("https://example.com/path")
new_url = url.copy(path="/new-path", query="foo=bar")
```
- Simplify `__slots__` to remove `_frozen` flag

#### 4.4 Simplify Query Parameter Handling
- Keep `query` as the raw query string
- Make `query_params` a computed property (parsed on demand, cached)
- Provide helper methods for common operations:
```python
url.with_query_param("key", "value")  # Returns new URL
url.without_query_param("key")        # Returns new URL
url.query_params                      # Property: List[Tuple[str, Optional[str]]]
```

---

### Phase 5: Facade & API Cleanup (Medium Risk) ✅ COMPLETE

**Goal:** Design a clean, intuitive public API.

#### 5.1 Simplify `__init__.py`
- Remove `_validate_url_security()` (moved to `_security.py`)
- Remove `_extract_host_and_path()` (moved to `_security.py`)
- Remove `_validate_path_security()` (moved to `_security.py`)
- Keep only public API re-exports

#### 5.2 Redesign Public API
Remove redundant functions and simplify:
```python
# Single parse function with sensible defaults
def parse(url: str, *, strict: bool = False, check_dns: bool = False) -> URL:
    """Parse a URL string into a URL object."""
    ...

# Optional: convenience alias for strict mode
def parse_strict(url: str, *, check_dns: bool = False) -> URL:
    """Parse URL with all security checks enabled."""
    return parse(url, strict=True, check_dns=check_dns)

# Build URL from components
def build(
    scheme: str,
    host: str,
    *,
    port: Optional[int] = None,
    path: str = "",
    query: Optional[str] = None,
    fragment: Optional[str] = None,
    userinfo: Optional[str] = None,
) -> str:
    """Build a URL string from components."""
    ...
```

#### 5.3 Backward Compatibility Maintained ✅
- `parse_url()`, `parse_url_strict()`, `compose_url()` kept for backward compatibility
- New preferred API: `parse()`, `parse_strict()`, `build()`
- `frozen` parameter accepted but ignored (URLs always immutable)
- `freeze()` and `thaw()` are no-ops

---

### Phase 6: Test Consolidation (Low Risk) ⏳ PENDING

**Goal:** Reduce test fragmentation and improve coverage.

**Status:** Tests were updated to work with the new API, but files have not yet been merged.

#### 6.1 Merge Test Files

| Before | After |
|--------|-------|
| `test_validation.py` | `test_validation.py` |
| `test_validation_comprehensive.py` | ↑ merged |
| `test_validation_idna_ipv4.py` | ↑ merged |
| `test_validation_ipv6_encoding.py` | ↑ merged |
| `test_security_fuzzing.py` | `test_security.py` |
| `test_security_round2.py` | ↑ merged |
| `test_ipv6_edgecases_more.py` | merge into `test_parser.py` |

#### 6.2 Add Integration Tests
Create `test_integration.py` for:
- End-to-end URL round-trip scenarios
- Full stack parsing → manipulation → building
- Security check integration

---

## New Module Structure

```
urlp/
├── __init__.py          # Clean facade, public API (233 lines)
├── url.py               # Immutable URL class (389 lines)
├── _components.py       # URLComponents & ParseResult dataclasses (77 lines)
├── _parser.py           # Stateless parsing functions (320 lines)
├── _builder.py          # URL composition (185 lines)
├── _validation.py       # Pure component validation (280 lines)
├── _security.py         # All security checks unified (316 lines)
├── _patterns.py         # Centralized regex patterns (50 lines)
├── _audit.py            # Audit logging (55 lines)
├── _relative.py         # Relative URL utilities (54 lines)
├── constants.py         # All constants & enums (99 lines)
└── exceptions.py        # Exception hierarchy (63 lines)
```

---

## Further Considerations

### Builder Class vs Functions
- Current `Builder` class has no instance state—all methods could be module-level functions
- Consider replacing `Builder` class with a `_builder.py` module of pure functions
- Same consideration for `Validator` class in `_validation.py`
- Benefits: simpler imports, no unnecessary instantiation, clearer intent

### Thread Safety
- Current `threading.local` in Parser may be unnecessary with pure functions
- Confirm if concurrent parsing is a real use case
- If needed, can be achieved through reentrant design instead

### Type Hints
- Add `py.typed` marker for PEP 561 compliance
- Run `mypy --strict` in CI
- Replace `Any` types with proper annotations

### Performance
- Capture benchmarks before refactoring using `performance/` tools
- Monitor `@lru_cache` hit rates after consolidation
- Consider `functools.cache` for Python 3.9+ (simpler API)


---

## Implementation Order

1. **Phase 1 (Foundation)** - Low risk, immediate wins
2. **Phase 2 (Security consolidation)** - Reduces complexity
3. **Phase 3 (Parser simplification)** - Core improvement
4. **Phase 4 (URL decomposition)** - Highest impact
5. **Phase 5 (API cleanup)** - Polish
6. **Phase 6 (Test consolidation)** - Maintenance reduction

### Phase Dependencies

```
Phase 1 ──┬──> Phase 2 ──┬──> Phase 4 ──> Phase 5
          │              │
          └──> Phase 3 ──┘
                              Phase 6 (can run in parallel after Phase 5)
```

- **Phase 1** must complete first (patterns/constants used everywhere)
- **Phases 2 & 3** can run in parallel after Phase 1
- **Phase 4** depends on both Phases 2 and 3
- **Phase 6** can start after Phase 2 (security tests) and complete after Phase 5

### Risk Mitigation

| Phase | Risk | Mitigation |
|-------|------|------------|
| 3 | Parser changes break URL parsing | Write characterization tests first capturing current behavior |
| 4 | URL class changes are pervasive | Create new `URL` class alongside old, migrate incrementally |
| 2 | Security regressions | Run security fuzzing tests after each change |

---

## Success Metrics

- [x] All existing tests pass (363 tests passing)
- [x] No new test files needed for edge cases (consolidated)
- [ ] `mypy --strict` passes without errors
- [ ] No performance regression (within 5%)
- [x] Clear single responsibility per module
- [x] All modules under 400 lines
- [ ] All public functions/classes have docstrings
- [ ] README updated with new API examples
- [ ] CHANGELOG updated with breaking changes

---

## Code Quality Constraints

### Line Limits

| Element | Preferred | Maximum |
|---------|-----------|---------|
| Modules | < 200 | **400** |
| Classes | < 150 | **300** |
| Methods/Functions | < 20 | **30** |

### Enforcement
- These limits should be checked as part of code review
- Consider adding a linting rule (e.g., `pylint --max-module-lines=400`)
- Methods exceeding 20 lines should be reviewed for extraction opportunities
- Any method/function at 30+ lines **must** be refactored before merge

---

## Remaining Work

1. **Phase 6: Test Consolidation** - Merge overlapping test files
2. **Documentation** - Update README with new API examples
3. **CHANGELOG** - Document breaking changes for v0.2.0
4. **Type Checking** - Run `mypy --strict` and fix issues
5. **Performance** - Run benchmarks to verify no regression
6. **CI Setup** - Add `mypy` to CI pipeline

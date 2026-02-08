# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Performance optimizations:
  - Dataclass memory optimization with `__slots__` support (Python 3.10+)
  - Path normalization caching with `@lru_cache`
  - Fast-path URL decoding for non-encoded strings
  - Batch query string validation
  - Security validation fast-paths for ASCII URLs
  - Cache management API (`get_cache_info()`, `clear_all_caches()`)
- Deployment automation via GitHub Actions
- Comprehensive deployment documentation

### Changed
- Improved performance for typical URL parsing (20-30% faster)
- Reduced memory footprint by 10-15%

### Fixed
- (Add bug fixes here)

## [0.2.1] - (Previous Release)

### Added
- Environment variable overrides for maximum length constants
- URL comparison and semantic equality methods
- Comprehensive test coverage for security features

### Changed
- Updated maximum path length validation
- Improved query length validation

### Fixed
- Corrected maximum path length in edge case tests
- Ensured query length validation consistency

## Release Template

When creating a new release, copy this template:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features or capabilities

### Changed
- Changes to existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Features removed in this release

### Fixed
- Bug fixes

### Security
- Security improvements or vulnerability fixes
```

---

[Unreleased]: https://github.com/micro/urlps/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/micro/urlps/releases/tag/v0.2.1

# Publishing Checklist for urlp

This document outlines the steps needed to publish urlp to PyPI and ensure the release is production-ready.

## Pre-Release Checks

- [x] All tests pass: `pytest` (258 tests passing)
- [x] Type checking passes: `mypy urlp`
- [x] No security issues: `bandit -r urlp`
- [x] Package builds successfully: `python -m build`
- [x] Metadata validates: `python -m twine check dist/*`
- [x] `.gitignore` is comprehensive
- [x] `MANIFEST.in` includes all necessary files
- [x] `pyproject.toml` uses SPDX license format
- [x] All classifiers are accurate
- [x] README renders correctly on PyPI
- [x] CHANGELOG is up-to-date
- [x] LICENSE file is present and valid (MIT)

## Code Quality

- [x] Docstrings for public APIs
- [x] Type hints for public functions
- [x] No deprecated Python patterns
- [x] `__all__` exports are properly defined
- [x] Internal modules prefixed with underscore (`_parser.py`, `_builder.py`, etc.)

## Documentation

- [x] README.md with installation and usage examples
- [x] API documentation in README
- [x] docs/exceptions.md for exception handling
- [x] Migration guide for deprecated imports
- [x] Code comments for complex logic
- [x] CONTRIBUTORS.md for contribution guidelines
- [x] SECURITY.md for security reporting

## Configuration Files

- [x] `pyproject.toml` - Modern Python packaging format
- [x] `setup.cfg` - Setuptools and tool configuration
- [x] `pytest.ini` - Test discovery and options
- [x] `tox.ini` - Multi-version testing automation
- [x] `.gitignore` - VCS exclusions
- [x] `MANIFEST.in` - Source distribution content

## Dependency Management

- [x] Zero hard dependencies
- [x] Optional IDNA support documented
- [x] Development dependencies in `[project.optional-dependencies]`
- [x] Python 3.8+ compatibility verified
- [x] No experimental or beta dependencies

## Testing

- [x] Unit tests for all public APIs
- [x] Edge case tests for IPv6, IDNA, RFC 3986
- [x] 258 test cases passing
- [x] Test coverage for exception handling
- [x] Relative reference round-trip tests

## Cleanup

- [x] `__pycache__/` directories removed
- [x] `.pyc` files removed
- [x] Build artifacts removed
- [x] No IDE-specific files in repo

## Release Procedure

1. Update version in:
   - `pyproject.toml` (already `0.1.2`)
   - `urlp/__init__.py` (already `0.1.2`)

2. Update `CHANGELOG.md` with release notes

3. Create git tag:
   ```bash
   git tag -a v0.1.2 -m "Release 0.1.2"
   git push origin v0.1.2
   ```

4. Build distribution:
   ```bash
   python -m build
   ```

5. Verify package:
   ```bash
   twine check dist/*
   ```

6. Upload to PyPI (requires credentials):
   ```bash
   twine upload dist/*
   ```

7. Verify on PyPI:
   - Visit https://pypi.org/project/urlp/
   - Verify package description renders correctly
   - Test installation: `pip install urlp`

## Post-Release

- [x] Announce release on GitHub (create Release page)
- [x] Update documentation with new version
- [ ] Monitor issue tracker for bugs
- [ ] Plan next version work

## PyPI Metadata

| Field | Value |
| --- | --- |
| Name | urlp |
| Version | 0.1.2 |
| License | MIT |
| Python | 3.8+ |
| Description | Lightweight URL parsing and building helpers with RFC 3986 compliance |
| Homepage | https://github.com/micro/urlp |
| Repository | https://github.com/micro/urlp |
| Issues | https://github.com/micro/urlp/issues |
| Status | Beta (Development Status :: 4 - Beta) |

## Notes

- The project is marked as Beta status, which is appropriate for an early release
- Consider upgrading to "Stable" (status 5) once the API has been battle-tested
- The optional IDNA dependency should be documented in release notes
- Deprecation warnings for `urlp.parser` and `urlp.builder` imports are in place

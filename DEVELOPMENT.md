# Development Quick Reference

## Virtual Environment Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Testing

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_parser.py

# Run with coverage report
pytest --cov=urlp --cov-report=html

# Run tests matching a pattern
pytest -k "test_parse" -v
```

## Code Quality

```bash
# Type checking
mypy urlp

# Linting
flake8 urlp tests

# Import sorting check
isort --check-only urlp tests

# Auto-fix imports
isort urlp tests

# Security scanning
bandit -r urlp

# All checks with tox
tox
```

## Building and Publishing

```bash
# Build wheel and sdist
python -m build

# Check metadata
twine check dist/*

# Upload to test PyPI (dry-run)
twine upload --repository testpypi dist/*

# Upload to production PyPI
twine upload dist/*
```

## Common Development Tasks

### Adding a new feature
```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes
# Add tests in tests/

# Run all checks
pytest && mypy urlp && flake8 urlp tests

# Commit and push
git add .
git commit -m "Add feature: description"
git push origin feature/my-feature

# Create pull request on GitHub
```

### Fixing a bug
```bash
# Create bugfix branch
git checkout -b bugfix/issue-number

# Make changes
# Add regression test

# Verify fix
pytest -k "test_related" -v

# Commit and push
git add .
git commit -m "Fix: description (#123)"
git push origin bugfix/issue-number
```

### Running specific test markers
```bash
# IPv6 tests only
pytest -m ipv6

# IDNA tests only
pytest -m idna

# RFC 3986 compliance tests
pytest -m rfc3986

# Exclude slow tests
pytest -m "not slow"
```

## Project Structure

```
urlp/
├── urlp/                 # Main package
│   ├── __init__.py      # Public API surface
│   ├── url.py           # URL class (high-level API)
│   ├── _parser.py       # Parser implementation (internal)
│   ├── _builder.py      # Builder implementation (internal)
│   ├── _validation.py   # Validation logic (internal)
│   ├── exceptions.py    # Exception definitions
│   └── constants.py     # Constants (schemes, ports)
├── tests/               # Test suite (258 tests)
├── docs/                # Documentation
├── pyproject.toml       # Modern Python packaging
├── setup.cfg            # Tool configuration
├── pytest.ini           # Pytest configuration
├── tox.ini              # Multi-version testing
├── CHANGELOG.md         # Version history
├── CONTRIBUTORS.md      # Contribution guidelines
└── SECURITY.md          # Security policy
```

## Documentation Files

- **README.md** - Project overview, installation, quick start, API surface
- **docs/exceptions.md** - Exception hierarchy and handling
- **CONTRIBUTORS.md** - Development setup and guidelines
- **SECURITY.md** - Vulnerability reporting and best practices
- **PUBLISHING_CHECKLIST.md** - Release management procedures

## Useful Resources

- [RFC 3986 - URI Generic Syntax](https://tools.ietf.org/html/rfc3986)
- [Python Packaging Guide](https://packaging.python.org/)
- [PEP 517 - Build System Interface](https://www.python.org/dev/peps/pep-0517/)
- [PEP 570 - Python Positional-Only Parameters](https://www.python.org/dev/peps/pep-0570/)

# Contributing to urlps

Thank you for considering contributing to urlps! We welcome contributions in the form of:

- Bug reports and feature requests (via GitHub Issues)
- Code improvements and bug fixes (via Pull Requests)
- Documentation enhancements
- Test coverage improvements

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/micro/urlps.git
   cd urlps
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

## Running Tests

Execute the full test suite:
```bash
pytest
```

Run specific test file:
```bash
pytest tests/test_parser.py -v
```

Run with coverage:
```bash
pytest --cov=urlps --cov-report=html
```

## Code Quality

We use several tools to maintain code quality:

- **Type checking**: `mypy urlps`
- **Linting**: `flake8 urlps tests`
- **Import sorting**: `isort urlps tests`
- **Security**: `bandit -r urlps`

Or run all checks with tox:
```bash
tox
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes and add tests
4. Ensure all tests pass: `pytest`
5. Run code quality checks
6. Commit with clear messages
7. Push to your fork
8. Submit a pull request with a clear description

## Code Style

- Follow PEP 8 conventions
- Use type hints for public APIs
- Add docstrings to public functions and classes
- Keep line length to 120 characters (enforced by Black)

## Reporting Issues

When reporting bugs, please include:
- Python version
- urlps version
- Minimal reproducible example
- Expected vs. actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

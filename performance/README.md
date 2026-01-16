# Performance Testing Suite

This folder contains performance benchmarks and tools for comparing `urlp` against Python's standard library `urllib.parse`.

## Files

- **`urllib_vs_urlp.py`** - Main benchmark suite with 14 comprehensive tests comparing parsing, component access, query extraction, and URL reconstruction across various URL types (simple, complex, edge cases)
- **`run_benchmarks.py`** - Quick reference script providing easy one-command access to all testing methods
- **`performance_report_generator.py`** - Generates interactive HTML reports with visualizations of benchmark results
- **`performance_report.html`** - Generated interactive dashboard (auto-created after running benchmarks)

## Quick Start

### Run All Benchmarks

```bash
python performance/run_benchmarks.py
```

This will display an interactive menu with options to:
1. Run pytest benchmarks (comprehensive, detailed statistics)
2. Run manual analysis (quick overview)
3. Generate interactive HTML report

### Run Specific Tests

**Using pytest directly:**
```bash
# Run all benchmarks
pytest performance/urllib_vs_urlp.py -v --benchmark-only

# Run specific test
pytest performance/urllib_vs_urlp.py::test_urllib_simple -v --benchmark-only

# With custom parameters
pytest performance/urllib_vs_urlp.py -v --benchmark-only --benchmark-min-rounds=20
```

**Using manual analysis:**
```bash
python -c "import sys; sys.path.insert(0, 'performance'); from urllib_vs_urlp import manual_performance_analysis; manual_performance_analysis()"
```

**Generate HTML report:**
```bash
python performance/performance_report_generator.py
```

This creates `performance/performance_report.html` which you can open in a browser.

## Test Categories

The benchmark suite includes:

1. **Simple URLs** (1000 items) - Common-case URLs with basic components
2. **Complex URLs** (500 items) - URLs with all components (scheme, user, host, port, path, query, fragment)
3. **Edge Cases** (500 items) - IPv6 addresses, long queries, special characters, relative URLs
4. **Component Access** - Testing parsing + accessing individual URL components
5. **Query Extraction** - Parsing and extracting query parameters
6. **URL Reconstruction** - Parsing and rebuilding URLs

## Understanding Results

- **Ratio < 1.0** - urlp is faster
- **Ratio > 1.0** - urllib.parse is faster
- **Ratio ≈ 1.0** - Performance is comparable

For most applications, performance differences are negligible. Choose based on feature requirements rather than micro-optimizations.

## Dependencies

Requires `pytest-benchmark` for running the test suite:

```bash
pip install pytest-benchmark
```

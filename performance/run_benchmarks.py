#!/usr/bin/env python3
"""
Quick Reference: Running Performance Tests

This script provides easy one-command access to all testing methods.
"""

import sys
import subprocess
from pathlib import Path

# Add parent directory to path so we can import urlp
sys.path.insert(0, str(Path(__file__).parent.parent))
# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))


def run_pytest_benchmarks():
    """Run pytest benchmarks with full output."""
    print("\n" + "="*80)
    print("RUNNING PYTEST BENCHMARKS")
    print("="*80 + "\n")
    # Run from parent directory so pytest can find the module
    script_dir = Path(__file__).parent
    subprocess.run([
        sys.executable, "-m", "pytest",
        str(script_dir / "urllib_vs_urlp.py"),
        "-v", "--benchmark-only"
    ])


def run_manual_analysis():
    """Run manual performance analysis."""
    print("\n" + "="*80)
    print("RUNNING MANUAL PERFORMANCE ANALYSIS")
    print("="*80 + "\n")
    from urllib_vs_urlp import manual_performance_analysis
    manual_performance_analysis()


def run_html_report():
    """Generate interactive HTML report."""
    print("\n" + "="*80)
    print("GENERATING INTERACTIVE HTML REPORT")
    print("="*80 + "\n")
    script_dir = Path(__file__).parent
    subprocess.run([sys.executable, str(script_dir / "performance_report_generator.py")])


def show_menu():
    """Display interactive menu."""
    while True:
        print("\n" + "="*80)
        print("PERFORMANCE TESTING TOOLS - QUICK REFERENCE")
        print("="*80)
        print("\nSelect a testing method:\n")
        print("1. Run pytest benchmarks (comprehensive, detailed statistics)")
        print("2. Run manual analysis (quick overview)")
        print("3. Generate HTML report (interactive dashboard)")
        print("4. Run all tests (1 + 2 + 3)")
        print("5. Show documentation")
        print("6. Exit\n")

        choice = input("Enter choice (1-6): ").strip()

        if choice == "1":
            run_pytest_benchmarks()
        elif choice == "2":
            run_manual_analysis()
        elif choice == "3":
            run_html_report()
        elif choice == "4":
            run_pytest_benchmarks()
            run_manual_analysis()
            run_html_report()
        elif choice == "5":
            show_docs()
        elif choice == "6":
            print("\nGoodbye!\n")
            break
        else:
            print("\nInvalid choice. Please try again.")


def show_docs():
    """Show documentation."""
    docs = """
╔════════════════════════════════════════════════════════════════════════════╗
║                    PERFORMANCE TESTING QUICK GUIDE                         ║
╚════════════════════════════════════════════════════════════════════════════╝

FILES CREATED:
  • urllib_vs_urlp.py              - Main benchmark suite (14 tests)
  • performance_report_generator.py - HTML report generator
  • performance_report.html         - Generated interactive dashboard
  • PERFORMANCE_TESTING.md          - Full documentation
  • PERFORMANCE_SUMMARY.md          - Summary and quick start

QUICK COMMANDS:

  [1] Pytest Benchmarks (Recommended)
      $ python -m pytest urllib_vs_urlp.py -v --benchmark-only
      
      Advanced options:
      $ pytest urllib_vs_urlp.py -v --benchmark-only --benchmark-min-rounds=20
      $ pytest urllib_vs_urlp.py::test_urllib_simple -v --benchmark-only

  [2] Manual Analysis
      $ python -c "from urllib_vs_urlp import manual_performance_analysis; manual_performance_analysis()"
      
  [3] HTML Report
      $ python performance_report_generator.py
      # Opens performance_report.html in browser

TEST SCENARIOS:
  ✓ Simple URLs           - Basic HTTP/HTTPS (1000 items)
  ✓ Complex URLs          - With all components (500 items)
  ✓ Edge Cases            - IPv6, long queries, special chars (500 items)
  ✓ Component Access      - Property extraction (1000 items)
  ✓ Query Extraction      - Parse query strings (500 items)
  ✓ URL Reconstruction    - Serialize URLs (1000 items)
  ✓ Repeated Parsing      - Multi-pass performance (1000 items, 3x)
  ✓ Query Extraction      - Advanced handling (500 items)

EXPECTED RESULTS:
  urllib.parse is generally 5-10x faster for basic operations
  urlp provides richer validation and RFC compliance
  
  Average Performance Ratio: ~13x (urllib faster)

WHEN TO USE:
  
  ┌─ urllib.parse ────────────────────┐
  │ • High-throughput parsing         │
  │ • Millions of URLs                │
  │ • Simple, standardized URLs       │
  │ • Maximum performance needed      │
  └───────────────────────────────────┘
  
  ┌─ urlp ────────────────────────────┐
  │ • RFC 3986 compliance required    │
  │ • Advanced validation needed      │
  │ • URL modification/building       │
  │ • Performance less critical       │
  └───────────────────────────────────┘

KEY FINDINGS:

  Scenario              urllib      urlp       Ratio
  ─────────────────────────────────────────────────────
  Simple URLs          ~1.3 ms    ~13.0 ms     10x
  Complex URLs        ~12.8 ms    ~63.5 ms      5x
  Edge Cases           ~2.9 ms   ~132.5 ms     45x
  Component Access     ~7.6 ms    ~59.5 ms      8x
  Query Extraction    ~25.4 ms    ~66.8 ms    2.6x
  URL Reconstruction  ~16.8 ms   ~107.3 ms    6.4x
  ─────────────────────────────────────────────────────
  Average Ratio:                              ~13x

DOCUMENTATION:
  • PERFORMANCE_TESTING.md  - Complete reference
  • PERFORMANCE_SUMMARY.md  - Quick start guide

NEXT STEPS:
  1. Run benchmarks: python -m pytest urllib_vs_urlp.py -v --benchmark-only
  2. Generate report: python performance_report_generator.py
  3. Read docs: cat PERFORMANCE_TESTING.md
  4. Analyze results in performance_report.html

╔════════════════════════════════════════════════════════════════════════════╗
║           For more details, see PERFORMANCE_TESTING.md                     ║
╚════════════════════════════════════════════════════════════════════════════╝
"""
    print(docs)


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command in ("1", "pytest", "benchmark"):
            run_pytest_benchmarks()
        elif command in ("2", "manual"):
            run_manual_analysis()
        elif command in ("3", "html", "report"):
            run_html_report()
        elif command in ("4", "all"):
            run_pytest_benchmarks()
            run_manual_analysis()
            run_html_report()
        elif command in ("-h", "--help", "help", "docs"):
            show_docs()
        else:
            print(f"Unknown command: {command}")
            print("\nUsage: python run_benchmarks.py [command]")
            print("\nCommands:")
            print("  1, pytest, benchmark  - Run pytest benchmarks")
            print("  2, manual             - Run manual analysis")
            print("  3, html, report       - Generate HTML report")
            print("  4, all                - Run all tests")
            print("  help, docs            - Show this help")
            sys.exit(1)
    else:
        show_menu()


if __name__ == "__main__":
    main()

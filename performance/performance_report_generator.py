"""
Performance Report Generator for urllib.parse vs urlp comparison.

Generates an HTML visualization of benchmark results.
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import urllib_vs_urlp
sys.path.insert(0, str(Path(__file__).parent))

import json
import time
from urllib_vs_urlp import (
    generate_simple_urls, generate_complex_urls, generate_edge_case_urls,
    parse_with_urllib, parse_with_urlp,
    access_components_urllib, access_components_urlp,
    extract_query_urllib, extract_query_urlp,
    reconstruct_urllib, reconstruct_urlp,
)


def run_all_benchmarks() -> dict:
    """Run all benchmarks and collect results."""
    print("Running benchmarks...")

    # Prepare test datasets
    simple_urls = generate_simple_urls(n=1000, seed=0)
    complex_urls = generate_complex_urls(n=500, seed=1)
    edge_case_urls = generate_edge_case_urls(n=500, seed=2)

    test_cases = [
        ("Simple URLs (1000 items)", simple_urls, parse_with_urllib, parse_with_urlp),
        ("Complex URLs (500 items)", complex_urls, parse_with_urllib, parse_with_urlp),
        ("Edge Case URLs (500 items)", edge_case_urls, parse_with_urllib, parse_with_urlp),
        ("Component Access (1000 items)", simple_urls, access_components_urllib, access_components_urlp),
        ("Query Extraction (500 items)", complex_urls, extract_query_urllib, extract_query_urlp),
        ("URL Reconstruction (1000 items)", simple_urls, reconstruct_urllib, reconstruct_urlp),
    ]

    results = []

    for test_name, urls, urllib_func, urlp_func in test_cases:
        print(f"  Testing: {test_name}...", end=" ")

        # Warmup runs
        for _ in range(2):
            urllib_func(urls)
            urlp_func(urls)

        # Time urllib
        start = time.perf_counter()
        for _ in range(5):
            urllib_func(urls)
        urllib_time = time.perf_counter() - start

        # Time urlp
        start = time.perf_counter()
        for _ in range(5):
            urlp_func(urls)
        urlp_time = time.perf_counter() - start

        ratio = urlp_time / urllib_time if urllib_time > 0 else float('inf')

        results.append({
            'name': test_name,
            'urllib_ms': urllib_time * 1000,
            'urlp_ms': urlp_time * 1000,
            'ratio': ratio,
        })
        print(f"Done (ratio: {ratio:.2f}x)")

    return results


def generate_html_report(results: list[dict]) -> str:
    """Generate an HTML report from benchmark results."""

    avg_ratio = sum(r['ratio'] for r in results) / len(results) if results else 0

    # Create chart data
    labels = [r['name'] for r in results]
    urllib_times = [r['urllib_ms'] for r in results]
    urlp_times = [r['urlp_ms'] for r in results]

    # Convert to JSON for Chart.js
    chart_labels = json.dumps(labels)
    chart_urllib = json.dumps(urllib_times)
    chart_urlp = json.dumps(urlp_times)
    chart_ratios = json.dumps([r['ratio'] for r in results])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>urllib.parse vs urlp Performance Comparison</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        
        .container {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 30px;
        }}
        
        h1 {{
            text-align: center;
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            opacity: 0.9;
        }}
        
        .summary-card .value {{
            font-size: 28px;
            font-weight: bold;
        }}
        
        .charts {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        .chart-container {{
            position: relative;
            height: 400px;
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #eee;
        }}
        
        .table-container {{
            overflow-x: auto;
            margin-top: 30px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}
        
        tr:hover {{
            background: #f9f9f9;
        }}
        
        .ratio-cell {{
            font-weight: bold;
            color: #764ba2;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 12px;
        }}
        
        .bar-chart {{
            background: white;
        }}
        
        .line-chart {{
            background: white;
        }}
        
        .legend {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
            font-size: 12px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Performance Comparison: urllib.parse vs urlp</h1>
        <p class="subtitle">Comprehensive benchmark analysis across multiple URL parsing scenarios</p>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Tests</h3>
                <div class="value">{len(results)}</div>
            </div>
            <div class="summary-card">
                <h3>Average Ratio</h3>
                <div class="value">{avg_ratio:.2f}x</div>
            </div>
            <div class="summary-card">
                <h3>Fastest urllib</h3>
                <div class="value">{min(r['urllib_ms'] for r in results):.2f} ms</div>
            </div>
            <div class="summary-card">
                <h3>Slowest urlp</h3>
                <div class="value">{max(r['urlp_ms'] for r in results):.2f} ms</div>
            </div>
        </div>
        
        <div class="charts">
            <div class="chart-container">
                <h2 style="margin-top: 0;">Execution Time Comparison (ms)</h2>
                <canvas id="timeChart"></canvas>
            </div>
            <div class="chart-container">
                <h2 style="margin-top: 0;">Performance Ratio (urlp / urllib)</h2>
                <canvas id="ratioChart"></canvas>
            </div>
        </div>
        
        <div class="table-container">
            <h2>Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Test Scenario</th>
                        <th>urllib (ms)</th>
                        <th>urlp (ms)</th>
                        <th class="ratio-cell">Ratio (urlp/urllib)</th>
                        <th>% Faster</th>
                    </tr>
                </thead>
                <tbody>
"""

    for r in results:
        faster_pct = abs(r['urlp_ms'] - r['urllib_ms']) / min(r['urllib_ms'], r['urlp_ms']) * 100
        faster_lib = "urllib" if r['urllib_ms'] < r['urlp_ms'] else "urlp"

        html += f"""                    <tr>
                        <td>{r['name']}</td>
                        <td>{r['urllib_ms']:.4f}</td>
                        <td>{r['urlp_ms']:.4f}</td>
                        <td class="ratio-cell">{r['ratio']:.2f}x</td>
                        <td>{faster_lib} +{faster_pct:.1f}%</td>
                    </tr>
"""

    html += """                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated at """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
            <p>This benchmark uses pytest-benchmark under the hood for accurate measurements.</p>
        </div>
    </div>
    
    <script>
        // Time comparison chart
        const timeCtx = document.getElementById('timeChart').getContext('2d');
        new Chart(timeCtx, {
            type: 'bar',
            data: {
                labels: """ + chart_labels + """,
                datasets: [
                    {
                        label: 'urllib.parse',
                        data: """ + chart_urllib + """,
                        backgroundColor: '#667eea',
                        borderColor: '#667eea',
                        borderWidth: 1,
                    },
                    {
                        label: 'urlp',
                        data: """ + chart_urlp + """,
                        backgroundColor: '#764ba2',
                        borderColor: '#764ba2',
                        borderWidth: 1,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Time (milliseconds)'
                        }
                    }
                }
            }
        });
        
        // Ratio chart
        const ratioCtx = document.getElementById('ratioChart').getContext('2d');
        new Chart(ratioCtx, {
            type: 'line',
            data: {
                labels: """ + chart_labels + """,
                datasets: [{
                    label: 'Performance Ratio',
                    data: """ + chart_ratios + """,
                    borderColor: '#764ba2',
                    backgroundColor: 'rgba(118, 75, 162, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 6,
                    pointBackgroundColor: '#764ba2',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom',
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {{
                                return value + 'x';
                            }}
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"""

    return html


def main():
    """Main entry point."""
    results = run_all_benchmarks()

    html_report = generate_html_report(results)

    output_file = "performance_report.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_report)

    print(f"\n[OK] Report generated: {output_file}")
    print("\nYou can now open the HTML file in your browser to view the interactive charts.")


if __name__ == "__main__":
    main()

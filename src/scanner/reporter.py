"""
BAYREUTHWING — Report Generator

Generates scan reports in multiple formats:
- Console (Rich terminal output)
- JSON (machine-readable)
- HTML (styled, interactive)
"""

import json
import os
from datetime import datetime
from typing import Optional


class ReportGenerator:
    """
    Multi-format security report generator.
    
    Produces professional security audit reports from scan results.
    """

    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
    }

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
    }

    def generate(
        self,
        results: dict,
        output_path: Optional[str] = None,
        format: str = "console",
    ) -> str:
        """
        Generate a report from scan results.
        
        Args:
            results: Scan results dictionary from ScanEngine.
            output_path: File path to save report (for json/html).
            format: Report format ('console', 'json', 'html').
            
        Returns:
            Report string.
        """
        if format == "json":
            return self._generate_json(results, output_path)
        elif format == "html":
            return self._generate_html(results, output_path)
        else:
            return self._generate_console(results)

    def _generate_console(self, results: dict) -> str:
        """Generate rich console report."""
        lines = []
        lines.append("")
        lines.append("╔" + "═" * 68 + "╗")
        lines.append("║" + "  🦅 BAYREUTHWING — SECURITY SCAN REPORT".ljust(68) + "║")
        lines.append("╚" + "═" * 68 + "╝")
        lines.append("")

        # Target info
        lines.append(f"  Target:      {results.get('target', 'Unknown')}")
        lines.append(f"  Scan Time:   {results.get('scan_time', 0):.2f}s")
        lines.append(f"  Files:       {results.get('files_scanned', 0)} scanned")
        lines.append(f"  Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Engine info
        engine = results.get("engine_info", {})
        modes = []
        if engine.get("ml_enabled"):
            modes.append("ML")
        if engine.get("rules_enabled"):
            modes.append("Rules")
        if engine.get("flow_enabled"):
            modes.append("Flow")
        lines.append(f"  Modules:     {' + '.join(modes)}")
        lines.append(f"  Rules:       {engine.get('total_rules', 0)} patterns")
        lines.append("")

        # Severity summary
        severity = results.get("severity_counts", {})
        lines.append("  ┌─────────────────────────────────────────┐")
        lines.append("  │          SEVERITY SUMMARY                │")
        lines.append("  ├─────────────────────────────────────────┤")
        lines.append(f"  │  🔴 Critical:  {severity.get('critical', 0):>5}                     │")
        lines.append(f"  │  🟠 High:      {severity.get('high', 0):>5}                     │")
        lines.append(f"  │  🟡 Medium:    {severity.get('medium', 0):>5}                     │")
        lines.append(f"  │  🔵 Low:       {severity.get('low', 0):>5}                     │")
        lines.append(f"  │                                         │")
        lines.append(f"  │  Total:       {results.get('total_findings', 0):>5}                     │")
        lines.append("  └─────────────────────────────────────────┘")
        lines.append("")

        # Vulnerability breakdown
        vuln_counts = results.get("vulnerability_counts", {})
        if vuln_counts:
            lines.append("  VULNERABILITY BREAKDOWN:")
            lines.append("  " + "─" * 50)
            for vuln_name, count in sorted(vuln_counts.items(), key=lambda x: -x[1]):
                bar = "█" * min(count, 20)
                lines.append(f"  {vuln_name:<35} {count:>3} {bar}")
            lines.append("")

        # Detailed findings (grouped by file)
        findings = results.get("findings", [])
        if findings:
            lines.append("  DETAILED FINDINGS:")
            lines.append("  " + "═" * 60)

            # Group by file
            by_file = {}
            for f in findings:
                fp = f["filepath"]
                if fp not in by_file:
                    by_file[fp] = []
                by_file[fp].append(f)

            for filepath, file_findings in by_file.items():
                lines.append(f"\n  📄 {filepath}")
                lines.append("  " + "─" * 60)

                for f in file_findings:
                    icon = self.SEVERITY_ICONS.get(f["severity"], "⚪")
                    lines.append(
                        f"    {icon} [{f['severity'].upper():>8}] "
                        f"Line {f.get('line', '?'):>4} | {f['vulnerability_name']}"
                    )
                    lines.append(f"      {f['message']}")
                    lines.append(f"      CWE: {f['cwe_id']} | OWASP: {f['owasp']}")
                    lines.append(f"      Confidence: {f['confidence']:.1%} | Source: {f['source']}")

                    if f.get("rule_id"):
                        lines.append(f"      Rule: {f['rule_id']}")

                    if f.get("remediation"):
                        lines.append(f"      Fix: {f['remediation'][0]}")

                    lines.append("")

        else:
            lines.append("  ✅ No vulnerabilities detected!")
            lines.append("")

        lines.append("╔" + "═" * 68 + "╗")
        lines.append("║" + "  Scan complete. Stay secure. 🛡️".ljust(68) + "║")
        lines.append("╚" + "═" * 68 + "╝")
        lines.append("")

        report = "\n".join(lines)
        return report

    def _generate_json(self, results: dict, output_path: Optional[str] = None) -> str:
        """Generate JSON report."""
        report = {
            "report_metadata": {
                "tool": "BAYREUTHWING",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat(),
                "format": "json",
            },
            "scan_summary": {
                "target": results.get("target", ""),
                "scan_time_seconds": results.get("scan_time", 0),
                "files_scanned": results.get("files_scanned", 0),
                "total_findings": results.get("total_findings", 0),
                "severity_counts": results.get("severity_counts", {}),
                "vulnerability_counts": results.get("vulnerability_counts", {}),
            },
            "engine_info": results.get("engine_info", {}),
            "findings": results.get("findings", []),
        }

        json_str = json.dumps(report, indent=2, ensure_ascii=False)

        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str

    def _generate_html(self, results: dict, output_path: Optional[str] = None) -> str:
        """Generate styled HTML report."""
        severity_counts = results.get("severity_counts", {})
        findings = results.get("findings", [])
        vuln_counts = results.get("vulnerability_counts", {})

        # Build findings HTML
        findings_html = ""
        for i, f in enumerate(findings):
            color = self.SEVERITY_COLORS.get(f["severity"], "#666")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {color};">
                        {f['severity'].upper()}
                    </span>
                    <span class="vuln-name">{f['vulnerability_name']}</span>
                    <span class="confidence">{f['confidence']:.0%} confidence</span>
                </div>
                <div class="finding-body">
                    <p class="message">{f['message']}</p>
                    <div class="details">
                        <span>📄 {f['filepath']}</span>
                        <span>📍 Line {f.get('line', '?')}</span>
                        <span>🏷️ {f['cwe_id']}</span>
                        <span>📋 {f['owasp']}</span>
                        <span>🔍 {f['source']}</span>
                    </div>
                    {"<div class='matched-code'><code>" + f['matched_text'][:200] + "</code></div>" if f.get('matched_text') else ""}
                    {"<div class='remediation'><strong>Remediation:</strong><ul>" + "".join(f"<li>{r}</li>" for r in f.get('remediation', [])[:3]) + "</ul></div>" if f.get('remediation') else ""}
                </div>
            </div>
            """

        # Build vuln chart data
        chart_items = ""
        for name, count in sorted(vuln_counts.items(), key=lambda x: -x[1]):
            max_count = max(vuln_counts.values()) if vuln_counts else 1
            width = (count / max_count) * 100
            chart_items += f"""
            <div class="chart-row">
                <span class="chart-label">{name}</span>
                <div class="chart-bar-container" role="progressbar" aria-valuenow="{count}" aria-valuemin="0" aria-valuemax="{max_count}" aria-label="{name} vulnerability count">
                    <div class="chart-bar" style="width: {width}%;"></div>
                </div>
                <span class="chart-value" aria-hidden="true">{count}</span>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BAYREUTHWING — Security Scan Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #6366f1;
            --accent-glow: rgba(99, 102, 241, 0.3);
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --safe: #16a34a;
            --border: #334155;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            text-align: center;
            padding: 3rem 0 2rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}

        header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #6366f1, #8b5cf6, #a855f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        header p {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}

        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .info-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border);
        }}

        .info-card .label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .info-card .value {{
            font-size: 1.8rem;
            font-weight: 700;
            margin-top: 0.25rem;
        }}

        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .severity-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .severity-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}

        .severity-card .count {{
            font-size: 2.5rem;
            font-weight: 800;
        }}

        .severity-card .label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }}

        .section-title {{
            font-size: 1.5rem;
            margin: 2rem 0 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent);
            display: inline-block;
        }}

        .chart-row {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin: 0.5rem 0;
        }}

        .chart-label {{
            width: 250px;
            font-size: 0.9rem;
            text-align: right;
            color: var(--text-secondary);
        }}

        .chart-bar-container {{
            flex: 1;
            height: 24px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
        }}

        .chart-bar {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent), #8b5cf6);
            border-radius: 4px;
            transition: width 0.5s ease;
        }}

        .chart-value {{
            width: 40px;
            text-align: right;
            font-weight: 600;
        }}

        .finding {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            border: 1px solid var(--border);
            transition: box-shadow 0.2s;
        }}

        .finding:hover {{
            box-shadow: 0 2px 15px rgba(0,0,0,0.2);
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
        }}

        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            color: white;
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 0.05em;
        }}

        .vuln-name {{
            font-weight: 600;
            font-size: 1.1rem;
        }}

        .confidence {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-left: auto;
        }}

        .finding-body .message {{
            margin-bottom: 0.75rem;
            color: var(--text-secondary);
        }}

        .details {{
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
        }}

        .matched-code {{
            background: #0d1117;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.75rem 0;
            overflow-x: auto;
        }}

        .matched-code code {{
            font-family: 'Cascadia Code', 'Fira Code', monospace;
            font-size: 0.85rem;
            color: #e2e8f0;
        }}

        .remediation {{
            background: rgba(22, 163, 98, 0.1);
            border: 1px solid rgba(22, 163, 98, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 0.75rem;
        }}

        .remediation strong {{
            color: var(--safe);
        }}

        .remediation ul {{
            margin-top: 0.5rem;
            padding-left: 1.25rem;
        }}

        .remediation li {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin: 0.25rem 0;
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border);
            margin-top: 3rem;
        }}

        @media (max-width: 768px) {{
            .severity-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .chart-label {{
                width: 150px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span aria-hidden="true">🦅</span> BAYREUTHWING</h1>
            <p>AI-Powered Security Scan Report</p>
        </header>

        <main>
        <div class="scan-info">
            <div class="info-card">
                <div class="label">Target</div>
                <div class="value" style="font-size: 1rem; word-break: break-all;">
                    {results.get('target', 'Unknown')}
                </div>
            </div>
            <div class="info-card">
                <div class="label">Files Scanned</div>
                <div class="value">{results.get('files_scanned', 0)}</div>
            </div>
            <div class="info-card">
                <div class="label">Scan Time</div>
                <div class="value">{results.get('scan_time', 0):.1f}s</div>
            </div>
            <div class="info-card">
                <div class="label">Total Findings</div>
                <div class="value">{results.get('total_findings', 0)}</div>
            </div>
        </div>

        <div class="severity-grid">
            <div class="severity-card">
                <div class="count" style="color: var(--critical);">{severity_counts.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="severity-card">
                <div class="count" style="color: var(--high);">{severity_counts.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="severity-card">
                <div class="count" style="color: var(--medium);">{severity_counts.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="severity-card">
                <div class="count" style="color: var(--low);">{severity_counts.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <h2 class="section-title">Vulnerability Breakdown</h2>
        <div style="background: var(--bg-card); border-radius: 12px; padding: 1.5rem; border: 1px solid var(--border);">
            {chart_items}
        </div>

        <h2 class="section-title">Detailed Findings ({len(findings)})</h2>
        {findings_html if findings_html else '<p style="color: var(--safe); font-size: 1.2rem; padding: 2rem;"><span aria-hidden="true">✅</span> No vulnerabilities detected!</p>'}
        </main>

        <footer>
            <p>Generated by BAYREUTHWING v1.0.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Defensive Security Analysis Tool</p>
        </footer>
    </div>
</body>
</html>"""

        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

        return html

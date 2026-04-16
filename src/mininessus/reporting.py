from __future__ import annotations

import json
from csv import DictWriter
from pathlib import Path

from jinja2 import Template

from .models import Finding, ReportDiff, SEVERITY_ORDER, ScanMetadata, ScanResult


def severity_sort_key(severity: str, finding_id: str) -> tuple[int, str]:
    return (SEVERITY_ORDER.index(severity), finding_id) if severity in SEVERITY_ORDER else (99, finding_id)


def _finding_map(report: dict) -> dict[tuple[str, str, str], dict]:
    return {(finding["id"], finding["target"], finding["evidence"]): finding for finding in report.get("findings", [])}


HTML_TEMPLATE = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AccuScanner Report</title>
  <style>
    :root {
      --bg: #f3f6fb;
      --panel: rgba(255, 255, 255, 0.92);
      --panel-strong: #ffffff;
      --text: #142033;
      --muted: #52627a;
      --line: #d7e1ee;
      --critical: #8b1e5d;
      --high: #d14343;
      --medium: #c77d19;
      --low: #1e88a8;
      --info: #2d8f60;
      --shadow: 0 20px 45px rgba(20, 32, 51, 0.08);
      --radius: 18px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(30,136,168,0.10), transparent 28%),
        radial-gradient(circle at top right, rgba(139,30,93,0.08), transparent 25%),
        linear-gradient(180deg, #f8fbff 0%, var(--bg) 100%);
    }
    .wrap { max-width: 1320px; margin: 0 auto; padding: 32px 20px 48px; }
    .hero, .panel {
      background: var(--panel);
      border: 1px solid rgba(255,255,255,0.7);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }
    .hero {
      padding: 28px;
      margin-bottom: 24px;
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
    }
    .eyebrow {
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: #e7eef7;
      color: #39516f;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    h1 { margin: 14px 0 10px; font-size: 34px; line-height: 1.1; }
    .lead { margin: 0; color: var(--muted); max-width: 72ch; }
    .meta-grid, .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 14px;
    }
    .priority-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }
    .metric, .summary-card {
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px 16px;
    }
    .metric .label, .summary-card .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 6px;
    }
    .metric .value, .summary-card .value {
      font-size: 22px;
      font-weight: 700;
      word-break: break-word;
    }
    .summary-card { position: relative; overflow: hidden; }
    .summary-card::before {
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 5px;
      background: var(--line);
    }
    .summary-card.critical::before { background: var(--critical); }
    .summary-card.high::before { background: var(--high); }
    .summary-card.medium::before { background: var(--medium); }
    .summary-card.low::before { background: var(--low); }
    .summary-card.info::before { background: var(--info); }
    .summary-card.total::before { background: #3f5d7d; }
    .stack { display: grid; gap: 24px; }
    .panel { padding: 22px; }
    h2 { margin: 0 0 18px; font-size: 22px; }
    .table-wrap { overflow-x: auto; border-radius: 16px; border: 1px solid var(--line); }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--panel-strong);
      min-width: 880px;
    }
    th, td {
      text-align: left;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    th {
      background: #eef4fb;
      color: #30445f;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    tr:last-child td { border-bottom: none; }
    .severity-pill {
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: #fff;
    }
    .severity-pill.critical { background: var(--critical); }
    .severity-pill.high { background: var(--high); }
    .severity-pill.medium { background: var(--medium); }
    .severity-pill.low { background: var(--low); }
    .severity-pill.info { background: var(--info); }
    .mono {
      font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
      font-size: 13px;
      background: #eef4fb;
      border: 1px solid #d9e4f2;
      border-radius: 10px;
      padding: 3px 8px;
      display: inline-block;
    }
    .muted { color: var(--muted); }
    .findings-list {
      display: grid;
      gap: 16px;
    }
    .finding-card {
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-left: 6px solid #93a5be;
      border-radius: 16px;
      padding: 18px;
    }
    .finding-card.critical { border-left-color: var(--critical); }
    .finding-card.high { border-left-color: var(--high); }
    .finding-card.medium { border-left-color: var(--medium); }
    .finding-card.low { border-left-color: var(--low); }
    .finding-card.info { border-left-color: var(--info); }
    .finding-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 10px;
      flex-wrap: wrap;
    }
    .finding-title {
      font-size: 18px;
      font-weight: 700;
      margin: 0;
    }
    .finding-meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 12px;
      color: var(--muted);
      font-size: 14px;
    }
    .tag {
      display: inline-block;
      margin-right: 6px;
      margin-top: 6px;
      padding: 4px 8px;
      border-radius: 999px;
      background: #eef4fb;
      color: #35506d;
      font-size: 12px;
    }
    .finding-section-title {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #51647e;
      margin: 14px 0 6px;
      font-weight: 700;
    }
    .empty {
      padding: 22px;
      border: 1px dashed var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.75);
      color: var(--muted);
    }
    .priority-card {
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 18px;
    }
    .priority-card h3 {
      margin: 0 0 8px;
      font-size: 16px;
    }
    .asset-group {
      display: grid;
      gap: 12px;
      margin-bottom: 18px;
    }
    .asset-title {
      margin: 0;
      font-size: 18px;
    }
    @media (max-width: 900px) {
      .hero { grid-template-columns: 1fr; }
      h1 { font-size: 28px; }
      .wrap { padding: 20px 14px 36px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <span class="eyebrow">AccuScanner Report</span>
        <h1>Defensive Vulnerability Assessment Summary</h1>
        <p class="lead">Structured export generated from nmap-based discovery, targeted validation checks, and severity-based finding analysis.</p>
      </div>
      <div class="meta-grid">
        <div class="metric"><div class="label">Target</div><div class="value">{{ report.metadata.target }}</div></div>
        <div class="metric"><div class="label">Mode</div><div class="value">{{ report.metadata.scan_mode|upper }}</div></div>
        <div class="metric"><div class="label">Started</div><div class="value">{{ report.metadata.started_at }}</div></div>
        <div class="metric"><div class="label">Ended</div><div class="value">{{ report.metadata.ended_at }}</div></div>
        <div class="metric"><div class="label">Duration</div><div class="value">{{ report.metadata.duration_seconds }}s</div></div>
        <div class="metric"><div class="label">Hosts</div><div class="value">{{ report.hosts|length }}</div></div>
      </div>
    </section>

    <div class="stack">
      <section class="panel">
        <h2>Severity Overview</h2>
        <div class="summary-grid">
          {% for severity, count in report.summary.severity_totals.items() %}
          <div class="summary-card {{ severity }}">
            <div class="label">{{ severity }}</div>
            <div class="value">{{ count }}</div>
          </div>
          {% endfor %}
          <div class="summary-card total">
            <div class="label">total findings</div>
            <div class="value">{{ report.summary.total_findings }}</div>
          </div>
          <div class="summary-card total">
            <div class="label">severity score</div>
            <div class="value">{{ report.summary.severity_score }}</div>
          </div>
        </div>
      </section>

      <section class="panel">
        <h2>Top Risks</h2>
        {% if report.summary.top_risks %}
        <div class="priority-grid">
          {% for finding in report.summary.top_risks %}
          <article class="priority-card">
            <span class="severity-pill {{ finding.severity }}">{{ finding.severity }}</span>
            <h3>{{ finding.title }}</h3>
            <div class="muted">{{ finding.target }}</div>
            <div class="finding-section-title">Recommendation</div>
            <div>{{ finding.recommendation }}</div>
          </article>
          {% endfor %}
        </div>
        {% else %}
        <div class="empty">No prioritized risks were generated for this scan.</div>
        {% endif %}
      </section>

      <section class="panel">
        <h2>Scan Metadata</h2>
        <p class="muted">Reproducibility details captured at export time.</p>
        <p><span class="mono">{{ report.metadata.nmap_command | join(" ") }}</span></p>
      </section>

      <section class="panel">
        <h2>Discovered Hosts</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Address</th><th>Hostname</th><th>Status</th><th>Open Ports</th><th>OS Matches</th></tr>
            </thead>
            <tbody>
              {% for host in report.hosts %}
              <tr>
                <td>{{ host.address }}</td>
                <td>{{ host.hostname or "-" }}</td>
                <td>{{ host.status }}</td>
                <td>{{ host.ports | selectattr("state", "equalto", "open") | map(attribute="port") | join(", ") or "-" }}</td>
                <td>{{ host.os_matches | join(", ") or "-" }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <h2>Remediation By Asset</h2>
        {% if report.findings_by_target %}
          {% for target, findings in report.findings_by_target.items() %}
          <section class="asset-group">
            <h3 class="asset-title">{{ target }}</h3>
            {% for finding in findings %}
            <article class="priority-card">
              <div class="finding-top">
                <strong>{{ finding.title }}</strong>
                <span class="severity-pill {{ finding.severity }}">{{ finding.severity }}</span>
              </div>
              <div class="muted">{{ finding.category }} | {{ finding.id }}</div>
              <div class="finding-section-title">Recommendation</div>
              <div>{{ finding.recommendation }}</div>
            </article>
            {% endfor %}
          </section>
          {% endfor %}
        {% else %}
        <div class="empty">No asset-grouped remediation items were generated.</div>
        {% endif %}
      </section>

      <section class="panel">
        <h2>Discovered Attack Surface</h2>
        {% set surface_findings = report.findings | selectattr("category", "equalto", "attack_surface") | list %}
        {% if surface_findings %}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>ID</th><th>Target</th><th>Evidence</th><th>Confidence</th></tr>
            </thead>
            <tbody>
              {% for finding in surface_findings %}
              <tr>
                <td>{{ finding.id }}</td>
                <td>{{ finding.target }}</td>
                <td>{{ finding.evidence }}</td>
                <td>{{ finding.confidence }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% else %}
        <div class="empty">No additional same-host routes, forms, or script assets were cataloged during this scan.</div>
        {% endif %}
      </section>

      <section class="panel">
        <h2>Findings</h2>
        {% if report.findings %}
        <div class="findings-list">
          {% for finding in report.findings %}
          <article class="finding-card {{ finding.severity }}">
            <div class="finding-top">
              <h3 class="finding-title">{{ finding.title }}</h3>
              <span class="severity-pill {{ finding.severity }}">{{ finding.severity }}</span>
            </div>
            <div class="finding-meta">
              <span><strong>ID:</strong> <span class="mono">{{ finding.id }}</span></span>
              <span><strong>Category:</strong> {{ finding.category }}</span>
              <span><strong>Target:</strong> {{ finding.target }}</span>
              <span><strong>Confidence:</strong> {{ finding.confidence }}</span>
            </div>
            {% if finding.tags %}
            <div>
              {% for tag in finding.tags %}
              <span class="tag">{{ tag }}</span>
              {% endfor %}
            </div>
            {% endif %}
            <div class="finding-section-title">Description</div>
            <div>{{ finding.description }}</div>
            <div class="finding-section-title">Evidence</div>
            <div>{{ finding.evidence }}</div>
            <div class="finding-section-title">Recommendation</div>
            <div>{{ finding.recommendation }}</div>
          </article>
          {% endfor %}
        </div>
        {% else %}
        <div class="empty">No findings were generated for this scan.</div>
        {% endif %}
      </section>
    </div>
  </div>
</body>
</html>"""
)


def write_json_report(result: ScanResult, path: Path) -> Path:
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path


def write_html_report(result: ScanResult, path: Path) -> Path:
    path.write_text(HTML_TEMPLATE.render(report=result.to_dict()), encoding="utf-8")
    return path


def write_markdown_report(result: ScanResult, path: Path) -> Path:
    report = result.to_dict()
    lines = [
        "# AccuScanner Report",
        "",
        f"- Target: `{report['metadata']['target']}`",
        f"- Mode: `{report['metadata']['scan_mode']}`",
        f"- Started: `{report['metadata']['started_at']}`",
        f"- Ended: `{report['metadata']['ended_at']}`",
        f"- Duration: `{report['metadata']['duration_seconds']}s`",
        f"- Severity score: `{report['summary']['severity_score']}`",
        "",
        "## Severity Summary",
        "",
    ]
    for severity, count in report["summary"]["severity_totals"].items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings were generated for this scan.")
    for finding in report["findings"]:
        lines.extend(
            [
                f"### {finding['title']} ({finding['severity']})",
                "",
                f"- ID: `{finding['id']}`",
                f"- Category: `{finding['category']}`",
                f"- Target: `{finding['target']}`",
                f"- Confidence: `{finding.get('confidence', 'medium')}`",
                f"- Description: {finding['description']}",
                f"- Evidence: {finding['evidence']}",
                f"- Recommendation: {finding['recommendation']}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_csv_report(result: ScanResult, path: Path) -> Path:
    rows = result.to_dict()["findings"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = DictWriter(
            handle,
            fieldnames=[
                "id",
                "title",
                "severity",
                "category",
                "target",
                "confidence",
                "description",
                "evidence",
                "recommendation",
                "tags",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "tags": ",".join(row.get("tags", []))})
    return path


def write_sarif_report(result: ScanResult, path: Path) -> Path:
    report = result.to_dict()
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AccuScanner",
                        "informationUri": "https://github.com/",
                        "rules": [
                            {
                                "id": finding["id"],
                                "name": finding["title"],
                                "shortDescription": {"text": finding["title"]},
                                "fullDescription": {"text": finding["description"]},
                                "help": {"text": finding["recommendation"]},
                            }
                            for finding in report["findings"]
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": finding["id"],
                        "level": _sarif_level(finding["severity"]),
                        "message": {"text": finding["description"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding["target"]},
                                }
                            }
                        ],
                        "properties": {
                            "category": finding["category"],
                            "confidence": finding.get("confidence", "medium"),
                            "evidence": finding["evidence"],
                            "recommendation": finding["recommendation"],
                            "tags": finding.get("tags", []),
                        },
                    }
                    for finding in report["findings"]
                ],
            }
        ],
    }
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path


def load_report(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def compare_reports(old_report: dict, new_report: dict) -> ReportDiff:
    old_map = _finding_map(old_report)
    new_map = _finding_map(new_report)
    new_findings = [Finding(**new_map[key]) for key in new_map.keys() - old_map.keys()]
    resolved_findings = [Finding(**old_map[key]) for key in old_map.keys() - new_map.keys()]
    new_findings.sort(key=lambda f: severity_sort_key(f.severity, f.id))
    resolved_findings.sort(key=lambda f: severity_sort_key(f.severity, f.id))
    return ReportDiff(new_findings=new_findings, resolved_findings=resolved_findings)


def write_diff_json(diff: ReportDiff, path: Path) -> Path:
    path.write_text(json.dumps(diff.to_dict(), indent=2), encoding="utf-8")
    return path


DASHBOARD_TEMPLATE = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AccuScanner Dashboard</title>
  <style>
    body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; background: #f4f7fb; color: #162233; }
    .wrap { max-width: 1280px; margin: 0 auto; padding: 28px 20px 40px; }
    .hero, .panel { background: #fff; border: 1px solid #dbe5f0; border-radius: 18px; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.06); }
    .hero { padding: 24px; margin-bottom: 20px; }
    .grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }
    .metric { padding: 16px; border: 1px solid #dbe5f0; border-radius: 14px; background: #f8fbff; }
    .label { font-size: 12px; text-transform: uppercase; color: #5a6c84; letter-spacing: .06em; }
    .value { font-size: 24px; font-weight: 700; margin-top: 6px; }
    .panel { padding: 20px; margin-top: 20px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 10px; border-bottom: 1px solid #e6edf5; text-align: left; vertical-align: top; }
    th { font-size: 12px; text-transform: uppercase; color: #5a6c84; }
    .pill { display: inline-block; padding: 4px 8px; border-radius: 999px; color: #fff; font-size: 12px; text-transform: uppercase; }
    .critical { background: #8b1e5d; } .high { background: #d14343; } .medium { background: #c77d19; } .low { background: #1e88a8; } .info { background: #2d8f60; }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>AccuScanner Dashboard</h1>
      <p>Aggregated view across {{ dashboard.scan_count }} reports.</p>
      <div class="grid">
        <div class="metric"><div class="label">Reports</div><div class="value">{{ dashboard.scan_count }}</div></div>
        <div class="metric"><div class="label">Targets</div><div class="value">{{ dashboard.target_count }}</div></div>
        <div class="metric"><div class="label">Findings</div><div class="value">{{ dashboard.total_findings }}</div></div>
        <div class="metric"><div class="label">Severity Score</div><div class="value">{{ dashboard.severity_score }}</div></div>
      </div>
    </section>
    <section class="panel">
      <h2>Severity Totals</h2>
      <div class="grid">
        {% for severity, count in dashboard.severity_totals.items() %}
        <div class="metric"><div class="label">{{ severity }}</div><div class="value">{{ count }}</div></div>
        {% endfor %}
      </div>
    </section>
    <section class="panel">
      <h2>Executive Summary</h2>
      <p><strong>Priority focus:</strong> {{ dashboard.executive_summary.priority_focus }}</p>
      <p><strong>Quick wins:</strong> {{ dashboard.executive_summary.quick_wins | join(", ") if dashboard.executive_summary.quick_wins else "None identified" }}</p>
      <p><strong>Cloud issues:</strong> {{ dashboard.executive_summary.cloud_issues }}</p>
      <p><strong>Authentication issues:</strong> {{ dashboard.executive_summary.auth_issues }}</p>
    </section>
    <section class="panel">
      <h2>Top Findings</h2>
      <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>ID</th></tr></thead>
        <tbody>
          {% for finding in dashboard.top_findings %}
          <tr>
            <td><span class="pill {{ finding.severity }}">{{ finding.severity }}</span></td>
            <td>{{ finding.title }}</td>
            <td>{{ finding.target }}</td>
            <td>{{ finding.id }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Per-Report Summary</h2>
      <table>
        <thead><tr><th>Target</th><th>Mode</th><th>Duration</th><th>Findings</th><th>Score</th></tr></thead>
        <tbody>
          {% for report in dashboard.reports %}
          <tr>
            <td>{{ report.metadata.target }}</td>
            <td>{{ report.metadata.scan_mode }}</td>
            <td>{{ report.metadata.duration_seconds }}s</td>
            <td>{{ report.summary.total_findings }}</td>
            <td>{{ report.summary.severity_score }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Trend Timeline</h2>
      <table>
        <thead><tr><th>Started</th><th>Target</th><th>Findings</th><th>Score</th></tr></thead>
        <tbody>
          {% for point in dashboard.timeline %}
          <tr>
            <td>{{ point.started_at or "-" }}</td>
            <td>{{ point.target or "-" }}</td>
            <td>{{ point.total_findings }}</td>
            <td>{{ point.severity_score }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Most Common Findings</h2>
      <table>
        <thead><tr><th>Finding ID</th><th>Occurrences</th></tr></thead>
        <tbody>
          {% for finding in dashboard.most_common_findings %}
          <tr>
            <td>{{ finding.id }}</td>
            <td>{{ finding.count }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Recurring Findings</h2>
      <table>
        <thead><tr><th>ID</th><th>Target</th><th>First Seen</th><th>Last Seen</th><th>Occurrences</th><th>Status</th></tr></thead>
        <tbody>
          {% for finding in dashboard.recurring_findings %}
          <tr>
            <td>{{ finding.id }}</td>
            <td>{{ finding.target }}</td>
            <td>{{ finding.first_seen or "-" }}</td>
            <td>{{ finding.last_seen or "-" }}</td>
            <td>{{ finding.occurrences }}</td>
            <td>{{ finding.status }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Riskiest Targets</h2>
      <table>
        <thead><tr><th>Target</th><th>Aggregate Score</th></tr></thead>
        <tbody>
          {% for target in dashboard.riskiest_targets %}
          <tr>
            <td>{{ target.target }}</td>
            <td>{{ target.score }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </section>
  </div>
</body>
</html>"""
)


def build_dashboard(report_payloads: list[dict]) -> dict:
    severity_totals = {severity: 0 for severity in SEVERITY_ORDER}
    all_findings: list[dict] = []
    targets: set[str] = set()
    severity_score = 0
    timeline: list[dict] = []
    findings_by_id: dict[str, int] = {}
    target_history: dict[str, list[dict]] = {}
    finding_lifecycle: dict[tuple[str, str], dict[str, object]] = {}
    target_scores: dict[str, int] = {}
    sorted_reports = sorted(report_payloads, key=lambda report: report.get("metadata", {}).get("started_at", ""))
    latest_started_at = sorted_reports[-1].get("metadata", {}).get("started_at") if sorted_reports else None
    for report in sorted_reports:
        summary = report.get("summary", {})
        for severity, count in summary.get("severity_totals", {}).items():
            severity_totals[severity] = severity_totals.get(severity, 0) + count
        severity_score += summary.get("severity_score", 0)
        report_findings = report.get("findings", [])
        all_findings.extend(report_findings)
        metadata = report.get("metadata", {})
        if metadata.get("target"):
            targets.add(metadata["target"])
            target_history.setdefault(metadata["target"], []).append(
                {
                    "started_at": metadata.get("started_at"),
                    "severity_score": summary.get("severity_score", 0),
                    "total_findings": summary.get("total_findings", 0),
                }
            )
        timeline.append(
            {
                "target": metadata.get("target"),
                "started_at": metadata.get("started_at"),
                "severity_score": summary.get("severity_score", 0),
                "total_findings": summary.get("total_findings", 0),
            }
        )
        for finding in report_findings:
            findings_by_id[finding["id"]] = findings_by_id.get(finding["id"], 0) + 1
            lifecycle_key = (finding["id"], finding["target"])
            started_at = metadata.get("started_at")
            entry = finding_lifecycle.setdefault(
                lifecycle_key,
                {
                    "id": finding["id"],
                    "title": finding.get("title"),
                    "target": finding["target"],
                    "severity": finding.get("severity", "info"),
                    "first_seen": started_at,
                    "last_seen": started_at,
                    "occurrences": 0,
                },
            )
            entry["occurrences"] += 1
            if started_at and (entry["first_seen"] is None or started_at < entry["first_seen"]):
                entry["first_seen"] = started_at
            if started_at and (entry["last_seen"] is None or started_at > entry["last_seen"]):
                entry["last_seen"] = started_at
            target_scores[finding["target"]] = target_scores.get(finding["target"], 0) + summary.get("severity_score", 0)
    all_findings.sort(key=lambda finding: severity_sort_key(finding.get("severity", "info"), finding.get("id", "")))
    timeline.sort(key=lambda entry: (entry.get("started_at") or "", entry.get("target") or ""))
    most_common_findings = sorted(findings_by_id.items(), key=lambda item: (-item[1], item[0]))[:10]
    recurring_findings = sorted(
        [
            {
                **entry,
                "still_present": entry["last_seen"] == latest_started_at,
                "status": "recurring" if entry["last_seen"] == latest_started_at else "resolved",
            }
            for entry in finding_lifecycle.values()
            if entry["occurrences"] > 1
        ],
        key=lambda entry: (-entry["occurrences"], severity_sort_key(str(entry["severity"]), str(entry["id"]))),
    )[:10]
    riskiest_targets = sorted(target_scores.items(), key=lambda item: (-item[1], item[0]))[:10]
    executive_summary = _build_executive_summary(all_findings, riskiest_targets)
    return {
        "scan_count": len(sorted_reports),
        "target_count": len(targets),
        "total_findings": len(all_findings),
        "severity_score": severity_score,
        "severity_totals": severity_totals,
        "top_findings": all_findings[:10],
        "timeline": timeline,
        "most_common_findings": [{"id": finding_id, "count": count} for finding_id, count in most_common_findings],
        "recurring_findings": recurring_findings,
        "riskiest_targets": [{"target": target, "score": score} for target, score in riskiest_targets],
        "executive_summary": executive_summary,
        "target_history": dict(sorted(target_history.items(), key=lambda item: item[0])),
        "reports": sorted_reports,
    }


def write_dashboard_html(dashboard: dict, path: Path) -> Path:
    path.write_text(DASHBOARD_TEMPLATE.render(dashboard=dashboard), encoding="utf-8")
    return path


def _build_executive_summary(all_findings: list[dict], riskiest_targets: list[tuple[str, int]]) -> dict[str, object]:
    cloud_issues = sum(1 for finding in all_findings if "cloud" in [tag.lower() for tag in finding.get("tags", [])])
    auth_issues = sum(1 for finding in all_findings if "auth" in [tag.lower() for tag in finding.get("tags", [])])
    quick_wins = sorted(
        {
            finding["title"]
            for finding in all_findings
            if finding.get("severity") in {"high", "medium"}
            and finding.get("category") in {"web_headers", "web_security", "aws_iam", "azure_iam", "gcp_iam", "host_auth"}
        }
    )[:5]
    priority_focus = f"Focus first on {riskiest_targets[0][0]}" if riskiest_targets else "No high-risk targets identified yet."
    return {
        "priority_focus": priority_focus,
        "quick_wins": quick_wins,
        "cloud_issues": cloud_issues,
        "auth_issues": auth_issues,
    }


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity.lower(), "warning")

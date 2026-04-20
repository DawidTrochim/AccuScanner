from pathlib import Path

from mininessus.models import Finding, ScanMetadata, ScanResult
from mininessus.reporting import write_csv_report, write_html_report, write_markdown_report, write_sarif_report


def _sample_result() -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(
            target="host-a",
            scan_mode="full",
            started_at="2026-04-15T12:00:00Z",
            ended_at="2026-04-15T12:00:10Z",
            duration_seconds=10.0,
            nmap_command=["nmap", "-oX", "-", "host-a"],
        ),
        findings=[
            Finding(
                id="HTTP-005",
                title="HTTP service does not enforce HTTPS",
                severity="high",
                category="web_security",
                target="host-a",
                description="HTTP stayed in plaintext.",
                evidence="Observed status 200 over HTTP.",
                recommendation="Redirect to HTTPS.",
                confidence="high",
                tags=["web", "transport"],
            ),
            Finding(
                id="HTTP-001",
                title="Missing HSTS header",
                severity="medium",
                category="web_headers",
                target="host-a",
                description="The security header `strict-transport-security` was not observed on the HTTP response.",
                evidence="Headers observed: ['server'].",
                recommendation="Set the recommended HTTP response header at the application or reverse proxy layer.",
                confidence="high",
                tags=["web", "headers"],
            ),
            Finding(
                id="HTTP-001",
                title="Missing HSTS header",
                severity="medium",
                category="web_headers",
                target="host-a",
                description="The security header `strict-transport-security` was not observed on the HTTPS response.",
                evidence="Headers observed: ['server', 'x-frame-options'].",
                recommendation="Set the recommended HTTP response header at the application or reverse proxy layer.",
                confidence="high",
                tags=["web", "headers"],
            ),
            Finding(
                id="HTTP-068-page",
                title="Discovered page surface",
                severity="info",
                category="attack_surface",
                target="host-a",
                description="A same-host page was discovered.",
                evidence="page: https://host-a/admin",
                recommendation="Review the page.",
                confidence="medium",
                tags=["web", "surface"],
            ),
            Finding(
                id="HTTP-068-query_parameter",
                title="Discovered query parameter surface",
                severity="info",
                category="attack_surface",
                target="host-a",
                description="A query parameter was discovered.",
                evidence="query_parameter: id",
                recommendation="Review the parameter.",
                confidence="medium",
                tags=["web", "surface"],
            ),
        ],
    )


def test_reporting_writers_emit_markdown_csv_and_sarif():
    result = _sample_result()
    output_dir = Path("test-report-output")
    output_dir.mkdir(exist_ok=True)
    markdown_path = output_dir / "report.md"
    html_path = output_dir / "report.html"
    csv_path = output_dir / "report.csv"
    sarif_path = output_dir / "report.sarif"

    try:
        write_markdown_report(result, markdown_path)
        write_html_report(result, html_path)
        write_csv_report(result, csv_path)
        write_sarif_report(result, sarif_path)

        assert "AccuScanner Report" in markdown_path.read_text(encoding="utf-8")
        html_text = html_path.read_text(encoding="utf-8")
        assert "Discovered Attack Surface" in html_text
        assert "Pages" in html_text
        assert "Query Parameters" in html_text
        assert "https://host-a/admin" in html_text
        assert "query_parameter: id" not in html_text
        assert html_text.count("Missing HSTS header") == 3
        assert "Protocols:</strong> HTTP, HTTPS" in html_text
        assert "HTTP-005" in csv_path.read_text(encoding="utf-8")
        assert "HTTP-068-page" not in csv_path.read_text(encoding="utf-8")
        assert '"version": "2.1.0"' in sarif_path.read_text(encoding="utf-8")
    finally:
        markdown_path.unlink(missing_ok=True)
        html_path.unlink(missing_ok=True)
        csv_path.unlink(missing_ok=True)
        sarif_path.unlink(missing_ok=True)
        output_dir.rmdir()


def test_html_report_groups_code_findings_by_category_and_file():
    result = ScanResult(
        metadata=ScanMetadata(
            target="repo-a",
            scan_mode="code",
            started_at="2026-04-20T12:00:00Z",
            ended_at="2026-04-20T12:00:05Z",
            duration_seconds=5.0,
            nmap_command=[],
        ),
        findings=[
            Finding(
                id="CODE-EXEC-001-file1.py-10",
                title="Shell execution with shell=True detected",
                severity="high",
                category="code_execution",
                target="file1.py",
                description="Risky shell execution detected.",
                evidence="file1.py:10: subprocess.run(cmd, shell=True)",
                recommendation="Avoid shell=True.",
                confidence="medium",
                tags=["code"],
            ),
            Finding(
                id="CODE-TLS-001-file1.py-12",
                title="TLS verification disabled in client request",
                severity="medium",
                category="code_transport",
                target="file1.py",
                description="TLS verify disabled.",
                evidence="file1.py:12: requests.get(url, verify=False)",
                recommendation="Enable TLS verification.",
                confidence="medium",
                tags=["code"],
            ),
        ],
    )
    output_dir = Path("test-code-report-output")
    output_dir.mkdir(exist_ok=True)
    html_path = output_dir / "report.html"

    try:
        write_html_report(result, html_path)
        html_text = html_path.read_text(encoding="utf-8")

        assert "Code Findings By Category" in html_text
        assert "Code Findings By File" in html_text
        assert "code_execution" in html_text
        assert "file1.py" in html_text
    finally:
        html_path.unlink(missing_ok=True)
        output_dir.rmdir()

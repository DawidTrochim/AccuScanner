from pathlib import Path

from mininessus.models import Finding, ScanMetadata, ScanResult
from mininessus.reporting import write_csv_report, write_markdown_report, write_sarif_report


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
            )
        ],
    )


def test_reporting_writers_emit_markdown_csv_and_sarif():
    result = _sample_result()
    output_dir = Path("test-report-output")
    output_dir.mkdir(exist_ok=True)
    markdown_path = output_dir / "report.md"
    csv_path = output_dir / "report.csv"
    sarif_path = output_dir / "report.sarif"

    try:
        write_markdown_report(result, markdown_path)
        write_csv_report(result, csv_path)
        write_sarif_report(result, sarif_path)

        assert "AccuScanner Report" in markdown_path.read_text(encoding="utf-8")
        assert "HTTP-005" in csv_path.read_text(encoding="utf-8")
        assert '"version": "2.1.0"' in sarif_path.read_text(encoding="utf-8")
    finally:
        markdown_path.unlink(missing_ok=True)
        csv_path.unlink(missing_ok=True)
        sarif_path.unlink(missing_ok=True)
        output_dir.rmdir()

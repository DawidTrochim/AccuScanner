from pathlib import Path
import json

from mininessus.history import load_history_reports, store_scan_history
from mininessus.models import Finding, ScanMetadata, ScanResult


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


def test_store_scan_history_creates_history_copy_and_loads_reports():
    output_dir = Path("test-history-output")
    history_dir = output_dir / "history"
    report_path = output_dir / "report.json"
    output_dir.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(_sample_result().to_dict()), encoding="utf-8")

    try:
        history_path = store_scan_history(_sample_result(), report_path, str(history_dir))
        reports = load_history_reports(history_dir)
        assert history_path.exists()
        assert len(reports) == 1
        assert reports[0]["metadata"]["target"] == "host-a"
    finally:
        for path in history_dir.glob("*"):
            path.unlink(missing_ok=True)
        history_dir.rmdir()
        report_path.unlink(missing_ok=True)
        output_dir.rmdir()

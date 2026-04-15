from mininessus.reporting import build_dashboard


def test_build_dashboard_aggregates_report_summaries():
    reports = [
        {
            "metadata": {"target": "host-a", "scan_mode": "quick", "duration_seconds": 3, "started_at": "2026-04-15T10:00:00Z"},
            "summary": {
                "severity_totals": {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0},
                "severity_score": 9,
                "total_findings": 2,
            },
            "findings": [
                {"id": "HTTP-005", "severity": "high", "title": "HTTP service does not enforce HTTPS", "target": "host-a"},
                {"id": "HTTP-012", "severity": "low", "title": "Server header discloses implementation details", "target": "host-a"},
            ],
        },
        {
            "metadata": {"target": "host-b", "scan_mode": "full", "duration_seconds": 5, "started_at": "2026-04-15T11:00:00Z"},
            "summary": {
                "severity_totals": {"critical": 0, "high": 0, "medium": 2, "low": 0, "info": 0},
                "severity_score": 8,
                "total_findings": 2,
            },
            "findings": [
                {"id": "TLS-002", "severity": "medium", "title": "Self-signed TLS certificate", "target": "host-b"},
                {"id": "SSH-003", "severity": "medium", "title": "SSH root login explicitly enabled", "target": "host-b"},
            ],
        },
        {
            "metadata": {"target": "host-a", "scan_mode": "full", "duration_seconds": 4, "started_at": "2026-04-15T12:00:00Z"},
            "summary": {
                "severity_totals": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                "severity_score": 7,
                "total_findings": 1,
            },
            "findings": [
                {"id": "HTTP-005", "severity": "high", "title": "HTTP service does not enforce HTTPS", "target": "host-a"},
            ],
        },
    ]

    dashboard = build_dashboard(reports)

    assert dashboard["scan_count"] == 3
    assert dashboard["target_count"] == 2
    assert dashboard["total_findings"] == 5
    assert dashboard["severity_score"] == 24
    assert dashboard["severity_totals"]["high"] == 2
    assert dashboard["severity_totals"]["medium"] == 2
    assert len(dashboard["timeline"]) == 3
    assert dashboard["most_common_findings"][0]["id"] == "HTTP-005"
    assert dashboard["most_common_findings"][0]["count"] == 2
    assert "host-a" in dashboard["target_history"]
    assert dashboard["recurring_findings"][0]["id"] == "HTTP-005"
    assert dashboard["recurring_findings"][0]["status"] == "recurring"
    assert dashboard["riskiest_targets"][0]["target"] == "host-a"
    assert dashboard["executive_summary"]["priority_focus"] == "Focus first on host-a"

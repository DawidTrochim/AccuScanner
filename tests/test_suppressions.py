import json
from pathlib import Path

from mininessus.models import Finding
from mininessus.suppressions import apply_suppressions, load_suppression_rules


def test_suppressions_filter_matching_findings():
    suppressions_path = Path("test-suppressions.json")
    suppressions_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "ids": ["HTTP-012"],
                        "targets": ["host-a"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    try:
        rules = load_suppression_rules(str(suppressions_path))
        findings = [
            Finding(
                id="HTTP-012",
                title="Server header discloses implementation details",
                severity="low",
                category="web_headers",
                target="host-a",
                description="Header exposed.",
                evidence="Server: nginx",
                recommendation="Suppress server version details.",
                tags=["web"],
            ),
            Finding(
                id="HTTP-005",
                title="HTTP service does not enforce HTTPS",
                severity="high",
                category="web_security",
                target="host-a",
                description="HTTP stayed in plaintext.",
                evidence="Observed status 200.",
                recommendation="Redirect to HTTPS.",
                tags=["web"],
            ),
        ]

        filtered = apply_suppressions(findings, rules)
        assert len(filtered) == 1
        assert filtered[0].id == "HTTP-005"
    finally:
        suppressions_path.unlink(missing_ok=True)


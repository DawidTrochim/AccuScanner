from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_SCORES = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 0,
}
CONFIDENCE_SCORES = {
    "high": 2,
    "medium": 1,
    "low": 0,
}
PRIORITY_TAG_BONUSES = {
    "auth": 2,
    "correlation": 2,
    "cloud": 1,
    "kubernetes": 1,
    "windows": 1,
    "linux": 1,
    "public": 1,
}


@dataclass(slots=True)
class PortService:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    banner: str | None = None

    @property
    def display_name(self) -> str:
        parts = [self.service, self.product, self.version]
        return " ".join(part for part in parts if part) or f"{self.protocol}/{self.port}"


@dataclass(slots=True)
class HostResult:
    address: str
    hostname: str | None = None
    status: str = "unknown"
    ports: list[PortService] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    category: str
    target: str
    description: str
    evidence: str
    recommendation: str
    confidence: str = "medium"
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanMetadata:
    target: str
    scan_mode: str
    started_at: str
    ended_at: str
    duration_seconds: float
    nmap_command: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    metadata: ScanMetadata
    hosts: list[HostResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def deduplicated_findings(self) -> list[Finding]:
        unique: dict[tuple[str, str, str], Finding] = {}
        for finding in self.findings:
            unique[(finding.id, finding.target, finding.evidence)] = finding
        return sorted(
            unique.values(),
            key=lambda finding: (-SEVERITY_SCORES.get(finding.severity.lower(), 0), finding.id, finding.target),
        )

    def severity_totals(self) -> dict[str, int]:
        totals = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.deduplicated_findings():
            severity = finding.severity.lower()
            totals.setdefault(severity, 0)
            totals[severity] += 1
        return totals

    def severity_score(self) -> int:
        return sum(SEVERITY_SCORES.get(finding.severity.lower(), 0) for finding in self.deduplicated_findings())

    def priority_score(self, finding: Finding) -> int:
        base = SEVERITY_SCORES.get(finding.severity.lower(), 0)
        confidence = CONFIDENCE_SCORES.get(finding.confidence.lower(), 0)
        tag_bonus = sum(PRIORITY_TAG_BONUSES.get(tag.lower(), 0) for tag in finding.tags)
        return base + confidence + tag_bonus

    def top_risks(self, limit: int = 5) -> list[Finding]:
        return sorted(
            self.deduplicated_findings(),
            key=lambda finding: (-self.priority_score(finding), -SEVERITY_SCORES.get(finding.severity.lower(), 0), finding.id, finding.target),
        )[:limit]

    def findings_by_target(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.deduplicated_findings():
            grouped.setdefault(finding.target, []).append(finding)
        for findings in grouped.values():
            findings.sort(key=lambda finding: (-self.priority_score(finding), -SEVERITY_SCORES.get(finding.severity.lower(), 0), finding.id))
        return dict(sorted(grouped.items(), key=lambda item: item[0]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": asdict(self.metadata),
            "summary": {
                "severity_totals": self.severity_totals(),
                "severity_score": self.severity_score(),
                "total_findings": len(self.deduplicated_findings()),
                "priority_score": sum(self.priority_score(finding) for finding in self.deduplicated_findings()),
                "top_risks": [asdict(finding) for finding in self.top_risks()],
            },
            "hosts": [asdict(host) for host in self.hosts],
            "findings": [asdict(finding) for finding in self.deduplicated_findings()],
            "findings_by_target": {
                target: [asdict(finding) for finding in findings]
                for target, findings in self.findings_by_target().items()
            },
            "errors": self.errors,
        }


@dataclass(slots=True)
class ReportDiff:
    new_findings: list[Finding]
    resolved_findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_findings": [asdict(finding) for finding in self.new_findings],
            "resolved_findings": [asdict(finding) for finding in self.resolved_findings],
        }


def build_finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    target: str,
    description: str,
    evidence: str,
    recommendation: str,
    confidence: str = "medium",
    tags: list[str] | None = None,
) -> Finding:
    """Create a Finding with normalized severity formatting."""

    return Finding(
        id=finding_id,
        title=title,
        severity=severity.lower(),
        category=category,
        target=target,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        confidence=confidence.lower(),
        tags=tags or [],
    )

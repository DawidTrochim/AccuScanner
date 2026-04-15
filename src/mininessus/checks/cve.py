from __future__ import annotations

import re
from collections.abc import Iterable

from .base import BaseCheck
from .cve_rules import CVE_RULES
from ..models import Finding, HostResult, PortService


VERSION_PART_RE = re.compile(r"\d+")


class CveMappingCheck(BaseCheck):
    name = "cve_mapping"

    def run(self, hosts: list[HostResult], target: str) -> Iterable[Finding]:
        findings: list[Finding] = []
        for host in hosts:
            for port in host.ports:
                if port.state != "open":
                    continue
                findings.extend(self._match_port_rules(host.address, port))
        return findings

    def _match_port_rules(self, target: str, port: PortService) -> list[Finding]:
        findings: list[Finding] = []
        for rule in CVE_RULES:
            if not _port_matches_rule(port, rule):
                continue
            findings.append(
                self.finding(
                    finding_id=rule["id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    category="cve_mapping",
                    target=target,
                    description=rule["description"],
                    evidence=f"Detected {port.display_name} on {port.port}/{port.protocol}.",
                    recommendation=rule["recommendation"],
                    confidence="low",
                    tags=["cve", "version", port.service or "service"],
                )
            )
        return findings


def _port_matches_rule(port: PortService, rule: dict) -> bool:
    service_name = (port.service or "").lower()
    product = (port.product or "").lower()
    version = port.version or ""

    if rule.get("service") and rule["service"] not in {service_name, (port.tunnel or "").lower()}:
        return False
    if rule.get("product_contains") and rule["product_contains"] not in product:
        return False
    if rule.get("version_equals") and version != rule["version_equals"]:
        return False
    if rule.get("version_contains") and rule["version_contains"] not in version:
        return False
    if rule.get("version_in") and version not in rule["version_in"]:
        return False
    if rule.get("version_lt") and not _version_lt(version, rule["version_lt"]):
        return False
    return True


def _version_lt(version: str, minimum: str) -> bool:
    current_parts = [int(value) for value in VERSION_PART_RE.findall(version)]
    minimum_parts = [int(value) for value in VERSION_PART_RE.findall(minimum)]
    if not current_parts:
        return False
    length = max(len(current_parts), len(minimum_parts))
    current_parts.extend([0] * (length - len(current_parts)))
    minimum_parts.extend([0] * (length - len(minimum_parts)))
    return tuple(current_parts) < tuple(minimum_parts)

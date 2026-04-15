from __future__ import annotations

from collections.abc import Iterable

from .base import BaseCheck
from ..models import HostResult


SENSITIVE_SERVICES = {"ftp", "telnet", "rdp", "vnc", "smb", "microsoft-ds"}


class BannerExposureCheck(BaseCheck):
    name = "banner_exposure"

    def run(self, hosts: list[HostResult], target: str) -> Iterable[Finding]:
        findings: list[Finding] = []
        for host in hosts:
            for port in host.ports:
                if port.state != "open":
                    continue
                service_name = (port.service or "").lower()
                banner_text = " ".join(part for part in [port.product, port.version, port.banner] if part)
                if service_name in SENSITIVE_SERVICES or banner_text:
                    findings.append(
                        self.finding(
                            finding_id=f"BANNER-{port.port}",
                            title="Service banner exposure",
                            severity="low" if banner_text else "info",
                            category="service_exposure",
                            target=host.address,
                            description="Open service metadata may help an attacker fingerprint software and prioritize exploits.",
                            evidence=f"Port {port.port}/{port.protocol}: {port.display_name}; banner: {banner_text or 'not captured'}",
                            recommendation="Reduce publicly exposed service metadata where possible and keep services patched.",
                        )
                    )
        return findings

from __future__ import annotations

from collections.abc import Iterable

from .base import BaseCheck
from ..models import Finding, HostResult


RISKY_PORTS = {
    21: ("FTP exposed", "FTP is often deployed without strong encryption."),
    23: ("Telnet exposed", "Telnet transmits credentials in cleartext."),
    3389: ("RDP exposed", "Internet-facing RDP increases brute-force and exploit risk."),
    5900: ("VNC exposed", "VNC services are frequently weakly authenticated."),
}


class RiskyPortCheck(BaseCheck):
    name = "risky_ports"

    def run(self, hosts: list[HostResult], target: str) -> Iterable[Finding]:
        findings: list[Finding] = []
        for host in hosts:
            for port in host.ports:
                if port.state != "open" or port.port not in RISKY_PORTS:
                    continue
                title, description = RISKY_PORTS[port.port]
                findings.append(
                    self.finding(
                        finding_id=f"PORT-{port.port}",
                        title=title,
                        severity="high",
                        category="network_exposure",
                        target=host.address,
                        description=description,
                        evidence=f"Open port {port.port}/{port.protocol} detected ({port.display_name}).",
                        recommendation="Restrict access with firewall rules, VPN, or service hardening.",
                    )
                )
        return findings

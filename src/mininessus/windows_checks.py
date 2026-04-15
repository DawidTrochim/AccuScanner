from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from .models import Finding, HostResult, build_finding

try:
    import winrm
except ImportError:  # pragma: no cover
    winrm = None


@dataclass(slots=True)
class WinRMAuthConfig:
    username: str
    password: str
    port: int = 5985
    use_ssl: bool = False
    transport: str = "ntlm"


WindowsFindingParser = Callable[[str, str, str, int], Finding | None]


@dataclass(frozen=True, slots=True)
class WindowsCommandCheck:
    command: str
    parser: WindowsFindingParser


def run_windows_host_checks(hosts: list[HostResult], auth: WinRMAuthConfig | None) -> list[Finding]:
    if auth is None:
        return []
    if winrm is None:
        return [
            build_finding(
                finding_id="WINRM-000",
                title="Windows checks unavailable",
                severity="info",
                category="host_auth",
                target="winrm",
                description="pywinrm is not installed, so authenticated Windows checks were skipped.",
                evidence="Install project dependencies including pywinrm to enable Windows host assessments.",
                recommendation="Install dependencies and provide WinRM credentials to enable authenticated Windows review.",
                confidence="high",
                tags=["winrm", "windows", "auth"],
            )
        ]

    findings: list[Finding] = []
    for host in hosts:
        open_ports = {port.port for port in host.ports if port.state == "open"}
        if auth.port not in open_ports and not ({5985, 5986} & open_ports):
            continue
        findings.extend(_inspect_windows_host(host, auth))
    return findings


def _inspect_windows_host(host: HostResult, auth: WinRMAuthConfig) -> list[Finding]:
    findings: list[Finding] = []
    scheme = "https" if auth.use_ssl else "http"
    endpoint = f"{scheme}://{host.address}:{auth.port}/wsman"
    try:
        session = winrm.Session(endpoint, auth=(auth.username, auth.password), transport=auth.transport)
        findings.extend(_run_windows_commands(session, host.address))
    except Exception as exc:
        findings.append(
            build_finding(
                finding_id="WINRM-004",
                title="Authenticated Windows review failed",
                severity="info",
                category="host_auth",
                target=host.address,
                description="The scanner could not complete authenticated Windows review over WinRM.",
                evidence=str(exc),
                recommendation="Validate WinRM reachability, credentials, and transport settings before rerunning Windows checks.",
                confidence="high",
                tags=["winrm", "windows", "auth"],
            )
        )
    return findings


def _run_windows_commands(session, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for check in _windows_command_checks():
        result = session.run_ps(check.command)
        stdout = result.std_out.decode("utf-8", errors="replace").strip()
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        finding = check.parser(target, stdout, stderr, result.status_code)
        if finding is not None:
            findings.append(finding)
    return findings


def _windows_command_checks() -> list[WindowsCommandCheck]:
    return [
        WindowsCommandCheck(
            "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'False'} | Select-Object -ExpandProperty Name) -join ', '",
            _firewall_finding,
        ),
        WindowsCommandCheck(
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
            _rdp_finding,
        ),
        WindowsCommandCheck(
            "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled",
            _guest_finding,
        ),
        WindowsCommandCheck(
            "(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled",
            _defender_finding,
        ),
        WindowsCommandCheck(
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication",
            _rdp_nla_finding,
        ),
        WindowsCommandCheck(
            "(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA",
            _uac_finding,
        ),
        WindowsCommandCheck(
            "(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ', '",
            _local_admins_inventory_finding,
        ),
        WindowsCommandCheck(
            "(Get-CimInstance Win32_OperatingSystem).Version",
            _windows_version_finding,
        ),
        WindowsCommandCheck(
            "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 -ExpandProperty HotFixID) -join ', '",
            _hotfix_inventory_finding,
        ),
        WindowsCommandCheck(
            "$latest = Get-HotFix | Where-Object {$_.InstalledOn} | Sort-Object InstalledOn -Descending | "
            "Select-Object -First 1 -ExpandProperty InstalledOn; if ($latest) { Get-Date ([datetime]$latest) -Format 'yyyy-MM-dd' }",
            _stale_patch_finding,
        ),
    ]


def _firewall_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if stdout:
        return build_finding(
            finding_id="WINRM-001",
            title="Windows firewall profile disabled",
            severity="medium",
            category="host_auth",
            target=target,
            description="One or more Windows firewall profiles appear disabled.",
            evidence=stdout,
            recommendation="Enable the Windows firewall on all relevant profiles or confirm compensating controls are in place.",
            confidence="medium",
            tags=["winrm", "windows", "firewall"],
        )
    return None


def _rdp_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if stdout == "0":
        return build_finding(
            finding_id="WINRM-002",
            title="RDP is enabled on the host",
            severity="medium",
            category="host_auth",
            target=target,
            description="Remote Desktop appears enabled on the Windows host.",
            evidence="fDenyTSConnections is set to 0.",
            recommendation="Disable RDP unless it is operationally required and restrict access to trusted management paths.",
            confidence="high",
            tags=["winrm", "windows", "rdp"],
        )
    return None


def _guest_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if stdout.lower() == "true":
        return build_finding(
            finding_id="WINRM-003",
            title="Guest account enabled",
            severity="high",
            category="host_auth",
            target=target,
            description="The built-in Guest account appears enabled.",
            evidence="Local Guest account returned Enabled=True.",
            recommendation="Disable the Guest account unless there is a documented exception requiring it.",
            confidence="high",
            tags=["winrm", "windows", "accounts"],
        )
    return None


def _defender_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if stdout.lower() == "false":
        return build_finding(
            finding_id="WINRM-005",
            title="Windows Defender appears disabled",
            severity="medium",
            category="host_auth",
            target=target,
            description="The host reported antivirus protection as disabled.",
            evidence="Get-MpComputerStatus returned AntivirusEnabled=False.",
            recommendation="Enable Microsoft Defender or confirm an approved endpoint protection platform is active.",
            confidence="medium",
            tags=["winrm", "windows", "defender"],
        )
    return None


def _windows_version_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if stdout:
        return build_finding(
            finding_id="WINRM-006",
            title="Authenticated Windows version inventory",
            severity="info",
            category="host_inventory",
            target=target,
            description="Authenticated Windows review captured the operating system version.",
            evidence=stdout,
            recommendation="Use authenticated inventory data to compare the host OS version against your patch baseline.",
            confidence="high",
            tags=["winrm", "windows", "inventory"],
        )
    return None


def _hotfix_inventory_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if not stdout:
        return None
    return build_finding(
        finding_id="WINRM-007",
        title="Authenticated Windows hotfix inventory sample",
        severity="info",
        category="host_inventory",
        target=target,
        description="Authenticated Windows review captured a sample of recently installed hotfixes.",
        evidence=stdout,
        recommendation="Use authenticated inventory data to compare installed hotfixes against your patch baseline.",
        confidence="high",
        tags=["winrm", "windows", "inventory", "patching"],
    )


def _rdp_nla_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if stdout != "0":
        return None
    return build_finding(
        finding_id="WINRM-011",
        title="RDP Network Level Authentication appears disabled",
        severity="high",
        category="host_auth",
        target=target,
        description="The RDP configuration suggests Network Level Authentication is disabled.",
        evidence="RDP UserAuthentication value is 0.",
        recommendation="Enable Network Level Authentication for RDP and restrict remote access to trusted administrative paths.",
        confidence="high",
        tags=["winrm", "windows", "rdp", "auth"],
    )


def _uac_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if stdout != "0":
        return None
    return build_finding(
        finding_id="WINRM-012",
        title="Windows UAC appears disabled",
        severity="medium",
        category="host_auth",
        target=target,
        description="The system policy suggests User Account Control is disabled.",
        evidence="EnableLUA value is 0.",
        recommendation="Re-enable UAC unless there is a documented exception and compensating control.",
        confidence="high",
        tags=["winrm", "windows", "uac"],
    )


def _local_admins_inventory_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if not stdout:
        return None
    return build_finding(
        finding_id="WINRM-013",
        title="Authenticated local administrators inventory",
        severity="info",
        category="host_inventory",
        target=target,
        description="Authenticated Windows review captured the current local Administrators group membership.",
        evidence=stdout,
        recommendation="Review local administrator membership against your least-privilege baseline.",
        confidence="high",
        tags=["winrm", "windows", "inventory", "accounts"],
    )


def _stale_patch_finding(target: str, stdout: str, stderr: str, status_code: int) -> Finding | None:
    if not stdout:
        return None
    try:
        latest_hotfix_date = datetime.strptime(stdout, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None

    patch_age_days = (datetime.now(UTC) - latest_hotfix_date).days
    if patch_age_days <= 90:
        return None

    return build_finding(
        finding_id="WINRM-008",
        title="Latest detected Windows hotfix appears stale",
        severity="medium",
        category="host_patch",
        target=target,
        description="The most recent detected hotfix appears older than 90 days.",
        evidence=f"Latest detected hotfix date: {stdout} ({patch_age_days} days ago).",
        recommendation="Review Windows patch cadence and confirm the host is receiving recent security updates.",
        confidence="medium",
        tags=["winrm", "windows", "patching"],
    )

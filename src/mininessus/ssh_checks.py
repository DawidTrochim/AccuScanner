from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .models import Finding, HostResult, build_finding

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None


@dataclass(slots=True)
class SSHAuthConfig:
    username: str
    password: str | None = None
    key_path: str | None = None
    port: int = 22
    timeout: int = 5


LinuxFindingParser = Callable[[str, str, str, int], Finding | None]


@dataclass(frozen=True, slots=True)
class LinuxCommandCheck:
    command: str
    parser: LinuxFindingParser


def run_linux_ssh_checks(hosts: list[HostResult], auth: SSHAuthConfig | None) -> list[Finding]:
    if auth is None:
        return []
    if paramiko is None:
        return [
            build_finding(
                finding_id="SSH-000",
                title="SSH checks unavailable",
                severity="info",
                category="host_auth",
                target="ssh",
                description="Paramiko is not installed, so authenticated Linux checks were skipped.",
                evidence="Install project dependencies including paramiko to enable SSH checks.",
                recommendation="Install dependencies and provide SSH credentials to enable authenticated Linux assessments.",
                confidence="high",
                tags=["ssh", "linux", "auth"],
            )
        ]

    findings: list[Finding] = []
    for host in hosts:
        if 22 not in {port.port for port in host.ports if port.state == "open"}:
            continue
        findings.extend(_inspect_linux_host(host, auth))
    return findings


def _inspect_linux_host(host: HostResult, auth: SSHAuthConfig) -> list[Finding]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    findings: list[Finding] = []
    try:
        client.connect(
            hostname=host.address,
            port=auth.port,
            username=auth.username,
            password=auth.password,
            key_filename=auth.key_path,
            timeout=auth.timeout,
            look_for_keys=auth.key_path is None and auth.password is None,
            allow_agent=True,
        )
        findings.extend(_run_linux_commands(client, host.address))
    except Exception as exc:
        findings.append(
            build_finding(
                finding_id="SSH-004",
                title="Authenticated SSH review failed",
                severity="info",
                category="host_auth",
                target=host.address,
                description="The scanner could not complete authenticated Linux review over SSH.",
                evidence=str(exc),
                recommendation="Validate SSH reachability and credentials before rerunning authenticated host checks.",
                confidence="high",
                tags=["ssh", "linux", "auth"],
            )
        )
    finally:
        client.close()
    return findings


def _run_linux_commands(client, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for check in _linux_command_checks():
        stdout, stderr, exit_code = _exec_command(client, check.command)
        finding = check.parser(target, stdout.strip(), stderr.strip(), exit_code)
        if finding is not None:
            findings.append(finding)
    return findings


def _linux_command_checks() -> list[LinuxCommandCheck]:
    return [
        LinuxCommandCheck("sudo -n true >/dev/null 2>&1; echo $?", _sudo_without_password_finding),
        LinuxCommandCheck(
            "find /etc /usr/local/bin -xdev -type f -perm -0002 2>/dev/null | head -n 5",
            _world_writable_finding,
        ),
        LinuxCommandCheck(
            "grep -Ei '^\\s*PermitRootLogin\\s+yes' /etc/ssh/sshd_config 2>/dev/null",
            _root_login_finding,
        ),
        LinuxCommandCheck(
            "command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null || echo 'ufw-not-installed'",
            _ufw_finding,
        ),
        LinuxCommandCheck(
            "grep -Ei '^\\s*PasswordAuthentication\\s+yes' /etc/ssh/sshd_config 2>/dev/null",
            _password_auth_finding,
        ),
        LinuxCommandCheck(
            "grep -Ei '^\\s*PermitEmptyPasswords\\s+yes' /etc/ssh/sshd_config 2>/dev/null",
            _empty_passwords_finding,
        ),
        LinuxCommandCheck(
            "find /etc/cron* -xdev -type f -perm -0002 2>/dev/null | head -n 5",
            _world_writable_cron_finding,
        ),
        LinuxCommandCheck("id -nG", _docker_group_membership_finding),
        LinuxCommandCheck("uname -r", _kernel_version_finding),
        LinuxCommandCheck(
            "if command -v apt >/dev/null 2>&1; then apt list --upgradable 2>/dev/null | sed -n '2,6p'; "
            "elif command -v dnf >/dev/null 2>&1; then dnf check-update -q 2>/dev/null | awk 'NF>=2 {print $1\" \"$2}' | head -n 5; "
            "elif command -v yum >/dev/null 2>&1; then yum check-update -q 2>/dev/null | awk 'NF>=2 {print $1\" \"$2}' | head -n 5; "
            "else echo ''; fi",
            _package_updates_finding,
        ),
        LinuxCommandCheck(
            "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | head -n 5; "
            "elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null | head -n 5; "
            "else echo ''; fi",
            _package_inventory_finding,
        ),
    ]


def _exec_command(client, command: str) -> tuple[str, str, int]:
    stdin, stdout, stderr = client.exec_command(command, timeout=10)
    exit_code = stdout.channel.recv_exit_status()
    return stdout.read().decode("utf-8", errors="replace"), stderr.read().decode("utf-8", errors="replace"), exit_code


def _sudo_without_password_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if stdout == "0":
        return build_finding(
            finding_id="SSH-001",
            title="Passwordless sudo available to SSH account",
            severity="high",
            category="host_auth",
            target=target,
            description="The supplied SSH account can run sudo without an interactive password prompt.",
            evidence="`sudo -n true` returned success.",
            recommendation="Restrict passwordless sudo to tightly justified administrative workflows and review privilege scope.",
            confidence="high",
            tags=["ssh", "linux", "sudo"],
        )
    return None


def _world_writable_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if stdout:
        return build_finding(
            finding_id="SSH-002",
            title="World-writable privileged path content detected",
            severity="high",
            category="host_auth",
            target=target,
            description="Files in privileged system paths appear to be world writable.",
            evidence=stdout,
            recommendation="Remove world-writable permissions from privileged paths and review file ownership.",
            confidence="medium",
            tags=["ssh", "linux", "permissions"],
        )
    return None


def _root_login_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if stdout:
        return build_finding(
            finding_id="SSH-003",
            title="SSH root login explicitly enabled",
            severity="medium",
            category="host_auth",
            target=target,
            description="The SSH daemon configuration explicitly permits root login.",
            evidence=stdout,
            recommendation="Disable direct root SSH access and use named accounts plus privilege escalation where required.",
            confidence="high",
            tags=["ssh", "linux", "root"],
        )
    return None


def _ufw_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if "status: inactive" in stdout.lower():
        return build_finding(
            finding_id="SSH-005",
            title="Host firewall appears inactive",
            severity="medium",
            category="host_auth",
            target=target,
            description="The authenticated review suggests the host-based firewall is inactive.",
            evidence=stdout,
            recommendation="Enable a host firewall or confirm equivalent network-layer protections are in place.",
            confidence="medium",
            tags=["ssh", "linux", "firewall"],
        )
    return None


def _kernel_version_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if stdout:
        return build_finding(
            finding_id="SSH-006",
            title="Authenticated kernel version inventory",
            severity="info",
            category="host_inventory",
            target=target,
            description="Authenticated Linux review captured the running kernel version.",
            evidence=stdout,
            recommendation="Use authenticated inventory data to compare the host kernel against your patch baseline.",
            confidence="high",
            tags=["ssh", "linux", "inventory"],
        )
    return None


def _package_updates_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if not stdout:
        return None
    return build_finding(
        finding_id="SSH-007",
        title="Package updates appear to be available",
        severity="medium",
        category="host_patch",
        target=target,
        description="The authenticated Linux review identified packages with available updates.",
        evidence=stdout,
        recommendation="Review pending package updates and apply security patches according to your maintenance process.",
        confidence="medium",
        tags=["ssh", "linux", "patching"],
    )


def _password_auth_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if not stdout:
        return None
    return build_finding(
        finding_id="SSH-009",
        title="SSH password authentication explicitly enabled",
        severity="medium",
        category="host_auth",
        target=target,
        description="The SSH daemon configuration explicitly allows password authentication.",
        evidence=stdout,
        recommendation="Prefer key-based authentication and disable password authentication where operationally possible.",
        confidence="high",
        tags=["ssh", "linux", "auth"],
    )


def _empty_passwords_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if not stdout:
        return None
    return build_finding(
        finding_id="SSH-010",
        title="SSH empty-password logins explicitly enabled",
        severity="high",
        category="host_auth",
        target=target,
        description="The SSH daemon configuration explicitly permits accounts with empty passwords to authenticate.",
        evidence=stdout,
        recommendation="Disable empty-password SSH logins immediately and audit local account authentication settings.",
        confidence="high",
        tags=["ssh", "linux", "auth"],
    )


def _world_writable_cron_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if not stdout:
        return None
    return build_finding(
        finding_id="SSH-011",
        title="World-writable cron content detected",
        severity="high",
        category="host_auth",
        target=target,
        description="Cron files appear world writable, which can allow unauthorized persistence or code execution.",
        evidence=stdout,
        recommendation="Remove world-writable permissions from cron paths and review scheduled task ownership.",
        confidence="medium",
        tags=["ssh", "linux", "cron"],
    )


def _docker_group_membership_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    groups = {group.strip() for group in stdout.split() if group.strip()}
    if "docker" not in groups:
        return None
    return build_finding(
        finding_id="SSH-012",
        title="Authenticated SSH account is in the docker group",
        severity="medium",
        category="host_auth",
        target=target,
        description="The authenticated account belongs to the docker group, which often grants root-equivalent container control on the host.",
        evidence=stdout,
        recommendation="Review docker group membership and restrict it to tightly controlled administrative accounts.",
        confidence="high",
        tags=["ssh", "linux", "docker", "auth"],
    )


def _package_inventory_finding(target: str, stdout: str, stderr: str, exit_code: int) -> Finding | None:
    if not stdout:
        return None
    return build_finding(
        finding_id="SSH-008",
        title="Authenticated package inventory sample",
        severity="info",
        category="host_inventory",
        target=target,
        description="Authenticated Linux review captured a small sample of installed packages.",
        evidence=stdout,
        recommendation="Use authenticated inventory data to compare installed packages against your approved baseline.",
        confidence="high",
        tags=["ssh", "linux", "inventory", "packages"],
    )

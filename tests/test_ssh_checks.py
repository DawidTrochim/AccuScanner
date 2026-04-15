from unittest.mock import MagicMock, patch

from mininessus.models import HostResult, PortService
from mininessus.ssh_checks import SSHAuthConfig, run_linux_ssh_checks


class _FakeStream:
    def __init__(self, text: str, exit_code: int = 0):
        self._text = text
        self.channel = MagicMock()
        self.channel.recv_exit_status.return_value = exit_code

    def read(self):
        return self._text.encode("utf-8")


def _exec_result(stdout_text: str, stderr_text: str = "", exit_code: int = 0):
    return MagicMock(), _FakeStream(stdout_text, exit_code), _FakeStream(stderr_text, exit_code)


@patch("mininessus.ssh_checks.paramiko")
def test_run_linux_ssh_checks_emits_findings_from_authenticated_commands(mock_paramiko):
    client = MagicMock()
    client.exec_command.side_effect = [
        _exec_result("0\n"),
        _exec_result("/etc/shadow\n"),
        _exec_result("PermitRootLogin yes\n"),
        _exec_result("Status: inactive\n"),
        _exec_result("PasswordAuthentication yes\n"),
        _exec_result("PermitEmptyPasswords yes\n"),
        _exec_result("/etc/cron.d/app\n"),
        _exec_result("ubuntu docker sudo\n"),
        _exec_result("6.8.0-31-generic\n"),
        _exec_result("openssl 3.0.2-0ubuntu1\nlinux-image-generic 6.8.0\n"),
        _exec_result("openssh-server 1:9.6p1-3ubuntu13.15\nnginx 1.24.0-2ubuntu7.4\n"),
    ]
    mock_paramiko.SSHClient.return_value = client
    mock_paramiko.AutoAddPolicy.return_value = object()

    host = HostResult(
        address="10.0.0.30",
        status="up",
        ports=[PortService(port=22, protocol="tcp", state="open", service="ssh")],
    )
    auth = SSHAuthConfig(username="ubuntu", password="passw0rd!")

    findings = run_linux_ssh_checks([host], auth)
    ids = {finding.id for finding in findings}

    assert {"SSH-001", "SSH-002", "SSH-003", "SSH-005", "SSH-006", "SSH-007", "SSH-008", "SSH-009", "SSH-010", "SSH-011", "SSH-012"} <= ids

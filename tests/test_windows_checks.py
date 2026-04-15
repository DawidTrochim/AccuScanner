from unittest.mock import MagicMock, patch

from mininessus.models import HostResult, PortService
from mininessus.windows_checks import WinRMAuthConfig, run_windows_host_checks


class _FakeWinRMResult:
    def __init__(self, stdout: str, stderr: str = "", status_code: int = 0):
        self.std_out = stdout.encode("utf-8")
        self.std_err = stderr.encode("utf-8")
        self.status_code = status_code


@patch("mininessus.windows_checks.winrm")
def test_run_windows_host_checks_emits_findings_from_authenticated_commands(mock_winrm):
    session = MagicMock()
    session.run_ps.side_effect = [
        _FakeWinRMResult("Domain, Private"),
        _FakeWinRMResult("0"),
        _FakeWinRMResult("True"),
        _FakeWinRMResult("False"),
        _FakeWinRMResult("0"),
        _FakeWinRMResult("0"),
        _FakeWinRMResult("BUILTIN\\Administrator, LAB\\Ops"),
        _FakeWinRMResult("10.0.17763"),
        _FakeWinRMResult("KB5034122, KB5033371"),
        _FakeWinRMResult("2024-01-10"),
    ]
    mock_winrm.Session.return_value = session

    host = HostResult(
        address="10.0.0.40",
        status="up",
        ports=[PortService(port=5985, protocol="tcp", state="open", service="http")],
    )
    auth = WinRMAuthConfig(username="Administrator", password="Password123!")

    findings = run_windows_host_checks([host], auth)
    ids = {finding.id for finding in findings}

    assert {"WINRM-001", "WINRM-002", "WINRM-003", "WINRM-005", "WINRM-006", "WINRM-007", "WINRM-008", "WINRM-011", "WINRM-012", "WINRM-013"} <= ids

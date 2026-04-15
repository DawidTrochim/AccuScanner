from unittest.mock import patch

from pathlib import Path

from mininessus.cli import _load_batch_targets, execute_scan
from mininessus.discovery import NmapExecution
from mininessus.models import HostResult


def _execution(xml: str, command: list[str]) -> NmapExecution:
    return NmapExecution(command=command, stdout=xml, stderr="", returncode=0)


EMPTY_SCAN_XML = """<?xml version="1.0"?><nmaprun></nmaprun>"""
HOST_SCAN_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="18.175.232.63" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@patch("mininessus.cli.run_checks")
@patch("mininessus.cli.run_nmap")
def test_execute_scan_retries_with_skip_host_discovery_when_no_hosts_found(mock_run_nmap, mock_run_checks):
    mock_run_nmap.side_effect = [
        _execution(EMPTY_SCAN_XML, ["nmap", "-oX", "-", "-T4", "-F", "-sV", "18.175.232.63"]),
        _execution(HOST_SCAN_XML, ["nmap", "-oX", "-", "-Pn", "-T4", "-F", "-sV", "18.175.232.63"]),
    ]
    mock_run_checks.return_value = []

    hosts, findings, errors, command, raw_xml = execute_scan("18.175.232.63", "quick")

    assert not errors
    assert findings == []
    assert len(hosts) == 1
    assert hosts[0].address == "18.175.232.63"
    assert command == ["nmap", "-oX", "-", "-Pn", "-T4", "-F", "-sV", "18.175.232.63"]
    assert "<host>" in raw_xml
    assert mock_run_nmap.call_count == 2
    assert mock_run_nmap.call_args_list[1].kwargs["skip_host_discovery"] is True


@patch("mininessus.cli.run_checks")
@patch("mininessus.cli.run_nmap")
def test_execute_scan_does_not_retry_when_hosts_are_found(mock_run_nmap, mock_run_checks):
    mock_run_nmap.return_value = _execution(HOST_SCAN_XML, ["nmap", "-oX", "-", "-T4", "-F", "-sV", "18.175.232.63"])
    mock_run_checks.return_value = []

    hosts, findings, errors, command, raw_xml = execute_scan("18.175.232.63", "quick")

    assert not errors
    assert findings == []
    assert len(hosts) == 1
    assert command == ["nmap", "-oX", "-", "-T4", "-F", "-sV", "18.175.232.63"]
    assert "<host>" in raw_xml
    assert mock_run_nmap.call_count == 1


def test_load_batch_targets_combines_cli_and_file_targets():
    targets_path = Path("test-targets.txt")
    targets_path.write_text("10.0.0.6\n10.0.0.7\n10.0.0.6\n", encoding="utf-8")
    try:
        targets = _load_batch_targets(["10.0.0.5"], str(targets_path))
        assert targets == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    finally:
        targets_path.unlink(missing_ok=True)

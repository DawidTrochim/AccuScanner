from mininessus.discovery import _normalize_nmap_command, build_extra_nmap_args


def test_build_extra_nmap_args_includes_udp_scan_settings():
    args = build_extra_nmap_args("22,80,443", "53,161", 20, ["ssl-cert"], ["safe", "vuln"], 10)

    assert "-sU" in args
    assert "-sS" in args
    assert "-p" in args
    assert "T:22,80,443,U:53,161" in args
    assert "--top-ports" in args
    assert "20" in args
    assert "--script" in args
    assert "safe,vuln,ssl-cert" in args
    assert "--min-parallelism" in args
    assert "10" in args


def test_build_extra_nmap_args_keeps_udp_only_scans_udp_only():
    args = build_extra_nmap_args(None, "53,161", None, None, None, None)

    assert "-sU" in args
    assert "-sS" not in args
    assert "-p" in args
    assert "U:53,161" in args


def test_normalize_nmap_command_removes_fast_scan_when_ports_are_explicit():
    command = ["nmap", "-oX", "-", "-T4", "-F", "-sV", "target", "-p", "T:22,80,U:53", "-sU"]

    normalized = _normalize_nmap_command(command)

    assert "-F" not in normalized
    assert "-p" in normalized
    assert "T:22,80,U:53" in normalized

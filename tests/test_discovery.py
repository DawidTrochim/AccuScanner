from mininessus.discovery import build_extra_nmap_args


def test_build_extra_nmap_args_includes_udp_scan_settings():
    args = build_extra_nmap_args("22,80,443", "53,161", 20, ["ssl-cert"], ["safe", "vuln"], 10)

    assert "-sU" in args
    assert "-p" in args
    assert "T:22,80,443,U:53,161" in args
    assert "--top-ports" in args
    assert "20" in args
    assert "--script" in args
    assert "safe,vuln,ssl-cert" in args
    assert "--min-parallelism" in args
    assert "10" in args

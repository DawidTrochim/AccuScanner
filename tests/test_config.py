from pathlib import Path

from mininessus.config import load_scan_config, merge_scan_config


def test_load_scan_config_reads_yaml():
    config_path = Path("test-scan-config.yml")
    try:
        config_path.write_text(
            "ports: '22,80,443'\nudp_ports: '53,161'\nudp_top_ports: 20\nnse_scripts:\n  - ssl-cert\nnse_categories:\n  - vuln\nparallelism: 10\nskip_host_discovery: true\nignore_ids:\n  - HTTP-001\nenable_azure_checks: true\n",
            encoding="utf-8",
        )

        config = load_scan_config(str(config_path))

        assert config.ports == "22,80,443"
        assert config.udp_ports == "53,161"
        assert config.udp_top_ports == 20
        assert config.nse_scripts == ["ssl-cert"]
        assert config.nse_categories == ["vuln"]
        assert config.parallelism == 10
        assert config.skip_host_discovery is True
        assert config.enable_azure_checks is True
        assert "HTTP-001" in config.ignore_ids
    finally:
        config_path.unlink(missing_ok=True)


def test_merge_scan_config_prefers_cli_values():
    assert merge_scan_config("80", "443") == "80"
    assert merge_scan_config(None, "443") == "443"

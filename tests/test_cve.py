from mininessus.checks.cve import CveMappingCheck
from mininessus.models import HostResult, PortService


def test_cve_mapping_matches_known_vulnerable_versions():
    host = HostResult(
        address="10.0.0.20",
        status="up",
        ports=[
            PortService(port=21, protocol="tcp", state="open", service="ftp", product="vsftpd", version="2.3.4"),
            PortService(port=80, protocol="tcp", state="open", service="http", product="Apache httpd", version="2.4.49"),
            PortService(port=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="7.2p2"),
        ],
    )

    findings = list(CveMappingCheck().run([host], "10.0.0.20"))
    ids = {finding.id for finding in findings}

    assert "CVE-2011-2523" in ids
    assert "CVE-2021-41773" in ids
    assert "CVE-2018-15473" in ids


def test_cve_mapping_matches_additional_service_rules():
    host = HostResult(
        address="10.0.0.21",
        status="up",
        ports=[
            PortService(port=21, protocol="tcp", state="open", service="ftp", product="ProFTPD", version="1.3.3c"),
            PortService(port=443, protocol="tcp", state="open", service="https", product="OpenSSL", version="3.0.6", tunnel="ssl"),
            PortService(port=445, protocol="tcp", state="open", service="microsoft-ds", product="Samba smbd", version="4.5.16"),
            PortService(port=80, protocol="tcp", state="open", service="http", product="Microsoft IIS httpd", version="6.0"),
        ],
    )

    findings = list(CveMappingCheck().run([host], "10.0.0.21"))
    ids = {finding.id for finding in findings}

    assert "CVE-2020-14145" in ids
    assert "CVE-2022-3602" in ids
    assert "CVE-2017-7494" in ids
    assert "CVE-2017-7269" in ids

from __future__ import annotations

from ..models import Finding, HostResult
from ..plugin_loader import load_plugin_checks
from .banner import BannerExposureCheck
from .cve import CveMappingCheck
from .http import HttpSecurityCheck
from .ports import RiskyPortCheck
from .services import ServiceExposureCheck
from .tls import TlsCertificateCheck


def get_check_plugins(plugin_dir: str | None = None) -> list:
    checks = [
        RiskyPortCheck(),
        ServiceExposureCheck(),
        HttpSecurityCheck(),
        TlsCertificateCheck(),
        CveMappingCheck(),
        BannerExposureCheck(),
    ]
    checks.extend(load_plugin_checks(plugin_dir))
    return checks


def run_checks(hosts: list[HostResult], target: str, plugin_dir: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for check in get_check_plugins(plugin_dir):
        findings.extend(list(check.run(hosts, target)))
    return findings

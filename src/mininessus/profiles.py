from __future__ import annotations

from dataclasses import fields, replace

from .config import ScanConfig


PROFILE_PRESETS: dict[str, ScanConfig] = {
    "external": ScanConfig(
        profile="external",
        ports="21,22,23,25,53,80,110,123,135,139,143,443,445,993,995,1433,1521,2375,3389,5432,5900,5985,5986,6379,6443,9200",
        udp_ports="53,123,161",
        nse_categories=["safe"],
        parallelism=10,
        save_history=True,
    ),
    "internal": ScanConfig(
        profile="internal",
        ports="1-1024,1433,1521,2375,3306,3389,5432,5900,5985,5986,6379,9200,10250",
        nse_categories=["safe", "default"],
        parallelism=20,
    ),
    "cloud": ScanConfig(
        profile="cloud",
        ports="22,80,443,445,3389,5985,5986,6379,6443,9200",
        udp_ports="53,123,161",
        nse_categories=["safe"],
        save_history=True,
        enable_aws_checks=True,
        enable_azure_checks=True,
        enable_gcp_checks=True,
    ),
    "k8s": ScanConfig(
        profile="k8s",
        ports="443,2379,6443,10250,10255,30000-32767",
        nse_scripts=["ssl-cert"],
        parallelism=10,
    ),
    "windows": ScanConfig(
        profile="windows",
        ports="80,135,139,445,3389,5985,5986",
        udp_ports="123,161",
        nse_categories=["safe"],
    ),
    "linux": ScanConfig(
        profile="linux",
        ports="21,22,23,80,111,443,2049,2375,3306,5432,6379,9200",
        udp_ports="53,123,161",
        nse_categories=["safe"],
    ),
}


def apply_profile(base_config: ScanConfig, profile_name: str | None) -> ScanConfig:
    if not profile_name:
        return base_config
    preset = PROFILE_PRESETS.get(profile_name)
    if preset is None:
        raise ValueError(f"Unknown scan profile: {profile_name}")
    merged = replace(preset)
    for field in fields(ScanConfig):
        field_name = field.name
        value = getattr(base_config, field_name)
        if value not in (None, False, "", [], set()):
            setattr(merged, field_name, value)
    merged.profile = profile_name
    return merged

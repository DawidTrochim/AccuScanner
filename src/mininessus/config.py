from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


@dataclass(slots=True)
class ScanConfig:
    profile: str | None = None
    ports: str | None = None
    udp_ports: str | None = None
    udp_top_ports: int | None = None
    nse_scripts: list[str] = field(default_factory=list)
    nse_categories: list[str] = field(default_factory=list)
    parallelism: int | None = None
    skip_host_discovery: bool = False
    save_raw_xml: bool = False
    save_history: bool = False
    history_dir: str | None = None
    suppressions_path: str | None = None
    ignore_ids: set[str] = field(default_factory=set)
    enable_aws_checks: bool = False
    enable_azure_checks: bool = False
    enable_gcp_checks: bool = False
    plugin_dir: str | None = None
    browser_assisted: bool = False
    browser_max_pages: int | None = None
    browser_timeout_ms: int | None = None
    web_cookie: str | None = None
    web_headers: list[str] = field(default_factory=list)


def load_scan_config(path: str | None) -> ScanConfig:
    if not path:
        return ScanConfig()
    raw_text = Path(path).read_text(encoding="utf-8")
    if yaml is None:
        content = _parse_simple_yaml(raw_text)
    else:
        content = yaml.safe_load(raw_text) or {}
    return ScanConfig(
        profile=content.get("profile"),
        ports=content.get("ports"),
        udp_ports=content.get("udp_ports"),
        udp_top_ports=content.get("udp_top_ports"),
        nse_scripts=[str(value) for value in content.get("nse_scripts", [])],
        nse_categories=[str(value) for value in content.get("nse_categories", [])],
        parallelism=content.get("parallelism"),
        skip_host_discovery=bool(content.get("skip_host_discovery", False)),
        save_raw_xml=bool(content.get("save_raw_xml", False)),
        save_history=bool(content.get("save_history", False)),
        history_dir=content.get("history_dir"),
        suppressions_path=content.get("suppressions_path"),
        ignore_ids={str(finding_id) for finding_id in content.get("ignore_ids", [])},
        enable_aws_checks=bool(content.get("enable_aws_checks", False)),
        enable_azure_checks=bool(content.get("enable_azure_checks", False)),
        enable_gcp_checks=bool(content.get("enable_gcp_checks", False)),
        plugin_dir=content.get("plugin_dir"),
        browser_assisted=bool(content.get("browser_assisted", False)),
        browser_max_pages=content.get("browser_max_pages"),
        browser_timeout_ms=content.get("browser_timeout_ms"),
        web_cookie=content.get("web_cookie"),
        web_headers=[str(value) for value in content.get("web_headers", [])],
    )


def merge_scan_config(cli_value: Any, config_value: Any) -> Any:
    return cli_value if cli_value not in (None, False, "") else config_value


def _parse_simple_yaml(raw_text: str) -> dict[str, Any]:
    """Fallback parser for small key/value scan profiles when PyYAML is unavailable."""

    parsed: dict[str, Any] = {}
    current_list_key: str | None = None
    for raw_line in raw_text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        stripped = line.strip()
        if stripped.startswith("- ") and current_list_key:
            parsed.setdefault(current_list_key, []).append(_coerce_simple_value(stripped[2:]))
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value == "":
            parsed[key] = []
            current_list_key = key
            continue
        current_list_key = None
        parsed[key] = _coerce_simple_value(value)
    return parsed


def _coerce_simple_value(value: str) -> Any:
    value = value.strip().strip("'").strip('"')
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if value.isdigit():
        return int(value)
    return value

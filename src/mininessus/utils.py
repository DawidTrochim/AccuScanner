from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # pragma: no cover
    Fore = Style = None

    def colorama_init(*_args, **_kwargs) -> None:
        return None


LOGGER_NAME = "accuscanner"


def configure_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    colorama_init(autoreset=True)
    return logging.getLogger(LOGGER_NAME)


def sanitize_target(target: str) -> str:
    if "://" not in target and "/" in target:
        return target.strip()
    parsed = urlparse(target if "://" in target else f"//{target}")
    hostname = parsed.hostname or parsed.path or target
    return hostname.strip()


def infer_scan_target(target: str) -> tuple[str, str | None]:
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname, parsed.scheme
    return sanitize_target(target), None


def ensure_output_dir(base_dir: str | None, timestamped: bool) -> Path:
    root = Path(base_dir or "reports")
    if timestamped:
        root = root / datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    root.mkdir(parents=True, exist_ok=True)
    return root


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "scan"


def utc_timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def build_report_stem(target: str, scan_mode: str, timestamp: str | None = None) -> str:
    parts = [safe_filename(sanitize_target(target)), scan_mode, timestamp or utc_timestamp()]
    return "-".join(part for part in parts if part)


def severity_color(severity: str) -> str:
    if Fore is None:
        return ""
    mapping = {
        "critical": Fore.MAGENTA,
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.CYAN,
        "info": Fore.GREEN,
    }
    return mapping.get(severity.lower(), "")


def color_text(text: str, severity: str) -> str:
    color = severity_color(severity)
    suffix = Style.RESET_ALL if color and Style is not None else ""
    return f"{color}{text}{suffix}" if color else text

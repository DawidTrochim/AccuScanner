from __future__ import annotations

import json
import shutil
from pathlib import Path

from .models import ScanResult


def store_scan_history(result: ScanResult, report_path: Path, history_dir: str | None = None) -> Path:
    root = Path(history_dir or "history")
    root.mkdir(parents=True, exist_ok=True)
    target_slug = _safe_name(result.metadata.target)
    history_path = root / f"{target_slug}-{result.metadata.scan_mode}-{result.metadata.started_at.replace(':', '').replace('-', '')}.json"
    shutil.copy2(report_path, history_path)
    _update_index(root / "index.json", history_path, result)
    return history_path


def load_history_reports(history_dir: str | Path) -> list[dict]:
    root = Path(history_dir)
    if not root.exists():
        return []
    reports: list[dict] = []
    for path in sorted(root.glob("*.json")):
        if path.name == "index.json":
            continue
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return reports


def _update_index(index_path: Path, history_path: Path, result: ScanResult) -> None:
    entries: list[dict] = []
    if index_path.exists():
        try:
            entries = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            entries = []
    entries.append(
        {
            "path": str(history_path),
            "target": result.metadata.target,
            "mode": result.metadata.scan_mode,
            "started_at": result.metadata.started_at,
            "severity_score": result.severity_score(),
            "total_findings": len(result.deduplicated_findings()),
        }
    )
    index_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in {".", "-", "_"} else "_" for char in value).strip("_") or "target"

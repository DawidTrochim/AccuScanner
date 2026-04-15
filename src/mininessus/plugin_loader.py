from __future__ import annotations

import importlib.util
from pathlib import Path


def load_plugin_checks(plugin_dir: str | None) -> list:
    if not plugin_dir:
        return []

    checks: list = []
    for path in sorted(Path(plugin_dir).glob("*.py")):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "get_checks"):
            checks.extend(module.get_checks())
        elif hasattr(module, "CHECKS"):
            checks.extend(module.CHECKS)
    return checks

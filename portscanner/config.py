"""
Configuration helpers for the port scanner CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


class ConfigLoadError(RuntimeError):
    """Raised when a configuration file cannot be loaded."""


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigLoadError(f"Config file not found: {path}")

    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigLoadError(f"Failed to parse config JSON: {exc}") from exc

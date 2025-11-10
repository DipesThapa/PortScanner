"""
Persistent baseline store for tracking scan history.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .differential import load_baseline_hosts


@dataclass
class BaselineRecord:
    path: Path
    timestamp: datetime
    summary: Dict[str, int]


class BaselineStore:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.history_path = self.directory / "history.json"
        self.history: List[Dict] = []
        if self.history_path.exists():
            try:
                data = json.loads(self.history_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self.history = data
            except json.JSONDecodeError:
                self.history = []

    def latest_record(self) -> Optional[BaselineRecord]:
        if not self.history:
            return None
        last = sorted(self.history, key=lambda item: item.get("timestamp", ""), reverse=True)[0]
        path = self.directory / last["filename"]
        if not path.exists():
            return None
        ts = datetime.fromisoformat(last["timestamp"])
        return BaselineRecord(path=path, timestamp=ts, summary=last.get("summary", {}))

    def load_latest_hosts(self) -> List[Dict]:
        record = self.latest_record()
        if not record:
            return []
        return load_baseline_hosts(str(record.path))

    def record_run(
        self,
        summary: Dict[str, int],
        hosts: Sequence[Dict],
        plugin_output: Optional[Dict] = None,
    ) -> Path:
        timestamp = datetime.utcnow().replace(microsecond=0)
        filename = f"run-{timestamp.isoformat().replace(':', '').replace('-', '')}.json"
        path = self.directory / filename
        payload = {
            "timestamp": timestamp.isoformat(),
            "summary": summary,
            "hosts": list(hosts),
            "plugins": plugin_output or {},
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.history.append({"timestamp": timestamp.isoformat(), "summary": summary, "filename": filename})
        self.history_path.write_text(json.dumps(self.history, indent=2), encoding="utf-8")
        return path

    def render_trend(self, limit: int = 5) -> str:
        if not self.history:
            return ""
        lines = ["=== Baseline Trend (most recent runs) ==="]
        for entry in sorted(self.history, key=lambda item: item.get("timestamp", ""), reverse=True)[:limit]:
            ts = entry.get("timestamp")
            summary = entry.get("summary", {})
            lines.append(
                f"- {ts}: hosts={summary.get('hosts', 0)}, open_ports={summary.get('open_ports', 0)}, "
                f"vulns={summary.get('vulnerabilities', 0)}"
            )
        return "\n".join(lines)

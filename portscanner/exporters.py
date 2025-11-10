"""
Pluggable exporters for scan results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable


class Exporter:
    name = "exporter"

    def __init__(self, options=None):
        self.options = options or {}

    def export(self, data: Dict) -> None:
        raise NotImplementedError


class StdoutExporter(Exporter):
    name = "stdout"

    def export(self, data: Dict) -> None:
        print("=== Exporter stdout ===")
        print(json.dumps(data, indent=2))


class JsonLinesExporter(Exporter):
    name = "jsonl"

    def export(self, data: Dict) -> None:
        path = self.options.get("path", "export.jsonl")
        Path(path).write_text(json.dumps(data) + "\n", encoding="utf-8")


BUILTIN_EXPORTERS = {
    StdoutExporter.name: StdoutExporter,
    JsonLinesExporter.name: JsonLinesExporter,
}


def load_exporters(names: Iterable[str], options: Dict[str, Dict]) -> Iterable[Exporter]:
    exporters = []
    for name in names:
        cls = BUILTIN_EXPORTERS.get(name)
        if not cls:
            print(f"[-] Unknown exporter '{name}'")
            continue
        exporters.append(cls(options.get(name, {})))
    return exporters

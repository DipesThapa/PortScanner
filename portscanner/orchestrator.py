"""
Distributed runner scaffolding for coordinating remote scan workers.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class WorkerNode:
    name: str
    address: str
    capabilities: Dict[str, str]


class DistributedRunner:
    def __init__(self, workers: List[WorkerNode]):
        self.workers = workers

    @classmethod
    def from_config(
        cls, path: str, *, base_dir: Optional[str] = None
    ) -> "DistributedRunner":
        # Guard against path traversal: when a base directory is supplied the
        # resolved config path must stay inside it. This prevents untrusted
        # input (e.g. an HTTP query parameter) from reading arbitrary files
        # such as /etc/passwd via ?config=../../etc/passwd.
        config_path = Path(path)
        if base_dir is not None:
            base = Path(base_dir).resolve()
            candidate = config_path if config_path.is_absolute() else base / config_path
            resolved = candidate.resolve()
            try:
                resolved.relative_to(base)
            except ValueError as exc:
                raise ValueError(
                    "Distributed runner config path escapes the permitted directory."
                ) from exc
            config_path = resolved

        data = json.loads(config_path.read_text(encoding="utf-8"))
        worker_entries = data.get("workers", []) if isinstance(data, dict) else data
        workers: List[WorkerNode] = []
        if not isinstance(worker_entries, list):
            raise ValueError("Distributed runner config must contain a list of workers.")
        for entry in worker_entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or entry.get("address") or "worker"
            address = entry.get("address")
            if not address:
                continue
            workers.append(WorkerNode(name=name, address=address, capabilities=entry.get("capabilities", {})))
        return cls(workers)

    def render_status(self) -> str:
        lines = ["=== Worker Nodes ==="]
        if not self.workers:
            lines.append("(no workers configured)")
            return "\n".join(lines)
        for worker in self.workers:
            reachable = self._check_reachability(worker.address)
            status = "reachable" if reachable else "offline"
            lines.append(f"- {worker.name} ({worker.address}) -> {status}")
        return "\n".join(lines)

    def get_statuses(self) -> List[Dict[str, object]]:
        results: List[Dict[str, object]] = []
        for worker in self.workers:
            reachable = self._check_reachability(worker.address)
            results.append(
                {
                    "name": worker.name,
                    "address": worker.address,
                    "reachable": reachable,
                    "capabilities": worker.capabilities or {},
                }
            )
        return results

    @staticmethod
    def _check_reachability(address: str) -> bool:
        host, _, port_str = address.partition(":")
        port = int(port_str or 22)
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            return False

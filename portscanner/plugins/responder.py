"""
Automated response plugin that builds follow-up tasks for high-risk findings.
"""

from __future__ import annotations

from typing import Dict, List

from .base import PluginContext, ScanPlugin

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class ResponderPlugin(ScanPlugin):
    name = "auto-responder"
    description = "Create remediation tasks for high severity or policy breaches."

    def initialize(self, context: PluginContext) -> None:
        super().initialize(context)
        self.tasks: List[Dict] = []
        self.threshold = SEVERITY_ORDER.get(self.get_option("min_severity", "high").lower(), 3)
        self.forbidden_ports = set(str(p) for p in self.get_option("forbidden_ports", []))

    def process_host(self, host: Dict) -> None:
        target = host.get("target")
        for vuln in host.get("vulnerabilities") or []:
            severity = (vuln.get("severity") or "").lower()
            sev_rank = SEVERITY_ORDER.get(severity, 0)
            if sev_rank >= self.threshold:
                task = self._build_vuln_task(target, vuln, severity)
                self.tasks.append(task)
                self.add_note(host, "auto-responder", f"Queued remediation task {task['task_id']}")

        for port in host.get("open_ports") or []:
            if self.forbidden_ports and str(port.get("port")) in self.forbidden_ports:
                task = self._build_port_task(target, port)
                self.tasks.append(task)
                self.add_note(host, "auto-responder", f"Flagged forbidden port {port.get('port')}")

    def _build_vuln_task(self, target: str, vuln: Dict, severity: str) -> Dict:
        task_id = f"remediate-{target}-{vuln.get('script_id')}"
        return {
            "task_id": task_id,
            "target": target,
            "type": "vulnerability",
            "severity": severity,
            "title": vuln.get("title"),
            "details": vuln,
        }

    def _build_port_task(self, target: str, port: Dict) -> Dict:
        task_id = f"close-port-{target}-{port.get('port')}"
        return {
            "task_id": task_id,
            "target": target,
            "type": "forbidden_port",
            "port": port,
            "message": "Port is marked forbidden by policy.",
        }

    def finalize(self) -> Dict[str, List[Dict]]:
        return {"tasks": self.tasks}

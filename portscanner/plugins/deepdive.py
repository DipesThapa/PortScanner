"""
Plugin that schedules protocol-specific deep dive checks.
"""

from __future__ import annotations

from typing import Dict, List

from .base import PluginContext, ScanPlugin

DEFAULT_DEEP_DIVES = {
    "https": ["testssl.sh --quiet --json"],
    "http": ["nuclei -target {target}:{port}"],
    "smb": ["nmap --script smb-enum-shares -p {port} {target}"],
}


class DeepDivePlugin(ScanPlugin):
    name = "deep-dive"
    description = "Suggest follow-up tooling for certain services."

    def initialize(self, context: PluginContext) -> None:
        super().initialize(context)
        self.tasks: List[Dict] = []
        self.command_map = dict(DEFAULT_DEEP_DIVES)
        custom_map = self.get_option("commands")
        if isinstance(custom_map, dict):
            for key, value in custom_map.items():
                if isinstance(value, list):
                    self.command_map[key.lower()] = value

    def process_host(self, host: Dict) -> None:
        target = host.get("target")
        cred_store = getattr(self.context, "credentials", None) if self.context else None
        for port in host.get("open_ports") or []:
            service = (port.get("service") or "").lower()
            commands = self.command_map.get(service)
            if not commands:
                continue
            credential_values = {}
            if cred_store is not None:
                try:
                    credential_values = cred_store.get_for_service(service)
                except AttributeError:
                    credential_values = {}
            expanded = [
                cmd.format(target=target, port=port.get("port"), **credential_values)
                for cmd in commands
            ]
            task = {
                "target": target,
                "service": service,
                "port": port.get("port"),
                "protocol": port.get("protocol"),
                "commands": expanded,
            }
            if credential_values:
                task["credentials"] = credential_values
            self.tasks.append(task)
            self.add_note(host, "deep-dive", f"Prepared {len(commands)} follow-up commands for {service}")

    def finalize(self) -> Dict[str, List[Dict]]:
        return {"tasks": self.tasks}

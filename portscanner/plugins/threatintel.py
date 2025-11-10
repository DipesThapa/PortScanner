"""
Plugin that enriches hosts with simple threat intelligence hints.
"""

from __future__ import annotations

from typing import Dict, List

from .base import PluginContext, ScanPlugin

SERVICE_ALERTS = {
    "rdp": {
        "campaigns": ["BlueKeep", "RDPLocker"],
        "recommendations": [
            "Ensure Network Level Authentication (NLA) is enabled.",
            "Restrict RDP exposure to VPN or bastion hosts.",
            "Review Microsoft advisories for CVE-2019-0708 (BlueKeep).",
        ],
    },
    "smb": {
        "campaigns": ["WannaCry", "NotPetya"],
        "recommendations": [
            "Disable SMBv1 where possible.",
            "Patch systems for MS17-010 and monitor for abnormal SMB traffic.",
        ],
    },
    "http": {
        "campaigns": ["ProxyShell", "CitrixBleed"],
        "recommendations": [
            "Check for outdated CMS/framework components.",
            "Enable WAF rules or rate limiting for internet-facing endpoints.",
        ],
    },
}


class ThreatIntelPlugin(ScanPlugin):
    name = "threat-intel"
    description = "Annotate services with distilled threat intel references."

    def initialize(self, context: PluginContext) -> None:
        super().initialize(context)
        self.matches: List[Dict] = []

    def process_host(self, host: Dict) -> None:
        open_ports = host.get("open_ports") or []
        for port in open_ports:
            service = (port.get("service") or "").lower()
            intel = SERVICE_ALERTS.get(service)
            if not intel:
                continue
            entry = {
                "target": host.get("target"),
                "service": service,
                "port": port.get("port"),
                "protocol": port.get("protocol"),
                "campaigns": intel["campaigns"],
                "recommendations": intel["recommendations"],
            }
            self.matches.append(entry)
            host.setdefault("threat_intel", [])
            host["threat_intel"].append(entry)
            self.add_note(
                host,
                "threat-intel",
                f"{service} service referenced in campaigns {', '.join(intel['campaigns'])}",
            )

    def finalize(self) -> Dict[str, List[Dict]]:
        return {"matches": self.matches}

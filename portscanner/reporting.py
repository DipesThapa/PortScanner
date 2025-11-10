"""
Helpers for rendering and saving scan results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from . import parser as parser_module


def _format_addresses(address_records: Sequence[Dict[str, str]]) -> str:
    parts = []
    for record in address_records:
        addr = record.get("address")
        addr_type = record.get("type")
        if addr:
            parts.append(f"{addr} ({addr_type})" if addr_type else addr)
    return ", ".join(parts)


def render_text_report(host_reports: Sequence[Dict], include_scripts: bool = True) -> str:
    """
    Build a human-readable report from parsed host data.
    """
    if not host_reports:
        return "[-] No host information found."

    total_hosts = len(host_reports)
    lines: List[str] = []
    for index, host in enumerate(host_reports, start=1):
        if total_hosts > 1:
            lines.append(f"=== Host {index} of {total_hosts} ===")

        state = host.get("state")
        reason = host.get("reason")
        if state:
            line = f"[*] Host State: {state}"
            if reason:
                line += f" (reason: {reason})"
            lines.append(line)

        addresses = _format_addresses(host.get("addresses", []))
        if addresses:
            lines.append(f"[*] Addresses: {addresses}")

        hostnames = host.get("hostnames") or []
        if hostnames:
            lines.append(f"[*] Hostnames: {', '.join(hostnames)}")

        asset = host.get("asset") or {}
        if asset:
            asset_name = asset.get("name") or asset.get("id")
            if asset_name:
                lines.append(f"[*] Asset: {asset_name}")
            meta = []
            for label, key in (("Owner", "owner"), ("Environment", "environment"), ("Criticality", "criticality")):
                value = asset.get(key)
                if value:
                    meta.append(f"{label}: {value}")
            if meta:
                lines.append(f"    {'; '.join(meta)}")
            tags = asset.get("tags") or []
            if tags:
                lines.append(f"[*] Asset Tags: {', '.join(tags)}")

        os_guess = host.get("os_guess")
        if os_guess:
            os_line = f"[*] OS Guess: {os_guess.get('name', 'unknown')}"
            accuracy = os_guess.get("accuracy")
            if accuracy:
                os_line += f" (Accuracy: {accuracy}%)"
            lines.append(os_line)

        open_ports = host.get("open_ports") or []
        if open_ports:
            lines.append("\n[+] Open Ports and Detected Services:")
            for port in open_ports:
                lines.append(
                    f"    - {port.get('protocol')}/{port.get('port')}: {port.get('service')}"
                )

        vulnerabilities = host.get("vulnerabilities") or []
        if vulnerabilities:
            lines.append("\n[!] Vulnerabilities detected:")
            for vuln in vulnerabilities:
                location = "Host"
                if vuln.get("scope") == "port":
                    location = f"Port {vuln.get('port')}/{vuln.get('protocol', 'tcp')}"
                summary = f"    - {location}: {vuln.get('title')} [{vuln.get('script_id')}]"
                qualifiers = []
                severity = vuln.get("severity")
                if severity:
                    qualifiers.append(f"Severity {severity}")
                cves = vuln.get("cves") or []
                if cves:
                    qualifiers.append(f"CVEs {', '.join(cves)}")
                if qualifiers:
                    summary += f" ({'; '.join(qualifiers)})"
                lines.append(summary)

        intel_services = (host.get("intel") or {}).get("services") or []
        if intel_services:
            lines.append("\n[~] Service Intelligence Findings:")
            for entry in intel_services:
                location = f"{entry.get('protocol')}/{entry.get('port')}"
                summary = entry.get("summary") or entry.get("service") or "service"
                risk = entry.get("risk")
                risk_text = f" [{risk.upper()}]" if risk else ""
                lines.append(f"    - {location}: {summary}{risk_text}")
                for obs in entry.get("observations", []) or entry.get("notes", []):
                    lines.append(f"      * {obs}")
                recs = entry.get("recommendations") or []
                if recs:
                    lines.append("      Recommended:")
                    for rec in recs:
                        lines.append(f"        - {rec}")

        if include_scripts:
            for script in host.get("scripts", {}).get("ports", []):
                descriptor = f"Port {script.get('port_id')}/{script.get('protocol')}"
                lines.append(f"\n[*] {descriptor} Script: {script.get('script_id')}")
                lines.extend(_render_script_details(script))

            for script in host.get("scripts", {}).get("host", []):
                lines.append(f"\n[*] Host Script: {script.get('script_id')}")
                lines.extend(_render_script_details(script))

        plugin_notes = host.get("plugin_notes") or {}
        for category, messages in plugin_notes.items():
            if not messages:
                continue
            lines.append(f"\n[+] Plugin {category} Notes:")
            for message in messages:
                lines.append(f"    - {message}")

        lines.append("")  # blank line between hosts

    return "\n".join(line for line in lines if line is not None)


def _render_script_details(script: Dict) -> List[str]:
    details: List[str] = []
    severity = script.get("severity")
    if severity:
        details.append(f"    Severity: {severity}")
    state = script.get("state")
    if state:
        details.append(f"    State: {state}")
    cves = script.get("cves") or []
    if cves:
        details.append(f"    CVEs: {', '.join(cves)}")
    lines = script.get("lines") or []
    if lines:
        details.append("    Details:")
        for line in lines:
            details.append(f"      - {line}")
    elif script.get("output"):
        details.append(f"    Output: {script['output']}")
    return details


def render_summary_text(summary: Dict[str, int]) -> str:
    lines = [
        "=== Scan Summary ===",
        f"Hosts analysed: {summary.get('hosts', 0)}",
        f"Open ports found: {summary.get('open_ports', 0)}",
        f"Vulnerabilities flagged: {summary.get('vulnerabilities', 0)}",
    ]
    host_states = summary.get("host_states", {})
    if host_states:
        lines.append("Host states:")
        for state, count in sorted(host_states.items()):
            lines.append(f"  - {state}: {count}")
    return "\n".join(lines)


def save_text_report(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def save_xml_output(path: str, xml_output: str) -> None:
    Path(path).write_text(xml_output, encoding="utf-8")


def save_vulnerability_report(path: str, host_reports: Sequence[Dict]) -> None:
    vulnerabilities = []
    for host in host_reports:
        host_addresses = host.get("addresses") or []
        hostnames = host.get("hostnames") or []
        host_state = host.get("state")
        host_reason = host.get("reason")
        os_guess = host.get("os_guess")
        asset = host.get("asset")

        for vuln in host.get("vulnerabilities") or []:
            entry = dict(vuln)
            entry.setdefault("host_addresses", host_addresses)
            entry.setdefault("hostnames", hostnames)
            entry.setdefault("host_state", host_state)
            entry.setdefault("host_reason", host_reason)
            entry.setdefault("os_guess", os_guess)
            if asset:
                entry.setdefault("asset", asset)
            vulnerabilities.append(entry)

    payload = {
        "hosts": host_reports,
        "vulnerabilities": vulnerabilities,
        "summary": parser_module.summarize_reports(host_reports),
    }

    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def save_json_report(path: str, data: Dict) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def render_plugin_summary(plugin_output: Dict[str, Dict]) -> str:
    if not plugin_output:
        return ""
    lines = ["=== Plugin Summary ==="]
    for name, payload in plugin_output.items():
        lines.append(f"* {name}")
        if not payload:
            lines.append("    (no data)")
            continue
        for key, value in payload.items():
            if isinstance(value, list):
                lines.append(f"    - {key}: {len(value)} item(s)")
            else:
                lines.append(f"    - {key}: {value}")
    return "\n".join(lines)

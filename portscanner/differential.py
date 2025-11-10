"""
Differential reporting between current scan results and a stored baseline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


class BaselineLoadError(RuntimeError):
    """Raised when a baseline file cannot be parsed."""


def load_baseline(path: str) -> Dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BaselineLoadError(f"Baseline file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineLoadError(f"Failed to parse baseline JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineLoadError("Baseline JSON must be an object.")
    return data


def _host_identity(host: Dict, default: str = "unknown") -> str:
    target = host.get("target")
    if target:
        return str(target)
    addresses = host.get("addresses") or []
    for record in addresses:
        addr = record.get("address")
        if addr:
            return str(addr)
    hostnames = host.get("hostnames") or []
    if hostnames:
        return str(hostnames[0])
    return default


def _collect_hosts_from_targets(target_map: Dict) -> List[Dict]:
    hosts: List[Dict] = []
    for target, host_list in target_map.items():
        if not isinstance(host_list, list):
            continue
        for host in host_list:
            if isinstance(host, dict):
                host.setdefault("target", target)
                hosts.append(host)
    return hosts


def load_baseline_hosts(path: str) -> List[Dict]:
    data = load_baseline(path)
    hosts: List[Dict] = []
    targets = data.get("targets")
    if isinstance(targets, dict):
        hosts.extend(_collect_hosts_from_targets(targets))
    elif isinstance(data.get("hosts"), list):
        hosts.extend([host for host in data["hosts"] if isinstance(host, dict)])
    else:
        # Allow raw host list stored directly at top-level for flexibility.
        hosts.extend([host for host in data.values() if isinstance(host, dict)])
    return hosts


def _port_key(host: Dict, port_entry: Dict) -> Tuple[str, str, str]:
    return (
        _host_identity(host),
        str(port_entry.get("protocol") or ""),
        str(port_entry.get("port") or ""),
    )


def _vuln_key(host: Dict, vuln_entry: Dict) -> Tuple[str, str, str, str]:
    scope = str(vuln_entry.get("scope") or "")
    if scope == "port":
        port_value = str(vuln_entry.get("port") or "")
    else:
        port_value = ""
    return (
        _host_identity(host),
        scope,
        str(vuln_entry.get("script_id") or ""),
        port_value,
    )


def _port_payload(host: Dict, port_entry: Dict) -> Dict:
    return {
        "target": _host_identity(host),
        "protocol": port_entry.get("protocol"),
        "port": port_entry.get("port"),
        "service": port_entry.get("service"),
    }


def _vuln_payload(host: Dict, vuln_entry: Dict) -> Dict:
    payload = {
        "target": _host_identity(host),
        "scope": vuln_entry.get("scope"),
        "script_id": vuln_entry.get("script_id"),
        "title": vuln_entry.get("title"),
        "severity": vuln_entry.get("severity"),
        "state": vuln_entry.get("state"),
        "cves": vuln_entry.get("cves"),
    }
    if vuln_entry.get("scope") == "port":
        payload["port"] = vuln_entry.get("port")
        payload["protocol"] = vuln_entry.get("protocol")
    return payload


def _collect_ports(hosts: Sequence[Dict]) -> Dict[Tuple[str, str, str], Dict]:
    result: Dict[Tuple[str, str, str], Dict] = {}
    for host in hosts:
        for port in host.get("open_ports") or []:
            key = _port_key(host, port)
            result[key] = _port_payload(host, port)
    return result


def _collect_vulns(hosts: Sequence[Dict]) -> Dict[Tuple[str, str, str, str], Dict]:
    result: Dict[Tuple[str, str, str, str], Dict] = {}
    for host in hosts:
        for vuln in host.get("vulnerabilities") or []:
            key = _vuln_key(host, vuln)
            result[key] = _vuln_payload(host, vuln)
    return result


def compute_diff(current_hosts: Sequence[Dict], baseline_hosts: Sequence[Dict]) -> Dict[str, Dict[str, List[Dict]]]:
    baseline_ports = _collect_ports(baseline_hosts)
    current_ports = _collect_ports(current_hosts)

    baseline_vulns = _collect_vulns(baseline_hosts)
    current_vulns = _collect_vulns(current_hosts)

    new_ports_keys = set(current_ports) - set(baseline_ports)
    closed_ports_keys = set(baseline_ports) - set(current_ports)

    new_vuln_keys = set(current_vulns) - set(baseline_vulns)
    resolved_vuln_keys = set(baseline_vulns) - set(current_vulns)

    return {
        "ports": {
            "new": [current_ports[key] for key in sorted(new_ports_keys)],
            "closed": [baseline_ports[key] for key in sorted(closed_ports_keys)],
        },
        "vulnerabilities": {
            "new": [current_vulns[key] for key in sorted(new_vuln_keys)],
            "resolved": [baseline_vulns[key] for key in sorted(resolved_vuln_keys)],
        },
    }


def format_diff_summary(diff: Dict[str, Dict[str, List[Dict]]]) -> str:
    ports = diff.get("ports", {})
    vulns = diff.get("vulnerabilities", {})
    lines = ["=== Differential Summary ==="]
    new_ports = len(ports.get("new", []))
    closed_ports = len(ports.get("closed", []))
    new_vulns = len(vulns.get("new", []))
    resolved_vulns = len(vulns.get("resolved", []))
    lines.append(f"New open ports: {new_ports}")
    lines.append(f"Closed ports: {closed_ports}")
    lines.append(f"New vulnerabilities: {new_vulns}")
    lines.append(f"Resolved vulnerabilities: {resolved_vulns}")
    return "\n".join(lines)

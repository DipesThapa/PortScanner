"""
Utilities for parsing Nmap XML output into structured Python objects.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Sequence

VULNERABLE_TOKEN = "VULNERABLE"
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NmapXMLParseError(ValueError):
    """Raised when Nmap XML output cannot be parsed."""


def _dedupe_preserve(sequence: Iterable[str]) -> List[str]:
    seen = set()
    items = []
    for item in sequence:
        if item not in seen:
            seen.add(item)
            items.append(item)
    return items


def _find_elem_value(script_el: ET.Element, keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        for elem in script_el.findall(f".//elem[@key='{key}']"):
            text = (elem.text or "").strip()
            if text:
                return text
    return None


def _collect_script_lines(script_el: ET.Element) -> List[str]:
    lines: List[str] = []
    output = script_el.get("output")
    if output:
        lines.extend(line.strip() for line in output.splitlines() if line.strip())

    for elem in script_el.findall(".//elem"):
        text = (elem.text or "").strip()
        key = elem.get("key")
        if not text:
            continue
        if key and key.lower() not in {"state"}:
            lines.append(f"{key}: {text}")
        else:
            lines.append(text)

    if not lines:
        lines.extend(line.strip() for line in script_el.itertext() if line.strip())

    return _dedupe_preserve(lines)


def _normalize_severity(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    lowered = value.lower()
    if lowered.startswith("risk factor:"):
        return value.split(":", 1)[1].strip().capitalize() or None
    if lowered in {"none", "unknown"}:
        return None
    return value


def _parse_script_output(script_el: ET.Element) -> Dict[str, Any]:
    script_id = script_el.get("id", "unknown")
    lines = _collect_script_lines(script_el)
    text_blob = "\n".join(lines)
    severity = _normalize_severity(_find_elem_value(script_el, {"risk_factor", "severity"}))
    state_value = _find_elem_value(script_el, {"state"})
    state = state_value.strip() if state_value else None
    cves = sorted({match.upper() for match in CVE_REGEX.findall(text_blob)})
    is_vulnerable = False
    if state and state.upper() == VULNERABLE_TOKEN:
        is_vulnerable = True
    elif VULNERABLE_TOKEN in text_blob.upper():
        is_vulnerable = True

    title = (
        _find_elem_value(script_el, {"title", "summary", "description", "id"})
        or (lines[0] if lines else script_id)
    )

    return {
        "script_id": script_id,
        "lines": lines,
        "output": script_el.get("output") or "",
        "severity": severity,
        "state": state,
        "cves": cves,
        "is_vuln": is_vulnerable,
        "title": title,
        "raw_text": text_blob,
    }


def _build_service_description(service_el: Optional[ET.Element]) -> str:
    if service_el is None:
        return "unknown"

    name = service_el.get("name") or "unknown"
    details = [
        detail
        for detail in (
            service_el.get("product"),
            service_el.get("version"),
            service_el.get("extrainfo"),
        )
        if detail
    ]
    if details:
        return f"{name} ({' '.join(details)})"
    return name


def _build_vulnerability_entry(addresses, hostnames, script_result) -> Dict[str, Any]:
    entry = {
        "host_addresses": addresses,
        "hostnames": hostnames,
        "scope": script_result.get("context"),
        "script_id": script_result.get("script_id"),
        "title": script_result.get("title") or script_result.get("script_id"),
        "severity": script_result.get("severity"),
        "state": script_result.get("state"),
        "cves": script_result.get("cves") or [],
        "details": script_result.get("lines") or [],
        "raw_text": script_result.get("raw_text") or "",
    }
    if entry["scope"] == "port":
        entry["port"] = script_result.get("port_id")
        entry["protocol"] = script_result.get("protocol")
    return entry


def _parse_host(host: ET.Element) -> Dict[str, Any]:
    status_el = host.find("status")
    state = status_el.get("state", "unknown") if status_el is not None else None
    reason = status_el.get("reason") if status_el is not None else None

    address_records = []
    for addr_el in host.findall("address"):
        addr = addr_el.get("addr")
        addr_type = addr_el.get("addrtype")
        if addr:
            address_records.append({"address": addr, "type": addr_type})

    host_names = []
    hostnames_el = host.find("hostnames")
    if hostnames_el is not None:
        host_names = [
            hn.get("name") for hn in hostnames_el.findall("hostname") if hn.get("name")
        ]

    os_info = None
    os_el = host.find("os")
    if os_el is not None:
        os_matches = os_el.findall("osmatch")
        if os_matches:
            best_match = os_matches[0]
            os_info = {
                "name": best_match.get("name", "unknown"),
                "accuracy": best_match.get("accuracy"),
            }

    host_record: Dict[str, Any] = {
        "state": state,
        "reason": reason,
        "addresses": address_records,
        "hostnames": host_names,
        "os_guess": os_info,
        "open_ports": [],
        "scripts": {"host": [], "ports": []},
        "vulnerabilities": [],
    }

    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            port_id = port_el.get("portid", "unknown")
            protocol = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            service_el = port_el.find("service")

            if state_el is not None and state_el.get("state") == "open":
                service_description = _build_service_description(service_el)
                host_record["open_ports"].append(
                    {"protocol": protocol, "port": port_id, "service": service_description}
                )

            for script_el in port_el.findall("script"):
                script_result = _parse_script_output(script_el)
                script_result.update({"context": "port", "port_id": port_id, "protocol": protocol})
                host_record["scripts"]["ports"].append(script_result)
                if script_result.get("is_vuln"):
                    host_record["vulnerabilities"].append(
                        _build_vulnerability_entry(address_records, host_names, script_result)
                    )

    for hostscript in host.findall("hostscript"):
        for script_el in hostscript.findall("script"):
            script_result = _parse_script_output(script_el)
            script_result.update({"context": "host"})
            host_record["scripts"]["host"].append(script_result)
            if script_result.get("is_vuln"):
                host_record["vulnerabilities"].append(
                    _build_vulnerability_entry(address_records, host_names, script_result)
                )

    return host_record


def parse_nmap_xml(xml_output: str) -> List[Dict[str, Any]]:
    """
    Parse Nmap XML output into structured dictionaries.

    Returns a list of host reports. Raises NmapXMLParseError if parsing fails.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise NmapXMLParseError("Failed to parse Nmap XML output.") from exc

    hosts = root.findall("host")
    return [_parse_host(host_element) for host_element in hosts]


def summarize_reports(host_reports: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute high-level statistics from parsed host reports.
    """
    total_hosts = len(host_reports)
    open_ports = sum(len(host.get("open_ports", [])) for host in host_reports)
    vulnerabilities = sum(len(host.get("vulnerabilities", [])) for host in host_reports)
    host_states = {}
    for host in host_reports:
        state = (host.get("state") or "unknown").lower()
        host_states[state] = host_states.get(state, 0) + 1

    return {
        "hosts": total_hosts,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
        "host_states": host_states,
    }

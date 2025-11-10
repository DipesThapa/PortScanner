"""Service intelligence enrichment for scan results."""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, Iterable, List, Sequence

DEFAULT_INTEL_SCRIPTS = ["banner", "http-title", "ssl-cert", "ssh-hostkey", "http-headers"]

SERVICE_FAMILY_HINTS = {
    "http": {
        "recommendations": [
            "Enforce HTTPS and redirect clear-text traffic to TLS-protected endpoints.",
            "Review security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
        ],
        "references": [
            "https://owasp.org/www-project-top-ten/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
    },
    "https": {
        "recommendations": [
            "Renew certificates before expiry and disable deprecated protocols (TLS 1.0/1.1).",
            "Review cipher suites to ensure forward secrecy and strong algorithms are enforced.",
        ],
        "references": [
            "https://ssl-config.mozilla.org/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        ],
    },
    "ssh": {
        "recommendations": [
            "Disable legacy key exchange and ciphers; prefer ed25519 or rsa-sha2 host keys.",
            "Enforce multi-factor authentication and fail2ban-style brute-force protections.",
        ],
        "references": [
            "https://infosec.mozilla.org/guidelines/openssh",
        ],
    },
    "smtp": {
        "recommendations": [
            "Enable STARTTLS with strong ciphers and require authentication for outbound relay.",
            "Implement DMARC, SPF, and DKIM to prevent spoofing.",
        ],
        "references": [
            "https://dmarc.org/overview/",
        ],
    },
    "rdp": {
        "recommendations": [
            "Require Network Level Authentication (NLA) and limit exposure via VPN/ZTNA.",
            "Patch RDP servers promptly and monitor for brute-force attempts.",
        ],
        "references": [
            "https://www.cisa.gov/sites/default/files/publications/CISA-Fact-Sheet-Securing-RDP.pdf",
        ],
    },
    "ftp": {
        "recommendations": [
            "Disable anonymous authentication unless explicitly required and write access is isolated.",
            "Migrate to SFTP/FTPS or another secure transfer protocol when possible.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/FTP_bounce_attack",
        ],
    },
    "mysql": {
        "recommendations": [
            "Bind the service to internal interfaces and enforce TLS for remote access.",
            "Use least-privilege database accounts and rotate credentials regularly.",
        ],
        "references": [
            "https://dev.mysql.com/doc/refman/en/security-guidelines.html",
        ],
    },
    "postgresql": {
        "recommendations": [
            "Restrict pg_hba.conf to trusted networks and require SCRAM authentication.",
            "Enable TLS with strong certificates for any remote connections.",
        ],
        "references": [
            "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
        ],
    },
    "mongodb": {
        "recommendations": [
            "Disable unauthenticated access and enable TLS with client certificate validation.",
            "Limit bind_ip to internal addresses and enable access control/authorization roles.",
        ],
        "references": [
            "https://www.mongodb.com/docs/manual/administration/security-checklist/",
        ],
    },
}

RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _normalize_service_name(name: str) -> str:
    return (name or "").lower()


def _resolve_family(service: str) -> str:
    normalized = _normalize_service_name(service)
    if "https" in normalized or normalized.endswith("ssl") or normalized.startswith("tls"):
        return "https"
    if "http" in normalized:
        return "http"
    if "ssh" in normalized:
        return "ssh"
    if "smtp" in normalized or "mail" in normalized:
        return "smtp"
    if "rdp" in normalized or "ms-wbt" in normalized:
        return "rdp"
    if "ftp" in normalized:
        return "ftp"
    if "mysql" in normalized:
        return "mysql"
    if "postgres" in normalized or "pgsql" in normalized:
        return "postgresql"
    if "mongo" in normalized:
        return "mongodb"
    return normalized


def _extract_banner(port: Dict) -> str:
    for key in ("banner", "product", "service_extrainfo", "version"):
        value = port.get(key)
        if value:
            return str(value)
    return ""


def _extract_script_output(port: Dict, script_id: str) -> str | None:
    scripts = port.get("scripts")
    if isinstance(scripts, list):
        for entry in scripts:
            if entry.get("id") == script_id:
                return entry.get("output")
    elif isinstance(scripts, dict):
        payload = scripts.get(script_id)
        if isinstance(payload, dict):
            return payload.get("output") or payload.get("text")
        if isinstance(payload, str):
            return payload
    return None


def _http_headers_map(headers_output: str | None) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not headers_output:
        return headers
    for line in headers_output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key:
            headers[key] = value.strip()
    return headers


def _build_finding(
    port: Dict,
    service: str,
    summary: str,
    risk: str,
    observations: Iterable[str],
    recommendations: Iterable[str],
    references: Iterable[str],
) -> Dict:
    finding = {
        "port": port.get("port"),
        "protocol": port.get("protocol"),
        "service": service,
        "summary": summary,
        "risk": risk,
        "observations": [obs for obs in observations if obs],
        "recommendations": [rec for rec in recommendations if rec],
        "references": sorted({ref for ref in references if ref}),
    }
    banner = _extract_banner(port)
    if banner:
        finding["banner"] = banner
    evidence = {}
    title = _extract_script_output(port, "http-title")
    if title:
        evidence["http_title"] = title.strip()
    cert = _extract_script_output(port, "ssl-cert")
    if cert:
        evidence["ssl_cert"] = cert.strip()
    if evidence:
        finding["evidence"] = evidence
    return finding


def _analyze_http(port: Dict, service: str) -> Dict:
    banner = _extract_banner(port)
    headers = _http_headers_map(_extract_script_output(port, "http-headers"))
    title = _extract_script_output(port, "http-title")

    observations = [
        f"HTTP service responded with banner: {banner}" if banner else "HTTP service responded to probes.",
    ]
    if title:
        observations.append(f"Discovered page title: {title.strip()[:120]}")

    missing_headers = []
    for header in ("strict-transport-security", "content-security-policy", "x-frame-options"):
        if header not in headers:
            missing_headers.append(header)
    recommendations = []
    if missing_headers:
        recommendations.append(
            "Consider setting security headers: " + ", ".join(sorted(missing_headers)).replace("-", " ")
        )

    if port.get("port") in {80, 8080} and "https" not in service:
        recommendations.append("Redirect clients to HTTPS and disable clear-text authentication paths.")

    refs = SERVICE_FAMILY_HINTS.get("http", {}).get("references", [])
    recs = SERVICE_FAMILY_HINTS.get("http", {}).get("recommendations", [])
    return _build_finding(
        port,
        service,
        summary="HTTP service exposed",
        risk="medium",
        observations=observations,
        recommendations=recommendations + recs,
        references=refs,
    )


def _analyze_https(port: Dict, service: str) -> Dict:
    banner = _extract_banner(port)
    cert_info = _extract_script_output(port, "ssl-cert")
    observations = [
        f"HTTPS/TLS service responded with banner: {banner}" if banner else "HTTPS/TLS service detected.",
    ]
    if cert_info:
        expiry_match = re.search(r"Not valid after:\s*(.+)", cert_info)
        if expiry_match:
            observations.append(f"Certificate expiry: {expiry_match.group(1).strip()}")
        issuer_match = re.search(r"Issuer:\s*(.+)", cert_info)
        if issuer_match:
            observations.append(f"Certificate issuer: {issuer_match.group(1).strip()[:80]}")

    recommendations = [
        "Disable deprecated protocols (SSLv3/TLS 1.0/1.1) and weak ciphers.",
    ]
    refs = SERVICE_FAMILY_HINTS.get("https", {}).get("references", [])
    recs = SERVICE_FAMILY_HINTS.get("https", {}).get("recommendations", [])
    return _build_finding(
        port,
        service,
        summary="HTTPS service available",
        risk="medium",
        observations=observations,
        recommendations=recommendations + recs,
        references=refs,
    )


def _analyze_ssh(port: Dict, service: str) -> Dict:
    banner = _extract_banner(port)
    observations = [
        f"SSH banner: {banner}" if banner else "SSH service detected.",
    ]
    kex_output = _extract_script_output(port, "ssh2-enum-algos")
    if kex_output:
        observations.append("Key exchange algorithms enumerated (review for legacy entries).")
    refs = SERVICE_FAMILY_HINTS.get("ssh", {}).get("references", [])
    recs = SERVICE_FAMILY_HINTS.get("ssh", {}).get("recommendations", [])
    return _build_finding(
        port,
        service,
        summary="SSH remote administration exposed",
        risk="medium",
        observations=observations,
        recommendations=recs,
        references=refs,
    )


def _analyze_smtp(port: Dict, service: str) -> Dict:
    banner = _extract_banner(port)
    observations = [
        f"SMTP banner: {banner}" if banner else "SMTP service detected.",
    ]
    starttls = _extract_script_output(port, "smtp-starttls")
    if starttls and "supported" in starttls.lower():
        observations.append("STARTTLS support advertised.")
    elif starttls:
        observations.append("STARTTLS not offered; traffic may be clear-text.")
    refs = SERVICE_FAMILY_HINTS.get("smtp", {}).get("references", [])
    recs = SERVICE_FAMILY_HINTS.get("smtp", {}).get("recommendations", [])
    return _build_finding(
        port,
        service,
        summary="Mail transfer agent exposed",
        risk="medium",
        observations=observations,
        recommendations=recs,
        references=refs,
    )


def _analyze_rdp(port: Dict, service: str) -> Dict:
    observations = ["Remote Desktop Protocol service reachable."]
    security = _extract_script_output(port, "rdp-enum-encryption")
    if security:
        observations.append("Encryption capabilities enumerated (review for RC4/128-bit legacy modes).")
    refs = SERVICE_FAMILY_HINTS.get("rdp", {}).get("references", [])
    recs = SERVICE_FAMILY_HINTS.get("rdp", {}).get("recommendations", [])
    return _build_finding(
        port,
        service,
        summary="RDP service exposed",
        risk="high",
        observations=observations,
        recommendations=recs,
        references=refs,
    )


def _generic_finding(port: Dict, service: str) -> Dict:
    hints = SERVICE_FAMILY_HINTS.get(service, {})
    observations = [
        f"Service '{service}' detected on port {port.get('port')} with banner: {_extract_banner(port)}".strip()
    ]
    recommendations = hints.get("recommendations", [])
    references = hints.get("references", [])
    return _build_finding(
        port,
        service,
        summary=f"{service.upper()} service detected",
        risk="medium",
        observations=observations,
        recommendations=recommendations,
        references=references,
    )


SERVICE_ANALYZERS = {
    "http": _analyze_http,
    "https": _analyze_https,
    "ssh": _analyze_ssh,
    "smtp": _analyze_smtp,
    "rdp": _analyze_rdp,
    "ftp": _generic_finding,
    "mysql": _generic_finding,
    "postgresql": _generic_finding,
    "mongodb": _generic_finding,
}


def analyze_host(host: Dict) -> List[Dict]:
    findings: List[Dict] = []
    target = host.get("target") or host.get("addresses", [{}])[0].get("address")
    for port in host.get("open_ports") or []:
        raw_service = port.get("service") or "unknown"
        family = _resolve_family(raw_service)
        analyzer = SERVICE_ANALYZERS.get(family)
        if analyzer is None and family in SERVICE_FAMILY_HINTS:
            analyzer = SERVICE_ANALYZERS.get(family, _generic_finding)
        if analyzer is None:
            continue
        finding = analyzer(port, family)
        finding["raw_service"] = raw_service
        if target:
            finding["target"] = target
        findings.append(finding)
    return findings


def enrich_hosts(host_reports: Sequence[Dict]) -> None:
    for host in host_reports:
        findings = analyze_host(host)
        if findings:
            host.setdefault("intel", {})
            host["intel"]["services"] = findings


def summarize(host_reports: Sequence[Dict]) -> Dict:
    if not host_reports:
        return {}

    all_findings: List[Dict] = []
    for host in host_reports:
        intel = (host.get("intel") or {}).get("services")
        if intel is None:
            findings = analyze_host(host)
            if findings:
                host.setdefault("intel", {})
                host["intel"]["services"] = findings
                all_findings.extend(findings)
        else:
            all_findings.extend(intel)

    if not all_findings:
        return {}

    risk_counter = Counter()
    targets: Dict[str, int] = {}
    for finding in all_findings:
        risk = finding.get("risk") or "unknown"
        risk_counter[risk] += 1
        target = finding.get("target") or "unknown"
        targets[target] = targets.get(target, 0) + 1

    metrics = {
        "total_findings": len(all_findings),
        "by_risk": dict(risk_counter),
        "affected_targets": len(targets),
    }

    sorted_findings = sorted(
        all_findings,
        key=lambda item: (RISK_ORDER.get(item.get("risk", ""), 0), item.get("target"), item.get("port")),
        reverse=True,
    )

    return {
        "metrics": metrics,
        "targets": targets,
        "findings": sorted_findings,
    }


def append_summary(plugin_output: Dict | None, host_reports: Sequence[Dict]) -> Dict:
    summary = summarize(host_reports)
    if not summary:
        return plugin_output or {}
    output = dict(plugin_output or {})
    output["service-intel"] = summary
    return output


__all__ = [
    "DEFAULT_INTEL_SCRIPTS",
    "enrich_hosts",
    "summarize",
    "append_summary",
]

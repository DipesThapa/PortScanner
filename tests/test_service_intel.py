from __future__ import annotations

from portscanner import service_intel


def _http_host():
    return {
        "target": "web.example.com",
        "open_ports": [
            {
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "product": "nginx 1.24",
                "scripts": {
                    "http-title": {"output": "Example Domain"},
                    "http-headers": {"output": "Server: nginx\nContent-Type: text/html"},
                },
            }
        ],
    }


def test_analyze_host_produces_rich_finding():
    host = _http_host()
    findings = service_intel.analyze_host(host)
    assert findings, "Expected HTTP analyzer to produce a finding"
    finding = findings[0]
    assert finding["summary"] == "HTTP service exposed"
    assert finding["risk"] == "medium"
    assert any("Example Domain" in obs for obs in finding.get("observations", []))
    assert "banner" in finding


def test_enrich_hosts_attaches_findings():
    hosts = [_http_host()]
    service_intel.enrich_hosts(hosts)
    intel = hosts[0].get("intel", {}).get("services")
    assert intel and intel[0]["summary"] == "HTTP service exposed"


def test_summarize_returns_metrics():
    hosts = [_http_host()]
    service_intel.enrich_hosts(hosts)
    summary = service_intel.summarize(hosts)
    assert summary["metrics"]["total_findings"] == 1
    assert summary["metrics"]["affected_targets"] == 1
    assert summary["findings"][0]["target"] == "web.example.com"


def test_append_summary_injects_into_plugin_output():
    hosts = [_http_host()]
    service_intel.enrich_hosts(hosts)
    output = service_intel.append_summary({"other": {}}, hosts)
    assert "service-intel" in output
    assert output["service-intel"]["metrics"]["total_findings"] == 1

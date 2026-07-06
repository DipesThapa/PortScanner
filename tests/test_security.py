"""Security regression tests: auth, input validation, injection, XXE, redaction.

These lock in the hardening applied to the web tier and scan engine.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from webapp import security
from webapp.main import app
from webapp.jobs import JobManager
from webapp.models import ScanRequest
from portscanner.parser import parse_nmap_xml, NmapXMLParseError
from portscanner.scanner import build_nmap_command


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


KEY = {"X-API-Key": security.API_KEY}


# --- T1: authentication -----------------------------------------------------

def test_api_requires_key(client):
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/scans", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/scans", headers=KEY).status_code == 200


def test_health_is_open(client):
    assert client.get("/api/health").status_code == 200


def test_delete_missing_job_returns_404(client):
    assert client.delete(f"/api/scans/{uuid.uuid4()}", headers=KEY).status_code == 404


# --- T2: input validation / argument injection ------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        {"target": "--script=/tmp/evil.nse"},
        {"target": "scanme.nmap.org; rm -rf /"},
        {"targets": ["ok.com", "bad -pn"]},
        {"target": "scanme.nmap.org", "extra_args": ["-oN", "/etc/cron.d/x"]},
        {"target": "scanme.nmap.org", "scripts": ["../../evil"]},
        {"target": "scanme.nmap.org", "ports": "80;rm"},
        {"target": "scanme.nmap.org", "start_port": 99999},
    ],
)
def test_malicious_scan_requests_rejected(payload):
    with pytest.raises(ValidationError):
        ScanRequest(**payload)


def test_clean_scan_request_accepted():
    req = ScanRequest(target="scanme.nmap.org", ports="1-1024,8080", scripts=["vuln"])
    assert req.target == "scanme.nmap.org"


def test_nmap_command_uses_double_dash_sentinel():
    cmd = build_nmap_command("scanme.nmap.org", 1, 100)
    assert cmd[-2] == "--" and cmd[-1] == "scanme.nmap.org"


# --- XXE: XML parsing safety ------------------------------------------------

def test_valid_nmap_xml_parses():
    hosts = parse_nmap_xml("<nmaprun><host><address addr='1.1.1.1'/></host></nmaprun>")
    assert len(hosts) == 1


def test_xxe_payload_is_blocked():
    xxe = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        "<nmaprun>&x;</nmaprun>"
    )
    with pytest.raises(NmapXMLParseError):
        parse_nmap_xml(xxe)


# --- T5: secret redaction ---------------------------------------------------

@pytest.mark.parametrize(
    "raw,leak",
    [
        ("password=hunter2", "hunter2"),
        ("token: abc123", "abc123"),
        ("Authorization: Bearer eyJsecret", "eyJsecret"),
        ("secret://db/creds", "db/creds"),
        ("api_key = sk-live-123", "sk-live-123"),
    ],
)
def test_logs_redacted(raw, leak):
    assert leak not in JobManager._redact_logs(raw)


def test_normal_log_lines_preserved():
    line = "port 443 open on scanme.nmap.org"
    assert JobManager._redact_logs(line) == line

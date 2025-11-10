from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import create_engine

from webapp import database, main
from webapp.jobs import JobManager
from webapp.models import ScanRequest, ScanResult
from webapp.deepdive import DeepDiveExecutor


@pytest.fixture()
def test_client(tmp_path: Path):
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    database.engine = engine
    database.init_db()

    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    job_manager = JobManager(base_dir=runs_dir)
    deep_dive_executor = DeepDiveExecutor(runs_dir, allowlist=["echo"])

    main.job_manager = job_manager
    main.deep_dive_executor = deep_dive_executor

    client = TestClient(main.app)
    try:
        yield client, job_manager, deep_dive_executor
    finally:
        client.close()


def _seed_scan(job_manager: JobManager) -> uuid.UUID:
    job_id = uuid.uuid4()
    request = ScanRequest(target="127.0.0.1")
    scan = ScanResult(
        job_id=job_id,
        status="completed",
        logs="",
        summary=None,
        diff=None,
        plugins={
            "deep-dive": {
                "tasks": [
                    {
                        "target": "127.0.0.1",
                        "service": "custom",
                        "port": 443,
                        "protocol": "tcp",
                        "commands": ["echo hello", "curl https://example.com"],
                    }
                ]
            }
        },
        trend=None,
        artifacts={},
        vulnerabilities=[],
        request=request,
    )
    job_manager.jobs[job_id] = scan
    return job_id


def test_allowlist_endpoint(test_client):
    client, _, _ = test_client
    response = client.get("/deepdive/allowlist/info")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enforced"] is True
    assert "echo" in payload["entries"]


def test_run_deep_dive_allowed_command(test_client):
    client, job_manager, _ = test_client
    job_id = _seed_scan(job_manager)

    response = client.post(f"/scans/{job_id}/deepdive", json={"commands": ["echo hello"]})
    assert response.status_code == 200
    tasks = response.json()
    assert len(tasks) == 1
    assert tasks[0]["command"] == "echo hello"

    list_response = client.get(f"/scans/{job_id}/deepdive")
    assert list_response.status_code == 200
    listed = list_response.json()
    assert len(listed) == 1
    assert listed[0]["command"] == "echo hello"
    assert listed[0]["status"] in {"pending", "running", "completed"}


def test_run_deep_dive_rejects_non_allowlisted_command(test_client):
    client, job_manager, _ = test_client
    job_id = _seed_scan(job_manager)

    response = client.post(f"/scans/{job_id}/deepdive", json={"commands": ["curl https://example.com"]})
    assert response.status_code == 403
    assert "allowlist" in response.json()["detail"]


def test_run_deep_dive_rejects_unknown_command(test_client):
    client, job_manager, _ = test_client
    job_id = _seed_scan(job_manager)

    response = client.post(f"/scans/{job_id}/deepdive", json={"commands": ["echo other"]})
    assert response.status_code == 400
    assert "Unsupported command" in response.json()["detail"]

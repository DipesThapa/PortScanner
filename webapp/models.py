from __future__ import annotations

import uuid
from pathlib import Path
from typing import Dict, List, Optional

import json
from datetime import datetime
from pydantic import BaseModel, Field
from sqlmodel import Field as SQLField, SQLModel


class ScanRequest(BaseModel):
    target: Optional[str] = None
    targets: Optional[List[str]] = None
    target_file: Optional[str] = None
    ports: Optional[str] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    scripts: Optional[List[str]] = None
    intel: bool = False
    intel_scripts: Optional[List[str]] = None
    aggressive: bool = True
    timing: Optional[int] = None
    extra_args: Optional[List[str]] = None
    concurrency: Optional[int] = None
    asset_file: Optional[str] = None
    baseline_json: Optional[str] = None
    diff_report: Optional[str] = None
    plugins: Optional[List[str]] = None
    plugin_config: Optional[str] = None
    plugin_options: Optional[Dict[str, Dict]] = None
    exporters: Optional[List[str]] = None
    exporter_config: Optional[str] = None
    exporter_options: Optional[Dict[str, Dict]] = None
    credential_file: Optional[str] = None
    secret_file: Optional[str] = None
    secret_prefix: Optional[str] = None
    baseline_store: Optional[str] = None
    orchestrator_config: Optional[str] = None
    api_listen: Optional[str] = None
    job_name: Optional[str] = None


class ScanResponse(BaseModel):
    job_id: uuid.UUID
    status: str


class ScanResult(BaseModel):
    job_id: uuid.UUID
    status: str
    message: Optional[str] = None
    logs: str = ""
    summary: Optional[Dict] = None
    diff: Optional[Dict] = None
    plugins: Optional[Dict] = None
    trend: Optional[str] = None
    artifacts: Dict[str, str] = Field(default_factory=dict)
    vulnerabilities: List[Dict] = Field(default_factory=list)
    request: ScanRequest


class ScanRecord(SQLModel, table=True):
    job_id: str = SQLField(primary_key=True, index=True)
    status: str
    request_json: str
    summary_json: Optional[str] = None
    diff_json: Optional[str] = None
    plugins_json: Optional[str] = None
    trend: Optional[str] = None
    logs: Optional[str] = None
    vulnerabilities_json: Optional[str] = None


class ScheduledJob(SQLModel, table=True):
    id: str = SQLField(primary_key=True, index=True)
    name: str
    request_json: str
    created_at: datetime = SQLField(default_factory=datetime.utcnow)


class ScheduleCreate(BaseModel):
    name: str
    request: ScanRequest


class ScheduleResponse(BaseModel):
    id: str
    name: str
    created_at: datetime
    request: ScanRequest

    @classmethod
    def from_record(cls, record: ScheduledJob) -> "ScheduleResponse":
        return cls(
            id=record.id,
            name=record.name,
            created_at=record.created_at,
            request=ScanRequest.model_validate_json(record.request_json),
        )


class WorkerStatusRecord(SQLModel, table=True):
    id: str = SQLField(primary_key=True, index=True)
    name: str
    address: str
    reachable: bool
    last_checked: datetime = SQLField(default_factory=datetime.utcnow)
    capabilities_json: Optional[str] = None


class WorkerStatus(BaseModel):
    name: str
    address: str
    reachable: bool
    last_checked: datetime
    capabilities: Dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_record(cls, record: WorkerStatusRecord) -> "WorkerStatus":
        return cls(
            name=record.name,
            address=record.address,
            reachable=record.reachable,
            last_checked=record.last_checked,
            capabilities=json.loads(record.capabilities_json) if record.capabilities_json else {},
        )


class DeepDiveTaskRecord(SQLModel, table=True):
    id: str = SQLField(primary_key=True, index=True)
    job_id: str = SQLField(index=True)
    command: str
    status: str
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    return_code: Optional[int] = None
    created_at: datetime = SQLField(default_factory=datetime.utcnow)
    updated_at: datetime = SQLField(default_factory=datetime.utcnow)


class DeepDiveTask(BaseModel):
    id: str
    job_id: str
    command: str
    status: str
    return_code: Optional[int]
    created_at: datetime
    updated_at: datetime
    stdout: Optional[str] = None
    stderr: Optional[str] = None

    @classmethod
    def from_record(cls, record: DeepDiveTaskRecord, include_output: bool = False) -> "DeepDiveTask":
        stdout = None
        stderr = None
        if include_output:
            if record.stdout_path and Path(record.stdout_path).exists():
                stdout = Path(record.stdout_path).read_text(encoding="utf-8", errors="replace")
            if record.stderr_path and Path(record.stderr_path).exists():
                stderr = Path(record.stderr_path).read_text(encoding="utf-8", errors="replace")
        return cls(
            id=record.id,
            job_id=record.job_id,
            command=record.command,
            status=record.status,
            return_code=record.return_code,
            created_at=record.created_at,
            updated_at=record.updated_at,
            stdout=stdout,
            stderr=stderr,
        )


class DeepDiveRequest(BaseModel):
    commands: Optional[List[str]] = None


def job_directory(base: Path, job_id: uuid.UUID) -> Path:
    return base / str(job_id)

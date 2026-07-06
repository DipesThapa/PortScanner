from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import json
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from sqlmodel import Field as SQLField, SQLModel

# A scan target must be a hostname, IPv4/IPv6 address, or CIDR range. This
# deliberately excludes whitespace, shell metacharacters, and a leading '-'
# (which nmap would otherwise interpret as a flag → argument injection).
_TARGET_RE = re.compile(r"^(?!-)[A-Za-z0-9._:/-]{1,255}$")
_PORTS_RE = re.compile(r"^[0-9,\-]{1,128}$")

# Nmap flags that let an attacker read/write arbitrary files or execute code.
# Refused inside extra_args, scripts, and target values.
_DANGEROUS_ARG_PREFIXES = (
    "--script",       # arbitrary NSE / Lua execution
    "--datadir",      # load NSE from an attacker-controlled directory
    "--servicedb",
    "--stylesheet",
    "-oN", "-oG", "-oS", "-oA", "-oX",  # write files to arbitrary paths
    "--resume",
    "--iflist",
)


def _validate_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Target must not be empty.")
    if value.startswith("-"):
        raise ValueError(f"Invalid target (looks like a flag): {value!r}")
    if not _TARGET_RE.match(value):
        raise ValueError(f"Invalid target: {value!r}")
    return value


def _reject_dangerous_arg(value: str) -> str:
    stripped = value.strip()
    lowered = stripped.lower()
    for prefix in _DANGEROUS_ARG_PREFIXES:
        if lowered == prefix.lower() or lowered.startswith(prefix.lower() + "="):
            raise ValueError(f"Disallowed nmap argument: {value!r}")
    return value


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

    @field_validator("target")
    @classmethod
    def _check_target(cls, v: Optional[str]) -> Optional[str]:
        return _validate_target(v) if v is not None else v

    @field_validator("targets")
    @classmethod
    def _check_targets(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        return [_validate_target(t) for t in v] if v else v

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not _PORTS_RE.match(v):
            raise ValueError(f"Invalid ports specification: {v!r}")
        return v

    @field_validator("start_port", "end_port")
    @classmethod
    def _check_port_number(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 65535):
            raise ValueError("Port must be between 0 and 65535.")
        return v

    @field_validator("timing")
    @classmethod
    def _check_timing(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 5):
            raise ValueError("Nmap timing template must be between 0 and 5.")
        return v

    @field_validator("concurrency")
    @classmethod
    def _check_concurrency(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (1 <= v <= 64):
            raise ValueError("Concurrency must be between 1 and 64.")
        return v

    @field_validator("extra_args")
    @classmethod
    def _check_extra_args(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        return [_reject_dangerous_arg(a) for a in v] if v else v

    @field_validator("scripts", "intel_scripts")
    @classmethod
    def _check_scripts(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if not v:
            return v
        for name in v:
            # NSE script names/categories only — no paths, flags, or metacharacters.
            if not re.match(r"^[A-Za-z0-9._+-]{1,64}$", name.strip()):
                raise ValueError(f"Invalid script name: {name!r}")
        return v

    @classmethod
    def from_stored(cls, raw_json: str) -> "ScanRequest":
        """Load a previously persisted request WITHOUT re-running input validators.

        Validation exists to gate *inbound* requests. Records already written to
        the database were validated (or predate validation) and must still load,
        so we reconstruct them without validation.
        """
        try:
            return cls.model_validate_json(raw_json)
        except Exception:
            return cls.model_construct(**json.loads(raw_json))


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
            request=ScanRequest.from_stored(record.request_json),
        )


class WorkerNodeRecord(SQLModel, table=True):
    id: str = SQLField(primary_key=True, index=True)
    name: str
    address: str
    reachable: bool = False
    last_checked: datetime = SQLField(default_factory=datetime.utcnow)
    capabilities_json: Optional[str] = None


class WorkerStatus(BaseModel):
    name: str
    address: str
    reachable: bool
    last_checked: datetime
    capabilities: Dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_record(cls, record: WorkerNodeRecord) -> "WorkerStatus":
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

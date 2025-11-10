from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from portscanner.orchestrator import DistributedRunner
from .jobs import JobManager
from .models import (
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScheduleCreate,
    ScheduleResponse,
    ScheduledJob,
    WorkerStatus,
    WorkerStatusRecord,
    DeepDiveTask,
    DeepDiveTaskRecord,
    DeepDiveRequest,
)
from .deepdive import DeepDiveExecutor
from .database import lifespan, get_session


app = FastAPI(title="Port Scanner Orchestrator", version="1.0.0", lifespan=lifespan)
job_manager = JobManager(base_dir=Path("web_runs"))
deep_dive_executor = DeepDiveExecutor(Path("web_runs"))
default_orchestrator_config = os.getenv("ORCHESTRATOR_CONFIG")
WS_REFRESH_SECONDS = 5


def _available_deep_dive_commands(scan: ScanResult) -> list[str]:
    commands: list[str] = []
    plugin_data = scan.plugins or {}
    deep_section = plugin_data.get("deep-dive") if isinstance(plugin_data, dict) else None
    if isinstance(deep_section, dict):
        for task in deep_section.get("tasks", []) or []:
            for command in task.get("commands", []) or []:
                commands.append(command)
    return commands


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scans", response_model=ScanResponse)
def create_scan(request: ScanRequest, background: BackgroundTasks) -> ScanResponse:
    job = job_manager.submit_job(request, background)
    return ScanResponse(job_id=job.job_id, status=job.status)


@app.get("/scans", response_model=list[ScanResult])
def list_scans() -> list[ScanResult]:
    return job_manager.list_jobs()


@app.get("/scans/{job_id}", response_model=ScanResult)
def get_scan(job_id: uuid.UUID) -> ScanResult:
    job = job_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/scans/{job_id}/artifacts/{path:path}")
def download_artifact(job_id: uuid.UUID, path: str):
    job = job_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    artifact = job.artifacts.get(path)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(Path(artifact))


@app.get("/scans/{job_id}/deepdive", response_model=list[DeepDiveTask])
def list_deep_dive(job_id: uuid.UUID) -> list[DeepDiveTask]:
    return deep_dive_executor.list_tasks(job_id)


@app.post("/scans/{job_id}/deepdive", response_model=list[DeepDiveTask])
async def run_deep_dive(job_id: uuid.UUID, payload: DeepDiveRequest) -> list[DeepDiveTask]:
    job = job_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    available_cmds = _available_deep_dive_commands(job)
    if not available_cmds:
        raise HTTPException(status_code=400, detail="No deep-dive commands available for this job")
    commands = payload.commands or available_cmds
    invalid = [cmd for cmd in commands if cmd not in available_cmds]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unsupported command(s): {', '.join(invalid)}")
    try:
        tasks = await deep_dive_executor.enqueue(job_id, commands)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return tasks


@app.get("/deepdive/{task_id}", response_model=DeepDiveTask)
def get_deep_dive_task(task_id: uuid.UUID, include_output: bool = False) -> DeepDiveTask:
    task = deep_dive_executor.get_task(task_id, include_output=include_output)
    if task is None:
        raise HTTPException(status_code=404, detail="Deep-dive task not found")
    return task


@app.get("/deepdive/allowlist/info")
def get_deep_dive_allowlist() -> dict:
    return deep_dive_executor.allowlist_info()


@app.get("/schedules", response_model=list[ScheduleResponse])
def list_schedules() -> list[ScheduleResponse]:
    with get_session() as session:
        records = session.query(ScheduledJob).order_by(ScheduledJob.created_at.desc()).all()
        return [ScheduleResponse.from_record(record) for record in records]


@app.post("/schedules", response_model=ScheduleResponse)
def create_schedule(payload: ScheduleCreate) -> ScheduleResponse:
    schedule_id = str(uuid.uuid4())
    record = ScheduledJob(
        id=schedule_id,
        name=payload.name,
        request_json=payload.request.model_dump_json(),
    )
    with get_session() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return ScheduleResponse.from_record(record)


@app.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: str) -> None:
    with get_session() as session:
        record = session.get(ScheduledJob, schedule_id)
        if not record:
            raise HTTPException(status_code=404, detail="Schedule not found")
        session.delete(record)
        session.commit()


@app.post("/schedules/{schedule_id}/run", response_model=ScanResponse)
def run_schedule(schedule_id: str, background: BackgroundTasks) -> ScanResponse:
    with get_session() as session:
        record = session.get(ScheduledJob, schedule_id)
        if not record:
            raise HTTPException(status_code=404, detail="Schedule not found")
        request = ScheduleResponse.from_record(record).request
    job = job_manager.submit_job(request, background)
    return ScanResponse(job_id=job.job_id, status=job.status)


@app.get("/workers", response_model=list[WorkerStatus])
def worker_status(config: str | None = None) -> list[WorkerStatus]:
    config_path = config or default_orchestrator_config
    if not config_path:
        return []
    try:
        runner = DistributedRunner.from_config(config_path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to load orchestrator config: {exc}")

    statuses = runner.get_statuses()
    now = datetime.utcnow()
    persisted: list[WorkerStatus] = []
    with get_session() as session:
        for status in statuses:
            record = session.get(WorkerStatusRecord, status["address"])
            if record is None:
                record = WorkerStatusRecord(
                    id=status["address"],
                    name=status["name"],
                    address=status["address"],
                    reachable=status["reachable"],
                    last_checked=now,
                    capabilities_json=json.dumps(status["capabilities"]),
                )
            else:
                record.name = status["name"]
                record.reachable = status["reachable"]
                record.last_checked = now
                record.capabilities_json = json.dumps(status["capabilities"])
            session.add(record)
            persisted.append(WorkerStatus.from_record(record))
        session.commit()
    return persisted


@app.websocket("/ws/status")
async def websocket_status(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            jobs = job_manager.list_jobs()
            payload = {
                "timestamp": datetime.utcnow().isoformat(),
                "jobs": [scan.model_dump() for scan in jobs],
            }
            workers = await _safe_get_workers()
            if workers is not None:
                payload["workers"] = [worker.model_dump() for worker in workers]
            deep_dive_tasks = []
            for scan in jobs:
                deep_dive_tasks.extend(deep_dive_executor.list_tasks(scan.job_id))
            if deep_dive_tasks:
                payload["deep_dive"] = [task.model_dump() for task in deep_dive_tasks]
            await websocket.send_json(payload)
            await asyncio.sleep(WS_REFRESH_SECONDS)
    except WebSocketDisconnect:
        return
    except Exception as exc:  # pragma: no cover
        await websocket.send_json({"error": str(exc)})
    finally:
        await websocket.close()


async def _safe_get_workers() -> list[WorkerStatus] | None:
    try:
        return worker_status(None)
    except HTTPException:
        return None

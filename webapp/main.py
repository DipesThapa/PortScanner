from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .security import require_api_key, websocket_key_ok
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
    ScheduleResponse,
    ScheduledJob,
    WorkerStatus,
    WorkerNodeRecord,
    DeepDiveTask,
    DeepDiveTaskRecord,
    DeepDiveRequest,
)
from .deepdive import DeepDiveExecutor
from .database import lifespan, get_session


app = FastAPI(title="Port Scanner Orchestrator", version="1.0.0", lifespan=lifespan)
# Every route on this router requires a valid X-API-Key header.
api_router = APIRouter(dependencies=[Depends(require_api_key)])
# Script upload is a code-execution surface; disabled unless explicitly enabled.
SCRIPT_UPLOAD_ENABLED = os.getenv("PORTSCANNER_ENABLE_SCRIPT_UPLOAD", "").lower() in {"1", "true", "yes"}
job_manager = JobManager(base_dir=Path("web_runs"))
deep_dive_executor = DeepDiveExecutor(Path("web_runs"))
default_orchestrator_config = os.getenv("ORCHESTRATOR_CONFIG")
WS_REFRESH_SECONDS = 5
FRONTEND_DIST = Path(__file__).parent / "frontend" / "dist"


def _available_deep_dive_commands(scan: ScanResult) -> list[str]:
    commands: list[str] = []
    plugin_data = scan.plugins or {}
    deep_section = plugin_data.get("deep-dive") if isinstance(plugin_data, dict) else None
    if isinstance(deep_section, dict):
        for task in deep_section.get("tasks", []) or []:
            for command in task.get("commands", []) or []:
                commands.append(command)
    return commands


@app.get("/api/health")
def health() -> dict:
    # Unauthenticated: used by container/orchestrator health checks.
    return {"status": "ok"}


@api_router.post("/scans", response_model=ScanResponse)
def create_scan(request: ScanRequest, background: BackgroundTasks) -> ScanResponse:
    job = job_manager.submit_job(request, background)
    return ScanResponse(job_id=job.job_id, status=job.status)


@api_router.get("/scans", response_model=list[ScanResult])
def list_scans() -> list[ScanResult]:
    return job_manager.list_jobs()


@api_router.get("/scans/{job_id}", response_model=ScanResult)
def get_scan(job_id: uuid.UUID) -> ScanResult:
    job = job_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@api_router.delete("/scans/{job_id}", status_code=204)
def delete_scan(job_id: uuid.UUID):
    if not job_manager.delete_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return



@api_router.get("/scans/{job_id}/artifacts/{path:path}")
def download_artifact(job_id: uuid.UUID, path: str):
    job = job_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    artifact = job.artifacts.get(path)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(Path(artifact))


@api_router.get("/scans/{job_id}/deepdive", response_model=list[DeepDiveTask])
def list_deep_dive(job_id: uuid.UUID) -> list[DeepDiveTask]:
    return deep_dive_executor.list_tasks(job_id)


@api_router.post("/scans/{job_id}/deepdive", response_model=list[DeepDiveTask])
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


@api_router.get("/deepdive/{task_id}", response_model=DeepDiveTask)
def get_deep_dive_task(task_id: uuid.UUID, include_output: bool = False) -> DeepDiveTask:
    task = deep_dive_executor.get_task(task_id, include_output=include_output)
    if task is None:
        raise HTTPException(status_code=404, detail="Deep-dive task not found")
    return task


@api_router.get("/deepdive/allowlist/info")
def get_deep_dive_allowlist() -> dict:
    # Refresh allowlist to include any new scripts
    deep_dive_executor.reload_allowlist()
    return deep_dive_executor.allowlist_info()


class ScriptUpload(BaseModel):
    name: str
    content: str


@api_router.post("/plugins/scripts")
async def upload_script(payload: ScriptUpload) -> dict:
    if not SCRIPT_UPLOAD_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Script upload is disabled. Set PORTSCANNER_ENABLE_SCRIPT_UPLOAD=1 to enable it.",
        )
    try:
        path = await deep_dive_executor.save_script(payload.name, payload.content)
        deep_dive_executor.reload_allowlist()
        return {
            "path": path,
            "message": (
                "Script uploaded. It is NOT executable until an operator adds it to "
                "DEEP_DIVE_ALLOWLIST or DEEP_DIVE_ALLOWLIST_FILE."
            ),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@api_router.get("/plugins/scripts")
def list_scripts() -> list[str]:
    scripts_dir = deep_dive_executor.base_dir / "scripts"
    if not scripts_dir.exists():
        return []
    return [str(p.name) for p in scripts_dir.glob("*") if p.is_file()]


@api_router.get("/schedules", response_model=list[ScheduleResponse])
def list_schedules() -> list[ScheduleResponse]:
    with get_session() as session:
        records = session.query(ScheduledJob).order_by(ScheduledJob.created_at.desc()).all()
        return [ScheduleResponse.from_record(record) for record in records]


@api_router.post("/schedules", response_model=ScheduleResponse)
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


@api_router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: str) -> None:
    with get_session() as session:
        record = session.get(ScheduledJob, schedule_id)
        if not record:
            raise HTTPException(status_code=404, detail="Schedule not found")
        session.delete(record)
        session.commit()


@api_router.post("/schedules/{schedule_id}/run", response_model=ScanResponse)
def run_schedule(schedule_id: str, background: BackgroundTasks) -> ScanResponse:
    with get_session() as session:
        record = session.get(ScheduledJob, schedule_id)
        if not record:
            raise HTTPException(status_code=404, detail="Schedule not found")
        request = ScheduleResponse.from_record(record).request
    job = job_manager.submit_job(request, background)
    return ScanResponse(job_id=job.job_id, status=job.status)


@api_router.get("/workers", response_model=list[WorkerStatus])
def worker_status(config: str | None = None) -> list[WorkerStatus]:
    # 1. Load workers from config file (if any)
    config_path = config or default_orchestrator_config
    file_workers: list[Any] = []
    if config_path:
        try:
            runner = DistributedRunner.from_config(config_path)
            file_workers = runner.workers
        except Exception:
            pass  # Fallback to DB only if config fails or missing

    # 2. Reconcile with DB
    # We want to check reachability for ALL known workers (file stored + DB stored).
    # We will persist them all to DB so we have a unified view.
    
    # Map by address to deduplicate
    worker_map = {w.address: w for w in file_workers}
    
    with get_session() as session:
        # Load existing DB workers
        db_records = session.query(WorkerNodeRecord).all()
        for record in db_records:
            if record.address not in worker_map:
                # Add DB-only worker to the map for checking
                from portscanner.orchestrator import WorkerNode
                worker_map[record.address] = WorkerNode(
                    name=record.name,
                    address=record.address,
                    capabilities=json.loads(record.capabilities_json) if record.capabilities_json else {}
                )

        # 3. Check statuses for everyone
        all_workers = list(worker_map.values())
        if not all_workers:
            return []
            
        runner = DistributedRunner(all_workers)
        statuses = runner.get_statuses()
        
        # 4. Update DB
        now = datetime.utcnow()
        persisted: list[WorkerStatus] = []
        
        for status in statuses:
            record = session.get(WorkerNodeRecord, status["address"])
            if record is None:
                record = WorkerNodeRecord(
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


class WorkerCreate(BaseModel):
    name: str
    address: str
    capabilities: Dict[str, str] = {}


@api_router.post("/workers", response_model=WorkerStatus)
def create_worker(payload: WorkerCreate) -> WorkerStatus:
    with get_session() as session:
        existing = session.get(WorkerNodeRecord, payload.address)
        if existing:
             raise HTTPException(status_code=409, detail="Worker with this address already exists")
        
        record = WorkerNodeRecord(
            id=payload.address,
            name=payload.name,
            address=payload.address,
            reachable=False, # Will be updated on next check
            capabilities_json=json.dumps(payload.capabilities)
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return WorkerStatus.from_record(record)


@api_router.delete("/workers/{address}", status_code=204)
def delete_worker(address: str):
    with get_session() as session:
        record = session.get(WorkerNodeRecord, address)
        if not record:
            raise HTTPException(status_code=404, detail="Worker not found")
        session.delete(record)
        session.commit()

app.include_router(api_router, prefix="/api")

@app.websocket("/ws/status")
async def websocket_status(websocket: WebSocket):
    token = websocket.query_params.get("token")
    header_key = websocket.headers.get("x-api-key")
    if not websocket_key_ok(token, header_key):
        await websocket.close(code=1008)  # Policy Violation
        return
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


if FRONTEND_DIST.exists():
    # Serve the built React app from dist/ when available.
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/", response_class=HTMLResponse)
    def serve_frontend_root() -> HTMLResponse:
        index_path = FRONTEND_DIST / "index.html"
        if not index_path.exists():
            raise HTTPException(status_code=404, detail="Frontend build not found")
        return HTMLResponse(index_path.read_text(encoding="utf-8"))

    @app.get("/{full_path:path}", response_class=HTMLResponse)
    def serve_frontend_spa(full_path: str) -> HTMLResponse:
        # SPA fallback: always return index so the client router can handle paths.
        index_path = FRONTEND_DIST / "index.html"
        if not index_path.exists():
            raise HTTPException(status_code=404, detail="Frontend build not found")
        return HTMLResponse(index_path.read_text(encoding="utf-8"))

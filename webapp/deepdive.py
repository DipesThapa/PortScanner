from __future__ import annotations

import asyncio
import json
import os
import shlex
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

from .models import DeepDiveTaskRecord, DeepDiveTask, job_directory
from .database import get_session

DEFAULT_ALLOWLIST: Set[str] = {"testssl.sh", "nmap", "nuclei"}


class DeepDiveExecutor:
    def __init__(
        self,
        base_dir: Path,
        allowlist: Optional[Sequence[str]] = None,
    ) -> None:
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.allowlist = self._load_allowlist(allowlist)

    def _task_dir(self, job_id: uuid.UUID, task_id: uuid.UUID) -> Path:
        task_dir = job_directory(self.base_dir, job_id) / "deepdive" / str(task_id)
        task_dir.mkdir(parents=True, exist_ok=True)
        return task_dir

    async def enqueue(self, job_id: uuid.UUID, commands: Iterable[str]) -> List[DeepDiveTask]:
        tasks: List[DeepDiveTask] = []
        for command in commands:
            if not self._is_allowed(command):
                raise PermissionError(
                    f"Command '{command}' is not allowlisted. Update the deep-dive allowlist to run it."
                )
            task_id = uuid.uuid4()
            task_dir = self._task_dir(job_id, task_id)
            stdout_path = task_dir / "stdout.log"
            stderr_path = task_dir / "stderr.log"
            with get_session() as session:
                record = DeepDiveTaskRecord(
                    id=str(task_id),
                    job_id=str(job_id),
                    command=command,
                    status="pending",
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                )
                session.add(record)
                session.commit()
            asyncio.create_task(self._run_task(job_id, task_id, command, stdout_path, stderr_path))
            tasks.append(DeepDiveTask.from_record(record))
        return tasks

    async def _run_task(
        self,
        job_id: uuid.UUID,
        task_id: uuid.UUID,
        command: str,
        stdout_path: Path,
        stderr_path: Path,
    ) -> None:
        self._update_record(task_id, status="running")
        try:
            def run_cmd():
                with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open(
                    "w", encoding="utf-8"
                ) as stderr_file:
                    argv = self._split_command(command)
                    return subprocess.run(
                        argv,
                        shell=False,
                        cwd=stdout_path.parent,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        check=False,
                        text=True,
                    )

            process = await asyncio.to_thread(run_cmd)
            self._update_record(task_id, status="completed", return_code=process.returncode)
        except Exception:  # pragma: no cover - defensive
            self._update_record(task_id, status="failed", return_code=-1)

    def _update_record(self, task_id: uuid.UUID, **kwargs) -> None:
        with get_session() as session:
            record = session.get(DeepDiveTaskRecord, str(task_id))
            if not record:
                return
            for key, value in kwargs.items():
                setattr(record, key, value)
            record.updated_at = datetime.utcnow()
            session.add(record)
            session.commit()

    def list_tasks(self, job_id: uuid.UUID) -> List[DeepDiveTask]:
        with get_session() as session:
            records = (
                session.query(DeepDiveTaskRecord)
                .filter(DeepDiveTaskRecord.job_id == str(job_id))
                .order_by(DeepDiveTaskRecord.created_at.desc())
                .all()
            )
            return [DeepDiveTask.from_record(record) for record in records]

    def get_task(self, task_id: uuid.UUID, include_output: bool = False) -> DeepDiveTask | None:
        with get_session() as session:
            record = session.get(DeepDiveTaskRecord, str(task_id))
            if not record:
                return None
            return DeepDiveTask.from_record(record, include_output=include_output)

    def allowlist_info(self) -> dict:
        enforced = self.allowlist is not None
        entries = sorted(self.allowlist) if self.allowlist else []
        return {"entries": entries, "enforced": enforced}

    def _load_allowlist(self, initial: Optional[Sequence[str]]) -> Optional[Set[str]]:
        allowed: Set[str] = set(DEFAULT_ALLOWLIST)
        if initial:
            allowed.update(cmd.strip() for cmd in initial if cmd and cmd.strip())
        env_value = os.getenv("DEEP_DIVE_ALLOWLIST")
        if env_value:
            allowed.update(self._parse_allowlist_source(env_value))
        file_env = os.getenv("DEEP_DIVE_ALLOWLIST_FILE")
        if file_env:
            allowed.update(self._parse_allowlist_file(Path(file_env)))

        if "*" in allowed:
            return None
        return allowed

    def _parse_allowlist_source(self, source: str) -> Set[str]:
        path = Path(source)
        if path.exists():
            return self._parse_allowlist_file(path)
        return {item.strip() for item in source.split(",") if item.strip()}

    def _parse_allowlist_file(self, path: Path) -> Set[str]:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return set()
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return {str(item).strip() for item in data if str(item).strip()}
            if isinstance(data, dict):
                return {str(item).strip() for item in data.get("commands", []) if str(item).strip()}
        except json.JSONDecodeError:
            pass
        return {line.strip() for line in content.splitlines() if line.strip()}

    def _command_key(self, command: str) -> str:
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        return tokens[0] if tokens else ""

    def _split_command(self, command: str) -> List[str]:
        tokens = shlex.split(command)
        if not tokens:
            raise ValueError("Command is empty after parsing")
        return tokens

    def _is_allowed(self, command: str) -> bool:
        if self.allowlist is None:
            return True
        key = self._command_key(command)
        return key in self.allowlist

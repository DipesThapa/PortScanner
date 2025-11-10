"""
Simple job scheduler scaffolding for queued scans.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class ScanJob:
    name: str
    args: List[str]


class JobScheduler:
    def __init__(self, jobs: List[ScanJob]):
        self.jobs = jobs

    @classmethod
    def from_file(cls, path: str) -> "JobScheduler":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        jobs: List[ScanJob] = []
        job_entries = data.get("jobs") if isinstance(data, dict) else data
        if not isinstance(job_entries, list):
            raise ValueError("Job file must contain a list of jobs.")
        for entry in job_entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or "job"
            args = entry.get("args") or []
            if isinstance(args, str):
                args = args.split()
            if not isinstance(args, list):
                continue
            jobs.append(ScanJob(name=name, args=[str(arg) for arg in args]))
        return cls(jobs)

    def render_plan(self) -> str:
        lines = ["=== Scheduled Jobs ==="]
        for index, job in enumerate(self.jobs, start=1):
            lines.append(f"{index}. {job.name} -> {' '.join(job.args)}")
        if len(lines) == 1:
            lines.append("(no jobs defined)")
        return "\n".join(lines)

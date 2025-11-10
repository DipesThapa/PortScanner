from __future__ import annotations

import asyncio
import io
import json
import shutil
import traceback
import uuid
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import BackgroundTasks

from portscanner import cli
from portscanner.baselines import BaselineStore
from .database import get_session
from .models import ScanRecord, ScanRequest, ScanResult, job_directory


class JobManager:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.jobs: Dict[uuid.UUID, ScanResult] = {}

    def list_jobs(self) -> List[ScanResult]:
        records: List[ScanResult] = []
        with get_session() as session:
            for record in session.query(ScanRecord).all():
                job_uuid = uuid.UUID(record.job_id)
                if job_uuid in self.jobs:
                    records.append(self.jobs[job_uuid])
                    continue
                req = ScanRequest.model_validate_json(record.request_json)
                result = ScanResult(
                    job_id=job_uuid,
                    status=record.status,
                    logs=record.logs or "",
                    summary=json.loads(record.summary_json) if record.summary_json else None,
                    diff=json.loads(record.diff_json) if record.diff_json else None,
                    plugins=json.loads(record.plugins_json) if record.plugins_json else None,
                    trend=record.trend,
                    artifacts=self._collect_artifacts(job_directory(self.base_dir, job_uuid)),
                    vulnerabilities=json.loads(record.vulnerabilities_json) if record.vulnerabilities_json else [],
                    request=req,
                )
                records.append(result)
        return records

    def get_job(self, job_id: uuid.UUID) -> Optional[ScanResult]:
        if job_id in self.jobs:
            return self.jobs[job_id]
        with get_session() as session:
            record = session.get(ScanRecord, str(job_id))
            if not record:
                return None
            req = ScanRequest.model_validate_json(record.request_json)
            return ScanResult(
                job_id=job_id,
                status=record.status,
                logs=record.logs or "",
                summary=json.loads(record.summary_json) if record.summary_json else None,
                diff=json.loads(record.diff_json) if record.diff_json else None,
                plugins=json.loads(record.plugins_json) if record.plugins_json else None,
                trend=record.trend,
                artifacts=self._collect_artifacts(job_directory(self.base_dir, job_id)),
                vulnerabilities=json.loads(record.vulnerabilities_json) if record.vulnerabilities_json else [],
                request=req,
            )

    def submit_job(self, req: ScanRequest, background: BackgroundTasks) -> ScanResult:
        job_id = uuid.uuid4()
        job_dir = job_directory(self.base_dir, job_id)
        if job_dir.exists():
            shutil.rmtree(job_dir)
        job_dir.mkdir(parents=True, exist_ok=True)

        result = ScanResult(
            job_id=job_id,
            status="pending",
            logs="",
            vulnerabilities=[],
            request=req,
        )
        self.jobs[job_id] = result
        with get_session() as session:
            record = ScanRecord(
                job_id=str(job_id),
                status="pending",
                request_json=req.model_dump_json(),
            )
            session.add(record)
            session.commit()
        background.add_task(self._run_job, job_id, req, job_dir)
        return result

    def _build_cli_args(self, req: ScanRequest, job_dir: Path) -> List[str]:
        args: List[str] = ["--batch"]
        temp_output_dir = job_dir / "artifacts"
        temp_output_dir.mkdir(parents=True, exist_ok=True)

        result_json = job_dir / "result.json"
        report_txt = job_dir / "report.txt"
        vulns_json = job_dir / "vulns.json"
        xml_dir = temp_output_dir / "xml"

        args.extend(["--output-json", str(result_json)])
        args.extend(["--save-report", str(report_txt)])
        args.extend(["--save-vulns", str(vulns_json)])
        args.extend(["--save-xml", str(xml_dir)])
        args.extend(["--output-dir", str(temp_output_dir)])

        if req.target:
            args.extend(["--target", req.target])
        if req.targets:
            args.append("--targets")
            args.extend(req.targets)
        if req.target_file:
            args.extend(["--target-file", req.target_file])
        if req.ports:
            args.extend(["--ports", req.ports])
        if req.start_port is not None:
            args.extend(["--start-port", str(req.start_port)])
        if req.end_port is not None:
            args.extend(["--end-port", str(req.end_port)])
        if req.scripts:
            args.append("--scripts")
            args.extend(req.scripts)
        if req.intel:
            args.append("--intel")
        if req.intel_scripts:
            args.append("--intel-scripts")
            args.extend(req.intel_scripts)
        if not req.aggressive:
            args.append("--no-aggressive")
        if req.timing is not None:
            args.extend(["--timing", str(req.timing)])
        if req.extra_args:
            for extra in req.extra_args:
                args.extend(["--extra-arg", extra])
        if req.concurrency is not None:
            args.extend(["--concurrency", str(req.concurrency)])
        if req.asset_file:
            args.extend(["--asset-file", req.asset_file])
        if req.baseline_json:
            args.extend(["--baseline-json", req.baseline_json])
        if req.diff_report:
            args.extend(["--diff-report", req.diff_report])
        if req.plugins:
            args.append("--plugins")
            args.extend(req.plugins)
        if req.plugin_config:
            args.extend(["--plugin-config", req.plugin_config])
        if req.plugin_options:
            plugin_options_path = job_dir / "plugin_options.json"
            plugin_options_path.write_text(json.dumps(req.plugin_options, indent=2), encoding="utf-8")
            args.extend(["--plugin-config", str(plugin_options_path)])
        if req.exporters:
            args.append("--exporters")
            args.extend(req.exporters)
        if req.exporter_config:
            args.extend(["--exporter-config", req.exporter_config])
        if req.exporter_options:
            exporter_options_path = job_dir / "exporter_options.json"
            exporter_options_path.write_text(json.dumps(req.exporter_options, indent=2), encoding="utf-8")
            args.extend(["--exporter-config", str(exporter_options_path)])
        if req.credential_file:
            args.extend(["--credential-file", req.credential_file])
        if req.secret_file:
            args.extend(["--secret-file", req.secret_file])
        if req.secret_prefix:
            args.extend(["--secret-prefix", req.secret_prefix])
        baseline_store_dir = req.baseline_store or str(job_dir / "baseline")
        args.extend(["--baseline-store", baseline_store_dir])
        if req.orchestrator_config:
            args.extend(["--orchestrator-config", req.orchestrator_config])
        if req.api_listen:
            # In web mode we already expose an API; avoid launching nested servers.
            pass
        if req.job_name:
            # purely informational, not used by CLI
            pass

        return args

    def _collect_artifacts(self, job_dir: Path) -> Dict[str, str]:
        artifacts: Dict[str, str] = {}
        for path in job_dir.rglob("*"):
            if path.is_file():
                rel = path.relative_to(job_dir)
                artifacts[str(rel)] = str(path)
        return artifacts

    def _extract_vulnerabilities(self, data: Dict, plugins: Optional[Dict]) -> List[Dict]:
        vulnerabilities: List[Dict] = []
        targets = data.get("targets") or {}
        if isinstance(targets, dict):
            for target, host_list in targets.items():
                if not isinstance(host_list, list):
                    continue
                for host in host_list:
                    for vuln in host.get("vulnerabilities") or []:
                        entry = dict(vuln)
                        entry.setdefault("target", target)
                        entry.setdefault("source", "nmap")
                        vulnerabilities.append(entry)

        plugin_data = plugins or {}
        auto_section = plugin_data.get("auto-responder") if isinstance(plugin_data, dict) else None
        if isinstance(auto_section, dict):
            for task in auto_section.get("tasks", []) or []:
                entry = {
                    "target": task.get("target"),
                    "title": task.get("title") or task.get("type"),
                    "severity": task.get("severity"),
                    "details": task,
                    "source": "auto-responder",
                }
                vulnerability_port = task.get("port") or task.get("port_id")
                if vulnerability_port:
                    entry["port"] = str(vulnerability_port)
                vulnerabilities.append(entry)

        threat_section = plugin_data.get("threat-intel") if isinstance(plugin_data, dict) else None
        if isinstance(threat_section, dict):
            for match in threat_section.get("matches", []) or []:
                entry = {
                    "target": match.get("target"),
                    "title": ", ".join(match.get("campaigns", [])) or f"{match.get('service')} exposure",
                    "details": match,
                    "source": "threat-intel",
                }
                service = match.get("service")
                if service:
                    entry["service"] = service
                vulnerabilities.append(entry)

        return vulnerabilities

    async def _run_job(self, job_id: uuid.UUID, req: ScanRequest, job_dir: Path):
        result = self.jobs[job_id]
        result.status = "running"
        cli_args = self._build_cli_args(req, job_dir)
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        try:
            def run_cli():
                with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                    try:
                        cli.main(cli_args)
                    except SystemExit as exc:
                        if exc.code not in (0, None):
                            raise RuntimeError(f"CLI exited with code {exc.code}")

            await asyncio.to_thread(run_cli)
            result.status = "completed"
        except Exception as exc:  # pragma: no cover - defensive
            result.status = "failed"
            trace = traceback.format_exc()
            result.message = f"{exc}"
            stderr_buffer.write("\n" + trace)
        finally:
            result.logs = stdout_buffer.getvalue() + "\n" + stderr_buffer.getvalue()

        result.artifacts = self._collect_artifacts(job_dir)

        result_json = job_dir / "result.json"
        if result_json.exists():
            try:
                data = json.loads(result_json.read_text(encoding="utf-8"))
                result.summary = data.get("summary")
                result.diff = data.get("diff")
                result.plugins = data.get("plugins")
                result.vulnerabilities = self._extract_vulnerabilities(data, result.plugins)
            except json.JSONDecodeError:
                pass

        baseline_dir = job_dir / "baseline"
        if baseline_dir.exists():
            try:
                store = BaselineStore(str(baseline_dir))
                result.trend = store.render_trend()
            except Exception:  # pragma: no cover - defensive
                pass

        self.jobs[job_id] = result
        with get_session() as session:
            record = session.get(ScanRecord, str(job_id))
            if record:
                record.status = result.status
                record.summary_json = json.dumps(result.summary) if result.summary else None
                record.diff_json = json.dumps(result.diff) if result.diff else None
                record.plugins_json = json.dumps(result.plugins) if result.plugins else None
                record.vulnerabilities_json = (
                    json.dumps(result.vulnerabilities) if result.vulnerabilities else None
                )
                record.trend = result.trend
                record.logs = result.logs
                session.add(record)
                session.commit()

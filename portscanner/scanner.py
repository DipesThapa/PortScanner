"""
Wrappers around Nmap execution, including concurrent scanning.
"""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

DEFAULT_SCRIPTS = ["vuln"]


class NmapNotFoundError(RuntimeError):
    """Raised when the nmap binary is not available."""


class NmapExecutionError(RuntimeError):
    """Raised when Nmap returns a non-zero exit code."""


@dataclass
class ScanResult:
    target: str
    command: Sequence[str]
    success: bool
    xml_output: str = ""
    error: str = ""
    returncode: int = 0

    def ensure_success(self) -> "ScanResult":
        if not self.success:
            raise NmapExecutionError(
                f"Nmap scan for {self.target} failed with code {self.returncode}: {self.error}"
            )
        return self


def build_nmap_command(
    target: str,
    start_port: int,
    end_port: int,
    scripts: Optional[Sequence[str]] = None,
    aggressive: bool = True,
    timing_template: Optional[int] = None,
    extra_nmap_args: Optional[Sequence[str]] = None,
) -> List[str]:
    port_range = f"{start_port}-{end_port}"
    command = ["nmap", "--reason", "-p", port_range, "-oX", "-"]

    if aggressive:
        command.append("-A")

    if scripts:
        command.extend(["--script", ",".join(scripts)])

    if timing_template is not None:
        command.append(f"-T{timing_template}")

    if extra_nmap_args:
        command.extend(extra_nmap_args)

    command.append(target)
    return command


def run_nmap(
    target: str,
    start_port: int,
    end_port: int,
    scripts: Optional[Sequence[str]] = None,
    aggressive: bool = True,
    timing_template: Optional[int] = None,
    extra_nmap_args: Optional[Sequence[str]] = None,
) -> ScanResult:
    scripts = scripts if scripts is not None else DEFAULT_SCRIPTS
    command = build_nmap_command(
        target,
        start_port,
        end_port,
        scripts=scripts,
        aggressive=aggressive,
        timing_template=timing_template,
        extra_nmap_args=extra_nmap_args,
    )

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise NmapNotFoundError("Nmap not found. Please install nmap and try again.") from exc

    success = result.returncode == 0 or (result.stdout and not result.stderr)
    return ScanResult(
        target=target,
        command=command,
        success=success,
        xml_output=result.stdout,
        error=result.stderr.strip(),
        returncode=result.returncode,
    )


def scan_targets(
    targets: Sequence[str],
    start_port: int,
    end_port: int,
    scripts: Optional[Sequence[str]] = None,
    aggressive: bool = True,
    timing_template: Optional[int] = None,
    extra_nmap_args: Optional[Sequence[str]] = None,
    concurrency: int = 2,
) -> List[ScanResult]:
    """
    Run scans against multiple targets concurrently.
    """
    results: List[ScanResult] = []
    if concurrency < 1:
        concurrency = 1

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_target = {
            executor.submit(
                run_nmap,
                target,
                start_port,
                end_port,
                scripts,
                aggressive,
                timing_template,
                extra_nmap_args,
            ): target
            for target in targets
        }
        for future in as_completed(future_to_target):
            try:
                results.append(future.result())
            except NmapNotFoundError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                target = future_to_target[future]
                results.append(
                    ScanResult(
                        target=target,
                        command=[],
                        success=False,
                        xml_output="",
                        error=str(exc),
                        returncode=1,
                    )
                )
    return results


def load_targets_from_file(path: str) -> List[str]:
    """
    Load targets from a file (one per line, comments with '#').
    """
    targets: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets

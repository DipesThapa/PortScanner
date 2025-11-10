"""
Command-line interface for the port scanner package.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import assets, config as config_module
from . import differential, interactive, parser, reporting, scanner, service_intel
from .credentials import CredentialStore
from .baselines import BaselineStore
from .scheduler import JobScheduler
from .plugins import PluginManager, PluginContext
from .exporters import load_exporters
from .orchestrator import DistributedRunner
from .api import start_api_server
from .config import ConfigLoadError
from .parser import NmapXMLParseError
from .reporting import render_text_report, render_summary_text
from .scanner import NmapNotFoundError

DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
MIN_PORT = 1
MAX_PORT = 65535

try:
    BooleanOptionalAction = argparse.BooleanOptionalAction  # type: ignore[attr-defined]
except AttributeError:  # pragma: no cover - fallback for Python<3.9

    class BooleanOptionalAction(argparse.Action):
        def __init__(self, option_strings, dest, default=None, **kwargs):
            _option_strings = []
            for option in option_strings:
                _option_strings.append(option)
                if option.startswith("--"):
                    _option_strings.append("--no-" + option[2:])
            super().__init__(_option_strings, dest, nargs=0, default=default, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            if option_string:
                setattr(namespace, self.dest, not option_string.startswith("--no-"))


def normalize_port_pair(start_port: int, end_port: int) -> (int, int):
    if not (MIN_PORT <= start_port <= MAX_PORT):
        raise ValueError(f"Start port must be between {MIN_PORT} and {MAX_PORT}.")
    if not (MIN_PORT <= end_port <= MAX_PORT):
        raise ValueError(f"End port must be between {MIN_PORT} and {MAX_PORT}.")
    if start_port > end_port:
        start_port, end_port = end_port, start_port
    return start_port, end_port


def parse_port_range(port_range: str) -> (int, int):
    if "-" in port_range:
        start_str, end_str = port_range.split("-", 1)
    else:
        start_str, end_str = port_range, port_range

    try:
        start_port = int(start_str)
        end_port = int(end_str)
    except ValueError:
        raise ValueError("Port values must be integers.")

    return normalize_port_pair(start_port, end_port)


def _tokenize_scripts(values: Sequence[str]) -> List[str]:
    scripts: List[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                scripts.append(part)
    return scripts


def parse_scripts_arg(values: Optional[Sequence[str]]) -> List[str]:
    if not values:
        return list(scanner.DEFAULT_SCRIPTS)
    scripts = _tokenize_scripts(values)
    return scripts or list(scanner.DEFAULT_SCRIPTS)


def slugify_target(target: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", target)
    slug = slug.strip("_")
    return slug or "target"


def _parse_scripts_value(value) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        value = [value]
    if isinstance(value, Sequence):
        return _tokenize_scripts(list(value))
    return []


def _merge_scripts(primary: Sequence[str], extras: Sequence[str]) -> List[str]:
    result = list(primary)
    for script in extras:
        if script not in result:
            result.append(script)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser_obj = argparse.ArgumentParser(
        description="Run advanced Nmap scans with friendly reporting."
    )
    parser_obj.add_argument("--config", help="Load defaults from a JSON configuration file.")
    parser_obj.add_argument("--target", help="Hostname or IP address to scan.")
    parser_obj.add_argument(
        "--targets",
        nargs="+",
        help="Additional hostnames or IPs to scan.",
    )
    parser_obj.add_argument(
        "--target-file",
        help="Path to a file containing targets (one per line).",
    )
    parser_obj.add_argument(
        "--ports",
        help="Port range in start-end format (e.g., 1-1024). Overrides --start-port/--end-port.",
    )
    parser_obj.add_argument(
        "--start-port",
        type=int,
        default=DEFAULT_START_PORT,
        help=f"Lowest TCP port to scan (default: {DEFAULT_START_PORT}).",
    )
    parser_obj.add_argument(
        "--end-port",
        type=int,
        default=DEFAULT_END_PORT,
        help=f"Highest TCP port to scan (default: {DEFAULT_END_PORT}).",
    )
    parser_obj.add_argument(
        "--scripts",
        nargs="+",
        help="Nmap NSE scripts or categories to run (comma separated allowed).",
    )
    parser_obj.add_argument(
        "--intel",
        action="store_true",
        help="Enable service intelligence enrichment and add banner/NSE intel scripts.",
    )
    parser_obj.add_argument(
        "--intel-scripts",
        nargs="+",
        help="Override the service intelligence script list (comma separated allowed).",
    )
    parser_obj.add_argument(
        "--aggressive",
        action=BooleanOptionalAction,
        default=True,
        help="Enable or disable Nmap -A aggressive scan features.",
    )
    parser_obj.add_argument(
        "--timing",
        type=int,
        choices=range(0, 6),
        help="Nmap timing template (0-5).",
    )
    parser_obj.add_argument(
        "--extra-arg",
        dest="extra_args",
        action="append",
        help="Additional raw arguments to pass directly to Nmap (repeatable).",
    )
    parser_obj.add_argument(
        "--concurrency",
        type=int,
        default=2,
        help="Number of Nmap scans to run in parallel (default: 2).",
    )
    parser_obj.add_argument(
        "--save-xml",
        help="Write raw Nmap XML output to PATH (directory if scanning multiple targets).",
    )
    parser_obj.add_argument(
        "--save-vulns",
        help="Write detected vulnerabilities to PATH as JSON.",
    )
    parser_obj.add_argument(
        "--save-report",
        help="Write the combined text report to PATH.",
    )
    parser_obj.add_argument(
        "--output-json",
        help="Write the combined structured report to PATH as JSON.",
    )
    parser_obj.add_argument(
        "--output-dir",
        help="Directory for per-target outputs (XML and vulnerability JSON).",
    )
    parser_obj.add_argument(
        "--baseline-json",
        help="Existing structured JSON report to compare against.",
    )
    parser_obj.add_argument(
        "--diff-report",
        help="Write differential results to PATH as JSON.",
    )
    parser_obj.add_argument(
        "--asset-file",
        help="Asset metadata catalog (JSON) to enrich scan results.",
    )
    parser_obj.add_argument(
        "--plugins",
        nargs="+",
        help="Enable additional plugins (built-ins: threat-intel, auto-responder, deep-dive).",
    )
    parser_obj.add_argument(
        "--exporters",
        nargs="+",
        help="Emit results via exporters (built-ins: stdout, jsonl).",
    )
    parser_obj.add_argument(
        "--exporter-config",
        help="JSON file mapping exporter names to options (e.g., output paths).",
    )
    parser_obj.add_argument(
        "--plugin-config",
        help="JSON file containing plugin-specific options.",
    )
    parser_obj.add_argument(
        "--credential-file",
        help="JSON file with service credentials for authenticated checks.",
    )
    parser_obj.add_argument(
        "--secret-file",
        help="JSON file containing named secrets (used when credential values reference secret:// keys).",
    )
    parser_obj.add_argument(
        "--secret-prefix",
        default="PORTSCANNER_",
        help="Environment variable prefix for secret lookups (default: PORTSCANNER_).",
    )
    parser_obj.add_argument(
        "--baseline-store",
        help="Directory for storing baseline history and trend data.",
    )
    parser_obj.add_argument(
        "--job-file",
        help="JSON file describing queued scan jobs (args per job).",
    )
    parser_obj.add_argument(
        "--orchestrator-config",
        help="JSON file describing distributed worker nodes.",
    )
    parser_obj.add_argument(
        "--api-listen",
        help="Start a read-only HTTP API on host:port to expose summary/diff/trend data.",
    )
    parser_obj.add_argument(
        "--xml-file",
        help="Parse an existing Nmap XML file instead of running a scan.",
    )
    parser_obj.add_argument(
        "--interactive",
        action="store_true",
        help="Force the guided interactive helper.",
    )
    parser_obj.add_argument(
        "--batch",
        action="store_true",
        help="Fail instead of launching the interactive helper when no targets are provided.",
    )
    return parser_obj


def _merge_config(args: argparse.Namespace, parser_obj: argparse.ArgumentParser) -> Dict:
    config_data: Dict = {}
    if not args.config:
        return config_data

    try:
        config_data = config_module.load_config(args.config)
    except ConfigLoadError as exc:
        parser_obj.error(str(exc))
    return config_data


def _resolve_port_range(
    args: argparse.Namespace,
    config_data: Dict,
    parser_obj: argparse.ArgumentParser,
) -> (int, int):
    start_port = args.start_port
    end_port = args.end_port

    if "start_port" in config_data:
        start_port = int(config_data["start_port"])
    if "end_port" in config_data:
        end_port = int(config_data["end_port"])
    if "ports" in config_data:
        try:
            start_port, end_port = parse_port_range(str(config_data["ports"]))
        except ValueError as exc:
            parser_obj.error(f"Invalid port range in config: {exc}")

    if args.ports:
        try:
            start_port, end_port = parse_port_range(args.ports)
        except ValueError as exc:
            parser_obj.error(str(exc))

    try:
        return normalize_port_pair(start_port, end_port)
    except ValueError as exc:
        parser_obj.error(str(exc))
    return start_port, end_port  # pragma: no cover - unreachable


def _collect_targets(
    args: argparse.Namespace,
    config_data: Dict,
) -> List[str]:
    targets: List[str] = []

    def _add_target(value: Optional[str]):
        if value and value not in targets:
            targets.append(value)

    config_targets = config_data.get("targets")
    if isinstance(config_targets, list):
        for entry in config_targets:
            _add_target(str(entry))

    _add_target(config_data.get("target"))

    if args.targets:
        for entry in args.targets:
            _add_target(entry)

    _add_target(args.target)

    target_file = config_data.get("target_file") or args.target_file
    if target_file:
        try:
            file_targets = scanner.load_targets_from_file(target_file)
        except FileNotFoundError:
            raise FileNotFoundError(f"Target file not found: {target_file}")
        for entry in file_targets:
            _add_target(entry)

    return targets


def _resolve_scripts(args: argparse.Namespace, config_data: Dict) -> List[str]:
    scripts = None
    config_scripts = config_data.get("scripts")
    if config_scripts:
        if isinstance(config_scripts, str):
            scripts = [config_scripts]
        else:
            scripts = list(config_scripts)
    cli_scripts = parse_scripts_arg(args.scripts)
    if args.scripts:
        scripts = cli_scripts
    elif scripts is None:
        scripts = cli_scripts
    return scripts


def _resolve_extra_args(args: argparse.Namespace, config_data: Dict) -> List[str]:
    extra_args: List[str] = []
    config_extra = config_data.get("extra_nmap_args")
    if isinstance(config_extra, list):
        extra_args.extend(str(item) for item in config_extra)
    elif isinstance(config_extra, str):
        extra_args.append(config_extra)
    if args.extra_args:
        extra_args.extend(args.extra_args)
    return extra_args


def _resolve_xml_file(args: argparse.Namespace, config_data: Dict) -> Optional[str]:
    return args.xml_file or config_data.get("xml_file")


def _load_plugin_options(path: Optional[str]) -> Dict[str, Dict]:
    if not path:
        return {}
    try:
        data = config_module.load_config(path)
    except ConfigLoadError as exc:
        raise ConfigLoadError(f"Failed to load plugin config: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigLoadError("Plugin config must be a JSON object mapping plugin names to options.")
    return {str(key): value for key, value in data.items() if isinstance(value, dict)}


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser_obj = build_parser()
    args = parser_obj.parse_args(argv)

    if args.job_file:
        try:
            scheduler = JobScheduler.from_file(args.job_file)
        except (ValueError, json.JSONDecodeError) as exc:
            parser_obj.error(f"Failed to load job file: {exc}")
        plan_text = scheduler.render_plan()
        print(plan_text)
        for job in scheduler.jobs:
            print(f"\n>>> Executing scheduled job: {job.name}")
            main(job.args)
        return

    config_data = _merge_config(args, parser_obj)
    start_port, end_port = _resolve_port_range(args, config_data, parser_obj)
    scripts = _resolve_scripts(args, config_data)
    extra_args = _resolve_extra_args(args, config_data)

    config_intel = config_data.get("intel")
    if args.intel:
        intel_enabled = True
    elif config_intel is not None:
        intel_enabled = bool(config_intel)
    else:
        intel_enabled = False
    cli_intel_scripts = _tokenize_scripts(args.intel_scripts) if args.intel_scripts else []
    config_intel_scripts = _parse_scripts_value(config_data.get("intel_scripts"))
    intel_scripts = cli_intel_scripts or config_intel_scripts
    if intel_enabled:
        if not intel_scripts:
            intel_scripts = list(service_intel.DEFAULT_INTEL_SCRIPTS)
        scripts = _merge_scripts(scripts, intel_scripts)
    else:
        intel_scripts = []

    aggressive = config_data.get("aggressive", args.aggressive)
    timing_template = config_data.get("timing_template", args.timing)
    concurrency = int(config_data.get("concurrency", args.concurrency or 1))

    save_xml = args.save_xml or config_data.get("save_xml")
    save_vulns = args.save_vulns or config_data.get("save_vulns")
    save_report = args.save_report or config_data.get("save_report")
    output_json = args.output_json or config_data.get("output_json")
    output_dir = args.output_dir or config_data.get("output_dir")
    baseline_path = args.baseline_json or config_data.get("baseline_json")
    diff_report_path = args.diff_report or config_data.get("diff_report")
    asset_path = args.asset_file or config_data.get("asset_file")
    credential_path = args.credential_file or config_data.get("credential_file")
    secret_file = args.secret_file or config_data.get("secret_file")
    secret_prefix = args.secret_prefix or config_data.get("secret_prefix", "PORTSCANNER_")
    baseline_store_path = args.baseline_store or config_data.get("baseline_store")
    plugin_specs = config_data.get("plugins") or []
    if args.plugins:
        plugin_specs = args.plugins
    plugin_config_path = args.plugin_config or config_data.get("plugin_config")
    plugin_options = {}
    if isinstance(config_data.get("plugin_options"), dict):
        plugin_options.update(config_data["plugin_options"])
    if plugin_config_path:
        plugin_options.update(_load_plugin_options(plugin_config_path))
    exporter_names = config_data.get("exporters") or []
    if args.exporters:
        exporter_names = args.exporters
    exporter_config_path = args.exporter_config or config_data.get("exporter_config")
    exporter_options = {}
    if isinstance(config_data.get("exporter_options"), dict):
        exporter_options.update(config_data["exporter_options"])
    if exporter_config_path:
        try:
            exporter_data = config_module.load_config(exporter_config_path)
            if isinstance(exporter_data, dict):
                exporter_options.update(exporter_data)
        except ConfigLoadError as exc:
            parser_obj.error(str(exc))
    orchestrator_config = args.orchestrator_config or config_data.get("orchestrator_config")
    api_listen = args.api_listen or config_data.get("api_listen")

    baseline_store = None
    baseline_hosts: List[Dict] = []
    if baseline_store_path:
        baseline_store = BaselineStore(baseline_store_path)
        latest_hosts = baseline_store.load_latest_hosts()
        if latest_hosts and not baseline_path:
            baseline_hosts = latest_hosts
            latest_record = baseline_store.latest_record()
            if latest_record:
                baseline_path = str(latest_record.path)
    if baseline_path and not baseline_hosts:
        try:
            baseline_hosts = differential.load_baseline_hosts(baseline_path)
        except differential.BaselineLoadError as exc:
            parser_obj.error(str(exc))

    asset_catalog = None
    if asset_path:
        try:
            asset_catalog = assets.load_catalog(asset_path)
        except assets.AssetCatalogLoadError as exc:
            parser_obj.error(str(exc))

    credential_store = None
    if credential_path or secret_file:
        try:
            credential_store = CredentialStore.from_sources(
                credential_path,
                env_prefix=secret_prefix,
                secret_file=secret_file,
            )
        except ValueError as exc:
            parser_obj.error(str(exc))

    plugin_manager = PluginManager(plugin_specs, plugin_options)
    plugin_manager.load_plugins()
    exporters = list(load_exporters(exporter_names, exporter_options))
    orchestrator = None
    if orchestrator_config:
        try:
            orchestrator = DistributedRunner.from_config(orchestrator_config)
            print(orchestrator.render_status())
        except (ValueError, json.JSONDecodeError) as exc:
            parser_obj.error(f"Failed to load orchestrator config: {exc}")
    api_server = None
    plugin_context = PluginContext(
        settings={
            "start_port": start_port,
            "end_port": end_port,
            "aggressive": aggressive,
            "timing_template": timing_template,
            "mode": "cli",
            "baseline_store": baseline_store_path,
        },
        asset_catalog=asset_catalog,
        config=plugin_options,
        credentials=credential_store,
    )
    plugin_manager.initialize(plugin_context)

    xml_file = _resolve_xml_file(args, config_data)
    targets = []
    try:
        targets = _collect_targets(args, config_data)
    except FileNotFoundError as exc:
        parser_obj.error(str(exc))

    interactive_requested = args.interactive or (
        not args.batch
        and not xml_file
        and not targets
        and not config_data.get("targets")
        and not config_data.get("target")
        and not config_data.get("target_file")
        and not args.target_file
    )

    if interactive_requested:
        initial_target = args.target or config_data.get("target")
        interactive.run_interactive_mode(
            initial_target=initial_target,
            default_start=start_port,
            default_end=end_port,
            scripts=scripts,
            intel_enabled=intel_enabled,
            asset_catalog=asset_catalog,
            plugin_specs=plugin_specs,
            plugin_options=plugin_options,
            credential_store=credential_store,
            baseline_hosts=baseline_hosts,
            baseline_store=baseline_store,
            baseline_path=baseline_path,
            exporters=exporters,
            api_listen=api_listen,
            orchestrator=orchestrator,
        )
        return

    if xml_file:
        plugin_context.settings.update({"mode": "cli-xml", "source": xml_file})
        try:
            xml_output = Path(xml_file).read_text(encoding="utf-8")
        except FileNotFoundError:
            parser_obj.error(f"XML file not found: {xml_file}")
        except OSError as exc:
            parser_obj.error(f"Failed to read XML file: {exc}")

        try:
            host_reports = parser.parse_nmap_xml(xml_output)
        except NmapXMLParseError as exc:
            parser_obj.error(str(exc))
        if intel_enabled:
            service_intel.enrich_hosts(host_reports)
        if asset_catalog:
            asset_catalog.enrich_hosts(host_reports)
        for host in host_reports:
            plugin_manager.process_host(host)

        default_target_name = Path(xml_file).stem
        for host in host_reports:
            host.setdefault("target", default_target_name)

        print(render_text_report(host_reports))
        summary_data = parser.summarize_reports(host_reports)
        print(render_summary_text(summary_data))

        diff_results = None
        if baseline_hosts:
            diff_results = differential.compute_diff(host_reports, baseline_hosts)
            plugin_context.diff_results = diff_results
            print(differential.format_diff_summary(diff_results))
            if diff_report_path:
                reporting.save_json_report(diff_report_path, diff_results)

        plugin_output = plugin_manager.finalize()
        plugin_output = service_intel.append_summary(plugin_output, host_reports)
        summary_text = reporting.render_plugin_summary(plugin_output)
        if summary_text:
            print(summary_text)

        if save_vulns:
            reporting.save_vulnerability_report(save_vulns, host_reports)
            print(f"[+] Vulnerability report saved to {save_vulns}")

        if save_report:
            reporting.save_text_report(save_report, render_text_report(host_reports))
            print(f"[+] Text report saved to {save_report}")

        if output_json:
            combined = {
                "targets": {"loaded": host_reports},
                "summary": summary_data,
                "settings": {
                    "start_port": start_port,
                    "end_port": end_port,
                    "scripts": scripts,
                    "intel_enabled": intel_enabled,
                    "intel_scripts": intel_scripts,
                    "baseline_path": baseline_path,
                    "diff_report_path": diff_report_path,
                    "credential_file": credential_path,
                    "plugins": plugin_specs,
                },
            }
            if diff_results:
                combined["diff"] = diff_results
            if plugin_output:
                combined["plugins"] = plugin_output
            reporting.save_json_report(output_json, combined)
            print(f"[+] Structured report saved to {output_json}")
        if baseline_store:
            snapshot_path = baseline_store.record_run(
                summary_data,
                host_reports,
                plugin_output,
            )
            print(f"[+] Baseline snapshot stored to {snapshot_path}")
            trend_text = baseline_store.render_trend()
            if trend_text:
                print(trend_text)
        trend_text = baseline_store.render_trend() if baseline_store else ""
        if api_listen:
            if api_server is None:
                api_server = start_api_server(api_listen, summary_data, diff_results, trend_text)
            else:
                api_server.update(summary_data, diff_results, trend_text)
        export_payload = {
            "mode": "xml-run",
            "summary": summary_data,
            "targets": {"loaded": host_reports},
            "diff": diff_results,
            "plugins": plugin_output,
        }
        for exporter in exporters:
            try:
                exporter.export(export_payload)
            except Exception as exc:
                print(f"[-] Exporter {getattr(exporter, 'name', 'unknown')} failed: {exc}")
        if api_server:
            try:
                print("[+] API server running. Press Ctrl+C to stop.")
                while True:
                    import time

                    time.sleep(60)
            except KeyboardInterrupt:
                print("\n[!] Stopping API server...")
                api_server.shutdown()
        return

    if not targets:
        parser_obj.error(
            "No targets specified. Provide --target/--targets/--target-file or run without --batch for interactive mode."
        )

    if concurrency < 1:
        concurrency = 1

    if save_xml and len(targets) > 1:
        xml_path = Path(save_xml)
        if xml_path.suffix:
            parser_obj.error("--save-xml must point to a directory when scanning multiple targets.")

    if output_dir:
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    try:
        scan_results = scanner.scan_targets(
            targets,
            start_port,
            end_port,
            scripts=scripts,
            aggressive=aggressive,
            timing_template=timing_template,
            extra_nmap_args=extra_args,
            concurrency=concurrency,
        )
    except NmapNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    target_order = {target: index for index, target in enumerate(targets)}
    scan_results.sort(key=lambda result: target_order.get(result.target, 0))

    aggregated_hosts: List[Dict] = []
    target_reports: Dict[str, List[Dict]] = {}
    failures: List[Dict] = []
    diff_results = None

    for result in scan_results:
        print(f"\n=== Results for {result.target} ===")
        if not result.success or not result.xml_output:
            print("[-] Scan failed or produced no output.")
            if result.error:
                print(result.error)
            failures.append(
                {
                    "target": result.target,
                    "error": result.error,
                    "returncode": result.returncode,
                }
            )
            continue

        if save_xml:
            xml_path = Path(save_xml)
            if len(targets) > 1:
                xml_path.mkdir(parents=True, exist_ok=True)
                out_path = xml_path / f"{slugify_target(result.target)}.xml"
                reporting.save_xml_output(str(out_path), result.xml_output)
            else:
                reporting.save_xml_output(save_xml, result.xml_output)

        if output_dir:
            dir_path = Path(output_dir)
            dir_path.mkdir(parents=True, exist_ok=True)
            slug = slugify_target(result.target)
            reporting.save_xml_output(str(dir_path / f"{slug}.xml"), result.xml_output)

        try:
            host_reports = parser.parse_nmap_xml(result.xml_output)
        except NmapXMLParseError as exc:
            print(str(exc))
            failures.append(
                {
                    "target": result.target,
                    "error": str(exc),
                    "returncode": result.returncode,
                }
            )
            continue

        if intel_enabled:
            service_intel.enrich_hosts(host_reports)
        if asset_catalog:
            asset_catalog.enrich_hosts(host_reports)
        for host in host_reports:
            plugin_manager.process_host(host)

        for host in host_reports:
            host.setdefault("target", result.target)

        text_report = render_text_report(host_reports)
        print(text_report)

        aggregated_hosts.extend(host_reports)
        target_reports[result.target] = host_reports

        if output_dir:
            slug = slugify_target(result.target)
            reporting.save_vulnerability_report(str(Path(output_dir) / f"{slug}.vulns.json"), host_reports)

    summary = parser.summarize_reports(aggregated_hosts)
    print(render_summary_text(summary))

    if baseline_hosts:
        diff_results = differential.compute_diff(aggregated_hosts, baseline_hosts)
        plugin_context.diff_results = diff_results
        print(differential.format_diff_summary(diff_results))
        if diff_report_path:
            reporting.save_json_report(diff_report_path, diff_results)

    plugin_output = plugin_manager.finalize()
    plugin_output = service_intel.append_summary(plugin_output, aggregated_hosts)
    summary_text = reporting.render_plugin_summary(plugin_output)
    if summary_text:
        print(summary_text)

    if save_vulns and aggregated_hosts:
        reporting.save_vulnerability_report(save_vulns, aggregated_hosts)
        print(f"[+] Vulnerability report saved to {save_vulns}")

    if save_report and aggregated_hosts:
        reporting.save_text_report(save_report, render_text_report(aggregated_hosts))
        print(f"[+] Text report saved to {save_report}")

    if output_json:
        combined = {
            "targets": target_reports,
            "summary": summary,
            "failures": failures,
            "settings": {
                "start_port": start_port,
                "end_port": end_port,
                "scripts": scripts,
                "aggressive": aggressive,
                "timing_template": timing_template,
                "extra_args": extra_args,
                "intel_enabled": intel_enabled,
                "intel_scripts": intel_scripts,
                "baseline_path": baseline_path,
                "diff_report_path": diff_report_path,
                "credential_file": credential_path,
                "plugins": plugin_specs,
            },
        }
        if diff_results:
            combined["diff"] = diff_results
    if plugin_output:
        combined["plugins"] = plugin_output
        reporting.save_json_report(output_json, combined)
        print(f"[+] Structured report saved to {output_json}")

    if baseline_store and aggregated_hosts:
        snapshot_path = baseline_store.record_run(summary, aggregated_hosts, plugin_output)
        print(f"[+] Baseline snapshot stored to {snapshot_path}")
        trend_text = baseline_store.render_trend()
        if trend_text:
            print(trend_text)
    else:
        trend_text = ""

    if api_listen:
        if api_server is None:
            api_server = start_api_server(api_listen, summary, diff_results, trend_text)
        else:
            api_server.update(summary, diff_results, trend_text)

    export_payload = {
        "mode": "batch-run",
        "summary": summary,
        "targets": target_reports,
        "diff": diff_results,
        "plugins": plugin_output,
        "failures": failures,
    }
    for exporter in exporters:
        try:
            exporter.export(export_payload)
        except Exception as exc:
            print(f"[-] Exporter {getattr(exporter, 'name', 'unknown')} failed: {exc}")

    if failures:
        print(f"\n[-] {len(failures)} scan(s) reported issues.")

    if api_server:
        try:
            print("[+] API server running. Press Ctrl+C to stop.")
            while True:
                import time

                time.sleep(60)
        except KeyboardInterrupt:
            print("\n[!] Stopping API server...")
            api_server.shutdown()

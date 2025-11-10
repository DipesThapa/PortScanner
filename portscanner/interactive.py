"""
Friendly interactive wizard for guiding users through scans.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence, Tuple

from . import parser, reporting, scanner, service_intel, differential
from .assets import AssetCatalog
from .plugins import PluginManager, PluginContext
from .api import start_api_server

DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
MIN_PORT = 1
MAX_PORT = 65535


def prompt_yes_no(question: str, default: bool = False) -> bool:
    yes_values = {"y", "yes"}
    no_values = {"n", "no"}
    default_display = "Y/n" if default else "y/N"

    while True:
        answer = input(f"{question} ({default_display}): ").strip().lower()
        if not answer:
            return default
        if answer in yes_values:
            return True
        if answer in no_values:
            return False
        print("Please type yes or no.")


def _prompt_for_ports(default_start: int, default_end: int) -> Tuple[int, int]:
    while True:
        start_input = input(f"Enter the start port (default is {default_start}): ").strip()
        end_input = input(f"Enter the end port (default is {default_end}): ").strip()

        start_value = start_input or str(default_start)
        end_value = end_input or str(default_end)

        try:
            start_port = int(start_value)
            end_port = int(end_value)
        except ValueError:
            print("Please enter whole numbers for the ports.")
            continue

        if not (MIN_PORT <= start_port <= MAX_PORT) or not (MIN_PORT <= end_port <= MAX_PORT):
            print(f"Ports need to be between {MIN_PORT} and {MAX_PORT}.")
            continue

        if start_port > end_port:
            print("Start port bigger than end port; I'll swap them for you.")
            start_port, end_port = end_port, start_port

        return start_port, end_port


def interactive_choose_port_range(default_start: int, default_end: int) -> Tuple[int, int]:
    print("\nHow many ports should I check?")
    print("  1) Quick scan (ports 1 to 1024) – fastest")
    print("  2) Full scan (ports 1 to 65535) – takes longer")
    print("  3) Custom range – you choose the start and end")
    custom_prefill = default_start != DEFAULT_START_PORT or default_end != DEFAULT_END_PORT
    if custom_prefill:
        print(f"  0) Use the range you already picked ({default_start}-{default_end})")

    while True:
        prompt = "Pick 1, 2, or 3"
        if custom_prefill:
            prompt += " (or 0)"
        prompt += ": "
        choice = input(prompt).strip()

        if custom_prefill and choice == "0":
            return default_start, default_end
        if choice == "1":
            return DEFAULT_START_PORT, DEFAULT_END_PORT
        if choice == "2":
            return MIN_PORT, MAX_PORT
        if choice == "3":
            print("\nOkay, let's choose a custom range.")
            return _prompt_for_ports(DEFAULT_START_PORT, DEFAULT_END_PORT)
        print("Let's try that again. Type 1, 2, or 3.")


def interactive_prompt_target(existing_target: Optional[str] = None) -> str:
    print("\nTell me who you want to scan.")
    print("Example targets: 192.168.1.10 or my-computer.local")
    while True:
        if existing_target:
            entry = input(f"Device or website [{existing_target}]: ").strip()
            if not entry:
                return existing_target
        else:
            entry = input("Device or website: ").strip()
        if entry:
            return entry
        print("I need something to scan. Let's try again.")


def interactive_prompt_file() -> Optional[Tuple[str, str]]:
    print("\nIf you already have a scan saved as XML, I can read it for you.")
    print("To go back, just press Enter without typing anything.")
    while True:
        path = input("Path to XML file: ").strip()
        if not path:
            return None
        try:
            xml_output = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            print("Hmm, I couldn't read that file. Double-check the path and try again.")
            continue
        except OSError as exc:
            print(f"Something went wrong while reading the file: {exc}")
            continue
        return path, xml_output


def interactive_save_path(kind: str, suggested_name: str) -> Optional[str]:
    if not prompt_yes_no(f"Do you want me to save the {kind} to a file?", default=False):
        return None
    while True:
        path = input(f"Where should I save it? [{suggested_name}]: ").strip()
        path = path or suggested_name
        if path:
            return path
        print("Please enter a file name or press Ctrl+C to stop.")


def interactive_summarize_results(host_reports) -> None:
    if not host_reports:
        print("\nAll done! I didn't receive any data to summarize.")
        return

    summary = parser.summarize_reports(host_reports)
    print("\n=== Friendly Summary ===")
    print(f"- Hosts talked about: {summary.get('hosts')}")
    print(f"- Open ports spotted: {summary.get('open_ports')}")
    vuln_count = summary.get("vulnerabilities", 0)
    if vuln_count:
        print(f"- Possible risks flagged: {vuln_count}")
        print("  (Scroll up to see the details!)")
    else:
        print("- No obvious risks reported by Nmap's scripts. Nice!")


def run_interactive_mode(
    initial_target: Optional[str] = None,
    default_start: int = DEFAULT_START_PORT,
    default_end: int = DEFAULT_END_PORT,
    scripts: Optional[Sequence[str]] = None,
    intel_enabled: bool = False,
    asset_catalog: Optional[AssetCatalog] = None,
    plugin_specs: Optional[Sequence[str]] = None,
    plugin_options: Optional[dict] = None,
    credential_store=None,
    baseline_hosts=None,
    baseline_store=None,
    baseline_path: Optional[str] = None,
    exporters=None,
    api_listen: Optional[str] = None,
    orchestrator=None,
) -> None:
    scripts = list(scripts or scanner.DEFAULT_SCRIPTS)
    baseline_hosts_data = list(baseline_hosts or [])
    exporters = list(exporters or [])
    plugin_options = plugin_options or {}
    api_server = None

    if orchestrator is not None:
        print(orchestrator.render_status())

    if baseline_store is not None:
        trend = baseline_store.render_trend()
        if trend:
            print(trend)
    elif baseline_path:
        print(f"[*] Using baseline from {baseline_path}")

    print("Hi! I'm your scanning buddy. Let's explore safely.")
    print("Remember: only scan devices you own or have permission to test.\n")

    while True:
        print("What would you like me to do?")
        print("  1) Run a new scan")
        print("  2) Read a saved scan (XML file)")
        print("  3) Quit")
        choice = input("Type 1, 2, or 3: ").strip()

        if choice == "1":
            target = interactive_prompt_target(existing_target=initial_target)
            start_port, end_port = interactive_choose_port_range(default_start, default_end)
            print("\nGreat! I'll get everything ready...")
            print(f"I'll check {target} from port {start_port} to {end_port}.")
            save_xml_path = interactive_save_path("raw scan (XML)", "scan.xml")
            save_vulns_path = interactive_save_path("vulnerability list (JSON)", "vulnerabilities.json")

            print("\nStarting the scan now. This might take a little while—feel free to stretch!")
            plugin_manager = PluginManager(plugin_specs or [], plugin_options)
            plugin_manager.load_plugins()
            plugin_context = PluginContext(
                settings={
                    "target": target,
                    "start_port": start_port,
                    "end_port": end_port,
                    "mode": "interactive",
                },
                asset_catalog=asset_catalog,
                config=plugin_options or {},
                credentials=credential_store,
            )
            plugin_manager.initialize(plugin_context)
            try:
                result = scanner.run_nmap(
                    target,
                    start_port,
                    end_port,
                    scripts=scripts,
                    aggressive=True,
                )
            except scanner.NmapNotFoundError as exc:
                print(str(exc))
                continue

            if not result.success or not result.xml_output:
                print("The scan didn't finish. Check the messages above and try again.")
                if result.error:
                    print(result.error)
                continue

            xml_output = result.xml_output

            if save_xml_path:
                reporting.save_xml_output(save_xml_path, xml_output)
                print(f"Saved XML to {save_xml_path}")

            try:
                host_reports = parser.parse_nmap_xml(xml_output)
            except parser.NmapXMLParseError as exc:
                print(str(exc))
                continue
            if intel_enabled:
                service_intel.enrich_hosts(host_reports)
            if asset_catalog:
                asset_catalog.enrich_hosts(host_reports)
            diff_results = None
            if baseline_hosts_data:
                diff_results = differential.compute_diff(host_reports, baseline_hosts_data)
                print(differential.format_diff_summary(diff_results))
            for host in host_reports:
                plugin_manager.process_host(host)

            summary_data = parser.summarize_reports(host_reports)
            print(reporting.render_text_report(host_reports))
            interactive_summarize_results(host_reports)
            plugin_output = plugin_manager.finalize()
            plugin_output = service_intel.append_summary(plugin_output, host_reports)
            plugin_summary = reporting.render_plugin_summary(plugin_output)
            if plugin_summary:
                print(plugin_summary)

            if save_vulns_path:
                reporting.save_vulnerability_report(save_vulns_path, host_reports)
                print(f"Saved vulnerability report to {save_vulns_path}")

            if baseline_store is not None:
                snapshot_path = baseline_store.record_run(summary_data, host_reports, plugin_output)
                print(f"[+] Baseline snapshot stored to {snapshot_path}")
                trend_text = baseline_store.render_trend()
                if trend_text:
                    print(trend_text)
                baseline_hosts_data = list(host_reports)
            elif baseline_hosts_data:
                baseline_hosts_data = list(host_reports)

            export_payload = {
                "mode": "interactive-run",
                "summary": summary_data,
                "targets": {"current": host_reports},
                "diff": diff_results,
                "plugins": plugin_output,
            }
            for exporter in exporters:
                try:
                    exporter.export(export_payload)
                except Exception as exc:
                    print(f"[-] Exporter {getattr(exporter, 'name', 'unknown')} failed: {exc}")

            trend_text = baseline_store.render_trend() if baseline_store is not None else ""
            if api_listen:
                if api_server is None:
                    api_server = start_api_server(api_listen, summary_data, diff_results, trend_text)
                else:
                    api_server.update(summary_data, diff_results, trend_text)

            initial_target = target
            default_start, default_end = start_port, end_port

        elif choice == "2":
            result = interactive_prompt_file()
            if result is None:
                print("No worries, heading back to the main menu.\n")
                continue
            path, xml_output = result
            print(f"\nReading {path}...")
            plugin_manager = PluginManager(plugin_specs or [], plugin_options)
            plugin_manager.load_plugins()
            plugin_context = PluginContext(
                settings={
                    "source": path,
                    "mode": "interactive-replay",
                },
                asset_catalog=asset_catalog,
                config=plugin_options or {},
                credentials=credential_store,
            )
            plugin_manager.initialize(plugin_context)
            try:
                host_reports = parser.parse_nmap_xml(xml_output)
            except parser.NmapXMLParseError as exc:
                print(str(exc))
                continue
            if intel_enabled:
                service_intel.enrich_hosts(host_reports)
            if asset_catalog:
                asset_catalog.enrich_hosts(host_reports)
            for host in host_reports:
                plugin_manager.process_host(host)

            summary_data = parser.summarize_reports(host_reports)
            diff_results = None
            if baseline_hosts_data:
                diff_results = differential.compute_diff(host_reports, baseline_hosts_data)
                print(differential.format_diff_summary(diff_results))
            print(reporting.render_text_report(host_reports))
            interactive_summarize_results(host_reports)
            plugin_output = plugin_manager.finalize()
            plugin_output = service_intel.append_summary(plugin_output, host_reports)
            plugin_summary = reporting.render_plugin_summary(plugin_output)
            if plugin_summary:
                print(plugin_summary)

            save_vulns_path = interactive_save_path("vulnerability list (JSON)", "vulnerabilities.json")
            if save_vulns_path:
                reporting.save_vulnerability_report(save_vulns_path, host_reports)
                print(f"Saved vulnerability report to {save_vulns_path}")

            export_payload = {
                "mode": "interactive-replay",
                "summary": summary_data,
                "targets": {"current": host_reports},
                "diff": diff_results,
                "plugins": plugin_output,
            }
            for exporter in exporters:
                try:
                    exporter.export(export_payload)
                except Exception as exc:
                    print(f"[-] Exporter {getattr(exporter, 'name', 'unknown')} failed: {exc}")

            trend_text = baseline_store.render_trend() if baseline_store is not None else ""
            if api_listen and summary_data:
                if api_server is None:
                    api_server = start_api_server(api_listen, summary_data, diff_results, trend_text)
                else:
                    api_server.update(summary_data, diff_results, trend_text)

        elif choice == "3":
            print("Okay, bye for now! Stay curious and stay safe.")
            if api_server:
                api_server.shutdown()
            return
        else:
            print("I didn't catch that. Let's pick 1, 2, or 3.\n")

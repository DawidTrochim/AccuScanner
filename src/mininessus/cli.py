from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from .aws_checks import run_aws_checks
from .azure_checks import run_azure_checks
from .checks import run_checks
from .checks.http import configure_browser_assistance
from .config import ScanConfig, load_scan_config, merge_scan_config
from .discovery import DiscoveryError, build_extra_nmap_args, run_nmap
from .gcp_checks import run_gcp_checks
from .history import load_history_reports, store_scan_history
from .interactive import run_interactive_menu
from .models import Finding, HostResult, ScanMetadata, ScanResult
from .parsing import NmapParseError, parse_nmap_xml
from .profiles import PROFILE_PRESETS, apply_profile
from .reporting import (
    build_dashboard,
    compare_reports,
    load_report,
    write_csv_report,
    write_dashboard_html,
    write_diff_json,
    write_html_report,
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)
from .ssh_checks import SSHAuthConfig, run_linux_ssh_checks
from .suppressions import apply_suppressions, load_suppression_rules
from .utils import build_report_stem, color_text, configure_logging, ensure_output_dir, infer_scan_target, utc_timestamp
from .windows_checks import WinRMAuthConfig, run_windows_host_checks


logger = logging.getLogger("accuscanner")
UTC_ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class SmartFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
    """Combines readable defaults with multi-line examples."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="accuscanner",
        description=(
            "AccuScanner is a defensive, Nessus-inspired assessment tool for\n"
            "owned and authorized systems. It uses nmap for discovery and\n"
            "exports structured JSON and HTML reports.\n\n"
            "Run `accuscanner` with no arguments to launch the guided menu."
        ),
        epilog=(
            "Examples:\n"
            "  accuscanner scan 192.168.1.10 --mode quick --timestamped-dir\n"
            "  accuscanner scan https://example.internal --mode web --save-raw-xml\n"
            "  accuscanner scan 10.0.0.0/24 --mode full --config scan-profile.yml\n"
            "  accuscanner scan 10.0.0.0/24 --mode azure --enable-azure-checks\n"
            "  accuscanner scan perimeter.example --enable-gcp-checks --gcp-project-id my-project\n"
            "  accuscanner dashboard reports/*.json --html-output reports/dashboard.html\n"
            "  accuscanner dashboard --history-dir history --html-output reports/history-dashboard.html\n"
            "  accuscanner compare reports/old.json reports/new.json --output reports/diff.json"
        ),
        formatter_class=SmartFormatter,
    )
    parser.add_argument("-help", action="help", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Run an assessment and export reports",
        description="Run nmap-based discovery, execute checks, and export JSON and HTML reports.",
        formatter_class=SmartFormatter,
    )
    scan.add_argument("-help", action="help", help=argparse.SUPPRESS)
    scan.add_argument("target", help="Authorized target IP, hostname, CIDR range, or URL")
    scan.add_argument("--profile", choices=sorted(PROFILE_PRESETS), default=None, help="Named scan profile preset")
    scan.add_argument("--mode", choices=["quick", "full", "web", "aws", "azure", "gcp"], default="quick", help="Assessment profile")
    scan.add_argument("--config", default=None, help="Optional YAML scan profile")
    scan.add_argument("--output-dir", default="reports", help="Base directory for exported reports")
    scan.add_argument("--timestamped-dir", action="store_true", help="Create a timestamped report subdirectory")
    scan.add_argument("--json-name", default=None, help="Optional JSON filename override")
    scan.add_argument("--html-name", default=None, help="Optional HTML filename override")
    scan.add_argument("--xml-name", default=None, help="Optional raw XML filename override")
    scan.add_argument("--markdown-name", default=None, help="Optional Markdown filename to export alongside the main report")
    scan.add_argument("--csv-name", default=None, help="Optional CSV filename to export alongside the main report")
    scan.add_argument("--sarif-name", default=None, help="Optional SARIF filename to export alongside the main report")
    scan.add_argument("--aws-region", default=None, help="AWS region override for aws mode")
    scan.add_argument("--azure-subscription-id", default=None, help="Azure subscription override for azure mode")
    scan.add_argument("--gcp-project-id", default=None, help="GCP project ID override for GCP checks")
    scan.add_argument("--ports", default=None, help="Custom port expression to pass to nmap, for example 22,80,443 or 1-1024")
    scan.add_argument("--udp-ports", default=None, help="UDP port expression to scan, for example 53,67,123,161")
    scan.add_argument("--udp-top-ports", type=int, default=None, help="Scan the top N UDP ports in addition to TCP checks")
    scan.add_argument("--nse-script", action="append", default=None, help="Nmap NSE script name to run; can be repeated")
    scan.add_argument("--nse-category", action="append", default=None, help="Nmap NSE script category to run; can be repeated")
    scan.add_argument("--parallelism", type=int, default=None, help="Minimum nmap parallelism, useful for larger target sets")
    scan.add_argument("--skip-host-discovery", action="store_true", help="Run nmap with -Pn from the start")
    scan.add_argument("--save-raw-xml", action="store_true", help="Save the raw nmap XML alongside parsed reports")
    scan.add_argument("--save-history", action="store_true", help="Copy the JSON report into a history directory for trend tracking")
    scan.add_argument("--history-dir", default=None, help="History directory used by --save-history and dashboard trend views")
    scan.add_argument("--suppressions", default=None, help="YAML or JSON suppression rules file")
    scan.add_argument("--enable-aws-checks", action="store_true", help="Run AWS posture checks alongside the network scan")
    scan.add_argument("--enable-azure-checks", action="store_true", help="Run Azure posture checks alongside the network scan")
    scan.add_argument("--enable-gcp-checks", action="store_true", help="Run GCP posture checks alongside the network scan")
    scan.add_argument("--ignore-id", action="append", default=None, help="Finding ID to suppress from the final report; can be repeated")
    scan.add_argument("--plugin-dir", default=None, help="Directory containing custom check plugins")
    scan.add_argument("--ssh-user", default=None, help="Username for authenticated Linux SSH checks")
    scan.add_argument("--ssh-password", default=None, help="Password for authenticated Linux SSH checks")
    scan.add_argument("--ssh-key-path", default=None, help="Private key path for authenticated Linux SSH checks")
    scan.add_argument("--winrm-user", default=None, help="Username for authenticated Windows WinRM checks")
    scan.add_argument("--winrm-password", default=None, help="Password for authenticated Windows WinRM checks")
    scan.add_argument("--winrm-port", type=int, default=5985, help="WinRM port for authenticated Windows checks")
    scan.add_argument("--winrm-transport", default="ntlm", help="WinRM transport such as ntlm, kerberos, or basic")
    scan.add_argument("--winrm-ssl", action="store_true", help="Use HTTPS for WinRM connections")
    scan.add_argument("--verbose", action="store_true", help="Enable debug logging")
    scan.add_argument("--browser-assisted", action="store_true", help="Use a headless browser to render pages and discover JS-driven routes during web scans")
    scan.add_argument("--browser-max-pages", type=int, default=None, help="Maximum rendered pages to inspect when --browser-assisted is enabled")
    scan.add_argument("--browser-timeout-ms", type=int, default=None, help="Browser navigation timeout in milliseconds for --browser-assisted web scans")

    compare = subparsers.add_parser(
        "compare",
        help="Compare two JSON reports",
        description="Highlight new and resolved findings between two exported JSON reports.",
        formatter_class=SmartFormatter,
    )
    compare.add_argument("-help", action="help", help=argparse.SUPPRESS)
    compare.add_argument("old_report", help="Path to the older JSON report")
    compare.add_argument("new_report", help="Path to the newer JSON report")
    compare.add_argument("--output", default=f"report-diff-{utc_timestamp()}.json", help="Where to write the diff JSON")
    compare.add_argument("--verbose", action="store_true", help="Enable debug logging")

    baseline = subparsers.add_parser(
        "baseline",
        help="Work with baseline reports",
        description="Create or compare baseline reports for drift and regression tracking.",
        formatter_class=SmartFormatter,
    )
    baseline.add_argument("-help", action="help", help=argparse.SUPPRESS)
    baseline_subparsers = baseline.add_subparsers(dest="baseline_command", required=True)
    baseline_create = baseline_subparsers.add_parser("create", help="Store a report as the current baseline", formatter_class=SmartFormatter)
    baseline_create.add_argument("report", help="Path to the source JSON report")
    baseline_create.add_argument("--output", default="baselines/current-baseline.json", help="Baseline output path")
    baseline_create.add_argument("--verbose", action="store_true", help="Enable debug logging")
    baseline_compare = baseline_subparsers.add_parser("compare", help="Compare a baseline to a newer report", formatter_class=SmartFormatter)
    baseline_compare.add_argument("baseline", help="Path to the baseline JSON report")
    baseline_compare.add_argument("report", help="Path to the newer JSON report")
    baseline_compare.add_argument("--output", default=f"baseline-diff-{utc_timestamp()}.json", help="Where to write the diff JSON")
    baseline_compare.add_argument("--verbose", action="store_true", help="Enable debug logging")

    batch = subparsers.add_parser(
        "batch",
        help="Run scans against multiple targets in parallel",
        description="Execute multiple scans concurrently and emit per-target reports plus an aggregate dashboard.",
        formatter_class=SmartFormatter,
    )
    batch.add_argument("-help", action="help", help=argparse.SUPPRESS)
    batch.add_argument("targets", nargs="*", help="One or more authorized targets")
    batch.add_argument("--targets-file", default=None, help="File containing one target per line")
    batch.add_argument("--workers", type=int, default=4, help="Maximum number of concurrent scans")
    batch.add_argument("--profile", choices=sorted(PROFILE_PRESETS), default=None, help="Named scan profile preset")
    batch.add_argument("--mode", choices=["quick", "full", "web", "aws", "azure", "gcp"], default="quick", help="Assessment profile")
    batch.add_argument("--config", default=None, help="Optional YAML scan profile")
    batch.add_argument("--output-dir", default="reports", help="Base directory for exported reports")
    batch.add_argument("--timestamped-dir", action="store_true", help="Create a timestamped report subdirectory")
    batch.add_argument("--save-history", action="store_true", help="Copy each JSON report into a history directory")
    batch.add_argument("--history-dir", default=None, help="History directory used by --save-history and dashboard trend views")
    batch.add_argument("--suppressions", default=None, help="YAML or JSON suppression rules file")
    batch.add_argument("--ports", default=None, help="Optional TCP ports expression")
    batch.add_argument("--udp-ports", default=None, help="Optional UDP ports expression")
    batch.add_argument("--udp-top-ports", type=int, default=None, help="Optional top UDP ports count")
    batch.add_argument("--nse-script", action="append", default=None, help="Optional NSE script name; can be repeated")
    batch.add_argument("--nse-category", action="append", default=None, help="Optional NSE category; can be repeated")
    batch.add_argument("--enable-aws-checks", action="store_true", help="Run AWS posture checks alongside the network scan")
    batch.add_argument("--enable-azure-checks", action="store_true", help="Run Azure posture checks alongside the network scan")
    batch.add_argument("--enable-gcp-checks", action="store_true", help="Run GCP posture checks alongside the network scan")
    batch.add_argument("--aws-region", default=None, help="AWS region override for aws mode")
    batch.add_argument("--azure-subscription-id", default=None, help="Azure subscription override for azure mode")
    batch.add_argument("--gcp-project-id", default=None, help="GCP project ID override for GCP checks")
    batch.add_argument("--parallelism", type=int, default=None, help="Minimum nmap parallelism")
    batch.add_argument("--skip-host-discovery", action="store_true", help="Run nmap with -Pn from the start")
    batch.add_argument("--save-raw-xml", action="store_true", help="Save the raw nmap XML alongside parsed reports")
    batch.add_argument("--ignore-id", action="append", default=None, help="Finding ID to suppress from the final report; can be repeated")
    batch.add_argument("--plugin-dir", default=None, help="Directory containing custom check plugins")
    batch.add_argument("--verbose", action="store_true", help="Enable debug logging")
    batch.add_argument("--browser-assisted", action="store_true", help="Use a headless browser to render pages and discover JS-driven routes during web scans")
    batch.add_argument("--browser-max-pages", type=int, default=None, help="Maximum rendered pages to inspect when --browser-assisted is enabled")
    batch.add_argument("--browser-timeout-ms", type=int, default=None, help="Browser navigation timeout in milliseconds for --browser-assisted web scans")

    dashboard = subparsers.add_parser(
        "dashboard",
        help="Aggregate multiple JSON reports into a dashboard",
        description="Build an aggregate JSON and HTML dashboard from one or more exported AccuScanner reports.",
        formatter_class=SmartFormatter,
    )
    dashboard.add_argument("-help", action="help", help=argparse.SUPPRESS)
    dashboard.add_argument("reports", nargs="*", help="One or more JSON report paths")
    dashboard.add_argument("--history-dir", default=None, help="Load all JSON reports from a history directory")
    dashboard.add_argument("--html-output", default=f"dashboard-{utc_timestamp()}.html", help="Dashboard HTML output path")
    dashboard.add_argument("--json-output", default=f"dashboard-{utc_timestamp()}.json", help="Dashboard JSON output path")
    dashboard.add_argument("--verbose", action="store_true", help="Enable debug logging")

    schedule = subparsers.add_parser(
        "schedule",
        help="Generate automation snippets for recurring scans",
        description="Produce cron, systemd, or Windows Task Scheduler commands for an AccuScanner scan.",
        formatter_class=SmartFormatter,
    )
    schedule.add_argument("-help", action="help", help=argparse.SUPPRESS)
    schedule.add_argument("target", help="Authorized target IP, hostname, CIDR range, or URL")
    schedule.add_argument("--mode", choices=["quick", "full", "web", "aws", "azure", "gcp"], default="quick", help="Assessment profile")
    schedule.add_argument("--format", choices=["cron", "systemd", "windows-task"], default="cron", help="Scheduling snippet format")
    schedule.add_argument("--output-dir", default="reports", help="Base directory for exported reports")
    schedule.add_argument("--timestamped-dir", action="store_true", help="Create timestamped report subdirectories")
    schedule.add_argument("--ports", default=None, help="Optional TCP ports expression")
    schedule.add_argument("--udp-ports", default=None, help="Optional UDP ports expression")
    schedule.add_argument("--udp-top-ports", type=int, default=None, help="Optional top UDP ports count")
    schedule.add_argument("--nse-script", action="append", default=None, help="Optional NSE script name; can be repeated")
    schedule.add_argument("--nse-category", action="append", default=None, help="Optional NSE category; can be repeated")
    schedule.add_argument("--enable-aws-checks", action="store_true", help="Include AWS checks in the generated command")
    schedule.add_argument("--enable-azure-checks", action="store_true", help="Include Azure checks in the generated command")
    schedule.add_argument("--enable-gcp-checks", action="store_true", help="Include GCP checks in the generated command")
    schedule.add_argument("--gcp-project-id", default=None, help="Optional GCP project ID to include in the generated command")
    schedule.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


def build_report_paths(
    args: argparse.Namespace,
    target_override: str | None = None,
) -> tuple[Path, Path, Path, Path | None, Path | None, Path | None]:
    report_dir = ensure_output_dir(args.output_dir, args.timestamped_dir)
    stem = build_report_stem(target_override or args.target, args.mode)
    return (
        report_dir / (args.json_name or f"{stem}.json"),
        report_dir / (args.html_name or f"{stem}.html"),
        report_dir / (args.xml_name or f"{stem}.xml"),
        report_dir / args.markdown_name if args.markdown_name else None,
        report_dir / args.csv_name if args.csv_name else None,
        report_dir / args.sarif_name if args.sarif_name else None,
    )


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime(UTC_ISO_FORMAT)


def parse_scan_execution(
    execution,
    target: str,
    plugin_dir: str | None,
) -> tuple[list[HostResult], list[Finding]]:
    hosts = parse_nmap_xml(execution.stdout)
    findings = run_checks(hosts, target, plugin_dir=plugin_dir)
    return hosts, findings


def execute_scan(
    target: str,
    mode: str,
    extra_nmap_args: list[str] | None = None,
    skip_host_discovery: bool = False,
    plugin_dir: str | None = None,
) -> tuple[list[HostResult], list[Finding], list[str], list[str], str]:
    hosts: list[HostResult] = []
    findings: list[Finding] = []
    errors: list[str] = []
    nmap_command: list[str] = []
    raw_xml = ""

    try:
        execution = run_nmap(target, mode if mode != "azure" else "quick", extra_args=extra_nmap_args, skip_host_discovery=skip_host_discovery)
        nmap_command = execution.command
        raw_xml = execution.stdout
        hosts, findings = parse_scan_execution(execution, target, plugin_dir)
        if not hosts and not skip_host_discovery:
            logger.info("No hosts discovered. Retrying scan with host discovery disabled (-Pn).")
            fallback_execution = run_nmap(
                target,
                mode if mode != "azure" else "quick",
                extra_args=extra_nmap_args,
                skip_host_discovery=True,
            )
            nmap_command = fallback_execution.command
            raw_xml = fallback_execution.stdout
            hosts, findings = parse_scan_execution(fallback_execution, target, plugin_dir)
    except (DiscoveryError, NmapParseError, ValueError) as exc:
        logger.exception("Scan failed")
        errors.append(str(exc))

    return hosts, findings, errors, nmap_command, raw_xml


def apply_cloud_checks(
    findings: list[Finding],
    mode: str,
    enable_aws_checks: bool,
    enable_azure_checks: bool,
    enable_gcp_checks: bool,
    aws_region: str | None,
    azure_subscription_id: str | None,
    gcp_project_id: str | None,
) -> list[Finding]:
    final_findings = list(findings)
    if mode == "aws" or enable_aws_checks:
        final_findings.extend(run_aws_checks(aws_region))
    if mode == "azure" or enable_azure_checks:
        final_findings.extend(run_azure_checks(azure_subscription_id))
    if mode == "gcp" or enable_gcp_checks:
        final_findings.extend(run_gcp_checks(gcp_project_id))
    return final_findings


def filter_findings(findings: list[Finding], ignored_ids: set[str]) -> list[Finding]:
    if not ignored_ids:
        return findings
    return [finding for finding in findings if finding.id not in ignored_ids]


def resolve_scan_config(args: argparse.Namespace) -> ScanConfig:
    config = load_scan_config(args.config)
    config.profile = merge_scan_config(args.profile, config.profile)
    config.ports = merge_scan_config(args.ports, config.ports)
    config.udp_ports = merge_scan_config(args.udp_ports, config.udp_ports)
    config.udp_top_ports = merge_scan_config(args.udp_top_ports, config.udp_top_ports)
    config.nse_scripts = list(args.nse_script or config.nse_scripts)
    config.nse_categories = list(args.nse_category or config.nse_categories)
    config.parallelism = merge_scan_config(args.parallelism, config.parallelism)
    config.skip_host_discovery = bool(args.skip_host_discovery or config.skip_host_discovery)
    config.save_raw_xml = bool(args.save_raw_xml or config.save_raw_xml)
    config.save_history = bool(args.save_history or config.save_history)
    config.history_dir = merge_scan_config(args.history_dir, config.history_dir)
    config.suppressions_path = merge_scan_config(args.suppressions, config.suppressions_path)
    config.enable_aws_checks = bool(args.enable_aws_checks or args.mode == "aws" or config.enable_aws_checks)
    config.enable_azure_checks = bool(args.enable_azure_checks or args.mode == "azure" or config.enable_azure_checks)
    config.enable_gcp_checks = bool(args.enable_gcp_checks or args.mode == "gcp" or config.enable_gcp_checks)
    config.plugin_dir = merge_scan_config(args.plugin_dir, config.plugin_dir)
    config.browser_assisted = bool(args.browser_assisted or config.browser_assisted)
    config.browser_max_pages = merge_scan_config(args.browser_max_pages, config.browser_max_pages)
    config.browser_timeout_ms = merge_scan_config(args.browser_timeout_ms, config.browser_timeout_ms)
    config.ignore_ids.update(args.ignore_id or [])
    return apply_profile(config, config.profile)


def run_scan(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    scan_config = resolve_scan_config(args)
    result, paths, history_path = _run_scan_for_target(args, scan_config, args.target)
    json_path, html_path, xml_path, markdown_path, csv_path, sarif_path = paths
    print_summary(
        result,
        json_path,
        html_path,
        xml_path if scan_config.save_raw_xml else None,
        markdown_path,
        csv_path,
        sarif_path,
        history_path,
    )
    return 1 if result.errors else 0


def run_compare(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    diff = compare_reports(load_report(args.old_report), load_report(args.new_report))
    output_path = Path(args.output)
    write_diff_json(diff, output_path)
    print(f"New findings: {len(diff.new_findings)}")
    print(f"Resolved findings: {len(diff.resolved_findings)}")
    print(f"Diff report written to: {output_path}")
    return 0


def _run_scan_for_target(
    args: argparse.Namespace,
    scan_config: ScanConfig,
    target: str,
) -> tuple[ScanResult, tuple[Path, Path, Path, Path | None, Path | None, Path | None], Path | None]:
    resolved_target, inferred_scheme = infer_scan_target(target)
    configure_browser_assistance(
        enabled=bool(scan_config.browser_assisted and args.mode == "web"),
        max_pages=scan_config.browser_max_pages,
        timeout_ms=scan_config.browser_timeout_ms,
    )
    json_path, html_path, xml_path, markdown_path, csv_path, sarif_path = build_report_paths(args, target_override=target)
    start_clock = perf_counter()
    started_at = utc_now_iso()
    extra_nmap_args = build_extra_nmap_args(
        scan_config.ports,
        scan_config.udp_ports,
        scan_config.udp_top_ports,
        scan_config.nse_scripts,
        scan_config.nse_categories,
        scan_config.parallelism,
    )
    hosts, findings, errors, nmap_command, raw_xml = execute_scan(
        resolved_target,
        args.mode,
        extra_nmap_args=extra_nmap_args,
        skip_host_discovery=scan_config.skip_host_discovery,
        plugin_dir=scan_config.plugin_dir,
    )
    findings = apply_cloud_checks(
        findings,
        args.mode,
        scan_config.enable_aws_checks,
        scan_config.enable_azure_checks,
        scan_config.enable_gcp_checks,
        getattr(args, "aws_region", None),
        getattr(args, "azure_subscription_id", None),
        getattr(args, "gcp_project_id", None),
    )
    findings.extend(run_linux_ssh_checks(hosts, _build_ssh_auth_config(args)))
    findings.extend(run_windows_host_checks(hosts, _build_winrm_auth_config(args)))
    findings = filter_findings(findings, scan_config.ignore_ids)
    findings = apply_suppressions(findings, load_suppression_rules(scan_config.suppressions_path))

    if inferred_scheme == "https" and args.mode == "quick":
        logger.info("URL target inferred as HTTPS; consider web mode for stronger web checks.")

    result = ScanResult(
        metadata=ScanMetadata(
            target=target,
            scan_mode=args.mode,
            started_at=started_at,
            ended_at=utc_now_iso(),
            duration_seconds=round(perf_counter() - start_clock, 2),
            nmap_command=nmap_command,
        ),
        hosts=hosts,
        findings=findings,
        errors=errors,
    )
    write_json_report(result, json_path)
    write_html_report(result, html_path)
    if markdown_path:
        write_markdown_report(result, markdown_path)
    if csv_path:
        write_csv_report(result, csv_path)
    if sarif_path:
        write_sarif_report(result, sarif_path)
    if scan_config.save_raw_xml and raw_xml:
        xml_path.write_text(raw_xml, encoding="utf-8")
    history_path = store_scan_history(result, json_path, scan_config.history_dir) if scan_config.save_history else None
    return result, (json_path, html_path, xml_path, markdown_path, csv_path, sarif_path), history_path


def run_baseline(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    if args.baseline_command == "create":
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(Path(args.report).read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Baseline written to: {output_path}")
        return 0

    diff = compare_reports(load_report(args.baseline), load_report(args.report))
    output_path = Path(args.output)
    write_diff_json(diff, output_path)
    print(f"New findings against baseline: {len(diff.new_findings)}")
    print(f"Resolved findings against baseline: {len(diff.resolved_findings)}")
    print(f"Baseline diff: {output_path}")
    return 0


def run_batch(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    targets = _load_batch_targets(args.targets, args.targets_file)
    if not targets:
        raise ValueError("No targets were provided for batch scanning.")
    scan_config = resolve_scan_config(args)
    reports: list[dict] = []
    error_count = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(_run_scan_for_target, args, scan_config, target): target for target in targets}
        for future in as_completed(futures):
            target = futures[future]
            result, paths, history_path = future.result()
            reports.append(result.to_dict())
            json_path, html_path, xml_path, markdown_path, csv_path, sarif_path = paths
            print_summary(
                result,
                json_path,
                html_path,
                xml_path if scan_config.save_raw_xml else None,
                markdown_path,
                csv_path,
                sarif_path,
                history_path,
            )
            if result.errors:
                error_count += 1

    dashboard = build_dashboard(reports)
    dashboard_dir = ensure_output_dir(args.output_dir, args.timestamped_dir)
    dashboard_json = dashboard_dir / f"batch-dashboard-{utc_timestamp()}.json"
    dashboard_html = dashboard_dir / f"batch-dashboard-{utc_timestamp()}.html"
    dashboard_json.write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    write_dashboard_html(dashboard, dashboard_html)
    print(f"Batch dashboard JSON: {dashboard_json}")
    print(f"Batch dashboard HTML: {dashboard_html}")
    return 1 if error_count else 0


def run_dashboard(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    reports = [load_report(path) for path in args.reports]
    if args.history_dir:
        reports.extend(load_history_reports(args.history_dir))
    if not reports:
        raise ValueError("No reports were provided. Supply report paths or --history-dir.")
    dashboard = build_dashboard(reports)
    json_output = Path(args.json_output)
    html_output = Path(args.html_output)
    json_output.write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    write_dashboard_html(dashboard, html_output)
    print(f"Dashboard reports aggregated: {dashboard['scan_count']}")
    print(f"Dashboard targets: {dashboard['target_count']}")
    print(f"Dashboard severity score: {dashboard['severity_score']}")
    print(f"Dashboard JSON: {json_output}")
    print(f"Dashboard HTML: {html_output}")
    return 0


def run_schedule(args: argparse.Namespace) -> int:
    configure_logging(args.verbose)
    command = _build_schedule_command(args)
    schedule_text = _render_schedule(args.format, command)
    print(schedule_text)
    return 0


def print_summary(
    result: ScanResult,
    json_path: Path,
    html_path: Path,
    xml_path: Path | None = None,
    markdown_path: Path | None = None,
    csv_path: Path | None = None,
    sarif_path: Path | None = None,
    history_path: Path | None = None,
) -> None:
    totals = result.severity_totals()
    print(f"Target: {result.metadata.target}")
    print(f"Mode: {result.metadata.scan_mode}")
    print(f"Duration: {result.metadata.duration_seconds}s")
    print(f"Hosts discovered: {len(result.hosts)}")
    print(f"Severity score: {result.severity_score()}")
    print("Severity summary:")
    for severity, count in totals.items():
        print(f"  {color_text(severity.upper(), severity)}: {count}")
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")
    if xml_path:
        print(f"Raw XML: {xml_path}")
    if markdown_path:
        print(f"Markdown report: {markdown_path}")
    if csv_path:
        print(f"CSV report: {csv_path}")
    if sarif_path:
        print(f"SARIF report: {sarif_path}")
    if history_path:
        print(f"History copy: {history_path}")
    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"  - {error}")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv:
        if sys.stdin.isatty() and sys.stdout.isatty():
            interactive_args = run_interactive_menu()
            if interactive_args is None:
                return 0
            argv = interactive_args
        else:
            parser.print_help()
            return 2
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "batch":
        return run_batch(args)
    if args.command == "compare":
        return run_compare(args)
    if args.command == "baseline":
        return run_baseline(args)
    if args.command == "dashboard":
        return run_dashboard(args)
    if args.command == "schedule":
        return run_schedule(args)
    parser.error("Unknown command")
    return 2


def _build_ssh_auth_config(args: argparse.Namespace) -> SSHAuthConfig | None:
    ssh_user = getattr(args, "ssh_user", None)
    if not ssh_user:
        return None
    return SSHAuthConfig(
        username=ssh_user,
        password=getattr(args, "ssh_password", None),
        key_path=getattr(args, "ssh_key_path", None),
    )


def _build_winrm_auth_config(args: argparse.Namespace) -> WinRMAuthConfig | None:
    winrm_user = getattr(args, "winrm_user", None)
    winrm_password = getattr(args, "winrm_password", None)
    if not winrm_user or not winrm_password:
        return None
    return WinRMAuthConfig(
        username=winrm_user,
        password=winrm_password,
        port=getattr(args, "winrm_port", 5985),
        use_ssl=getattr(args, "winrm_ssl", False),
        transport=getattr(args, "winrm_transport", "ntlm"),
    )


def _load_batch_targets(targets: list[str], targets_file: str | None) -> list[str]:
    batch_targets = list(targets)
    if targets_file:
        file_targets = [
            line.strip()
            for line in Path(targets_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        batch_targets.extend(file_targets)
    deduplicated: list[str] = []
    seen: set[str] = set()
    for target in batch_targets:
        if target in seen:
            continue
        seen.add(target)
        deduplicated.append(target)
    return deduplicated


def _build_schedule_command(args: argparse.Namespace) -> str:
    parts = [
        "accuscanner",
        "scan",
        args.target,
        "--mode",
        args.mode,
        "--output-dir",
        args.output_dir,
    ]
    if args.timestamped_dir:
        parts.append("--timestamped-dir")
    for option, value in (
        ("--ports", args.ports),
        ("--udp-ports", args.udp_ports),
        ("--udp-top-ports", args.udp_top_ports),
    ):
        if value:
            parts.extend([option, str(value)])
    for script in args.nse_script or []:
        parts.extend(["--nse-script", script])
    for category in args.nse_category or []:
        parts.extend(["--nse-category", category])
    if args.enable_aws_checks:
        parts.append("--enable-aws-checks")
    if args.enable_azure_checks:
        parts.append("--enable-azure-checks")
    if args.enable_gcp_checks:
        parts.append("--enable-gcp-checks")
    if args.gcp_project_id:
        parts.extend(["--gcp-project-id", args.gcp_project_id])
    return " ".join(parts)


def _render_schedule(schedule_format: str, command: str) -> str:
    if schedule_format == "cron":
        return f"0 2 * * * {command}"
    if schedule_format == "systemd":
        return (
            "[Unit]\nDescription=AccuScanner scheduled scan\n\n"
            "[Service]\nType=oneshot\n"
            f"ExecStart={command}\n\n"
            "[Install]\nWantedBy=multi-user.target"
        )
    return (
        'schtasks /Create /SC DAILY /ST 02:00 /TN "AccuScanner Scan" '
        f'/TR "{command}"'
    )

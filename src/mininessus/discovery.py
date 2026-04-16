from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from .utils import LOGGER_NAME


logger = logging.getLogger(LOGGER_NAME)


SCAN_MODE_ARGS: dict[str, list[str]] = {
    "quick": ["-T4", "-F", "-sV"],
    "full": ["-T4", "-p-", "-sV", "-sC"],
    "web": ["-T4", "-p", "80,443,8080,8443", "-sV", "--script", "http-title"],
    "aws": ["-T4", "-F", "-sV"],
}


@dataclass(slots=True)
class NmapExecution:
    command: list[str]
    stdout: str
    stderr: str
    returncode: int


class DiscoveryError(RuntimeError):
    """Raised when nmap execution fails."""


def ensure_nmap_installed() -> None:
    nmap_path = os.getenv("NMAP_PATH") or shutil.which("nmap")
    if nmap_path is None:
        raise DiscoveryError("nmap is not installed or not available in PATH.")


def build_nmap_command(target: str, scan_mode: str, skip_host_discovery: bool = False) -> list[str]:
    try:
        mode_args = SCAN_MODE_ARGS[scan_mode]
    except KeyError as exc:
        raise DiscoveryError(f"Unsupported scan mode: {scan_mode}") from exc
    discovery_args = ["-Pn"] if skip_host_discovery else []
    return ["nmap", "-oX", "-", *discovery_args, *mode_args, target]


def run_nmap(
    target: str,
    scan_mode: str,
    extra_args: Sequence[str] | None = None,
    skip_host_discovery: bool = False,
) -> NmapExecution:
    ensure_nmap_installed()
    command = build_nmap_command(target, scan_mode, skip_host_discovery=skip_host_discovery)
    if extra_args:
        command.extend(extra_args)
    command = _normalize_nmap_command(command)
    logger.info("Running nmap command: %s", " ".join(command))
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise DiscoveryError(completed.stderr.strip() or "nmap execution failed")
    return NmapExecution(command=command, stdout=completed.stdout, stderr=completed.stderr, returncode=completed.returncode)


def build_extra_nmap_args(
    ports: str | None = None,
    udp_ports: str | None = None,
    udp_top_ports: int | None = None,
    nse_scripts: Sequence[str] | None = None,
    nse_categories: Sequence[str] | None = None,
    parallelism: int | None = None,
) -> list[str]:
    extra_args: list[str] = []
    port_argument = _build_port_argument(ports, udp_ports)
    if port_argument:
        extra_args.extend(["-p", port_argument])
    include_udp_scan = bool(udp_ports or udp_top_ports)
    if include_udp_scan:
        extra_args.append("-sU")
    if include_udp_scan and _includes_tcp_ports(ports, udp_ports):
        extra_args.append("-sS")
    if udp_top_ports:
        extra_args.extend(["--top-ports", str(udp_top_ports)])
    script_arguments = [value for value in [*(nse_categories or []), *(nse_scripts or [])] if value]
    if script_arguments:
        extra_args.extend(["--script", ",".join(script_arguments)])
    if parallelism:
        extra_args.extend(["--min-parallelism", str(parallelism)])
    return extra_args


def _build_port_argument(tcp_ports: str | None, udp_ports: str | None) -> str | None:
    if tcp_ports and udp_ports:
        return f"T:{tcp_ports},U:{udp_ports}"
    if udp_ports:
        return f"U:{udp_ports}"
    return tcp_ports


def _includes_tcp_ports(tcp_ports: str | None, udp_ports: str | None) -> bool:
    """Return True when the scan should include TCP probes alongside UDP."""

    return bool(tcp_ports or not udp_ports)


def _normalize_nmap_command(command: list[str]) -> list[str]:
    """Remove incompatible nmap switches when richer profile options are present."""

    if "-F" in command and "-p" in command:
        command = [part for part in command if part != "-F"]
    return command

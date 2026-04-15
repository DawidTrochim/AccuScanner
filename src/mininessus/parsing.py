from __future__ import annotations

import xml.etree.ElementTree as ET

from .models import HostResult, PortService


class NmapParseError(ValueError):
    """Raised when nmap XML cannot be parsed."""


def parse_nmap_xml(xml_output: str) -> list[HostResult]:
    """Parse nmap XML output into host and service objects."""

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise NmapParseError(f"Failed to parse nmap XML: {exc}") from exc

    return [host for node in root.findall("host") if (host := _parse_host(node)) is not None]


def _parse_host(host_node: ET.Element) -> HostResult | None:
    address_node = host_node.find("address")
    if address_node is None:
        return None

    hostname_node = host_node.find("hostnames/hostname")
    status_node = host_node.find("status")
    host = HostResult(
        address=address_node.attrib.get("addr", "unknown"),
        hostname=hostname_node.attrib.get("name") if hostname_node is not None else None,
        status=status_node.attrib.get("state", "unknown") if status_node is not None else "unknown",
        ports=[_parse_port(port_node) for port_node in host_node.findall("ports/port")],
        os_matches=[node.attrib.get("name", "") for node in host_node.findall("os/osmatch")],
    )
    return host


def _parse_port(port_node: ET.Element) -> PortService:
    state_node = port_node.find("state")
    service_node = port_node.find("service")
    script_output = [script.attrib.get("output", "") for script in port_node.findall("script")]

    return PortService(
        port=int(port_node.attrib.get("portid", 0)),
        protocol=port_node.attrib.get("protocol", "tcp"),
        state=state_node.attrib.get("state", "unknown") if state_node is not None else "unknown",
        service=service_node.attrib.get("name") if service_node is not None else None,
        product=service_node.attrib.get("product") if service_node is not None else None,
        version=service_node.attrib.get("version") if service_node is not None else None,
        extrainfo=service_node.attrib.get("extrainfo") if service_node is not None else None,
        tunnel=service_node.attrib.get("tunnel") if service_node is not None else None,
        banner=" | ".join(filter(None, script_output)) or None,
    )

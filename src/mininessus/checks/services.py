from __future__ import annotations

import ftplib
import socket
import ssl
from collections.abc import Iterable

from .base import BaseCheck
from ..models import Finding, HostResult


EXPOSED_SERVICE_RULES = {
    139: ("SMB service exposed", "medium", "File-sharing services should not be broadly exposed."),
    445: ("SMB service exposed", "medium", "File-sharing services should not be broadly exposed."),
    3389: ("RDP service exposed", "medium", "Remote desktop services should be restricted to trusted management networks."),
    5985: ("WinRM service exposed", "medium", "Windows remote management should not be broadly exposed to untrusted networks."),
    5986: ("WinRM over HTTPS exposed", "medium", "Windows remote management should be limited to trusted administrative paths."),
    11211: ("Memcached service exposed", "high", "Memcached is frequently abused when exposed to untrusted networks."),
    2375: ("Docker daemon exposed", "critical", "Unauthenticated Docker API exposure can allow full host takeover."),
    2379: ("etcd service exposed", "critical", "Exposed etcd can leak cluster secrets and control-plane state."),
    27017: ("MongoDB service exposed", "high", "Exposed databases can disclose data or be abused without strong access controls."),
    6379: ("Redis service exposed", "high", "Redis should not be internet-facing without strict network controls."),
    6443: ("Kubernetes API exposed", "high", "Kubernetes control-plane services should be restricted to trusted administrative networks."),
    10250: ("Kubelet API exposed", "high", "The kubelet API can expose workload metadata and cluster control surfaces."),
    9200: ("Elasticsearch service exposed", "high", "Exposed search clusters can leak indexed data and administrative APIs."),
    161: ("SNMP service exposed", "medium", "Exposed SNMP services can leak system inventory and configuration data."),
    25: ("SMTP service exposed", "low", "Mail services should be reviewed to confirm they are intentionally reachable."),
}


class ServiceExposureCheck(BaseCheck):
    name = "service_exposure"

    def run(self, hosts: list[HostResult], target: str) -> Iterable[Finding]:
        findings: list[Finding] = []
        for host in hosts:
            open_ports = {port.port for port in host.ports if port.state == "open"}
            for port in (port for port in host.ports if port.state == "open"):
                findings.extend(self._build_exposure_findings(host.address, port))
            findings.extend(self._check_anonymous_ftp(host))
            findings.extend(self._run_service_access_checks(host.address, open_ports))
        return findings

    def _build_exposure_findings(self, target: str, port) -> list[Finding]:
        rule = EXPOSED_SERVICE_RULES.get(port.port)
        if not rule:
            return []
        title, severity, description = rule
        return [
            self.finding(
                finding_id=f"SVC-{port.port}",
                title=title,
                severity=severity,
                category="service_exposure",
                target=target,
                description=description,
                evidence=f"Open port {port.port}/{port.protocol} detected ({port.display_name}).",
                recommendation="Restrict exposure to trusted networks and require strong authentication where supported.",
                confidence="high",
                tags=["network", "service"],
            )
        ]

    def _run_service_access_checks(self, host: str, open_ports: set[int]) -> list[Finding]:
        findings: list[Finding] = []
        if 6379 in open_ports:
            findings.extend(self._check_redis(host))
        if 2375 in open_ports:
            findings.extend(self._check_docker_api(host))
        if 9200 in open_ports:
            findings.extend(self._check_elasticsearch(host))
        if 27017 in open_ports:
            findings.extend(self._check_mongodb(host))
        if 445 in open_ports:
            findings.extend(self._check_smb_signing(host))
        if 5985 in open_ports or 5986 in open_ports:
            findings.extend(self._check_winrm_listener(host, open_ports))
        if 3389 in open_ports:
            findings.extend(self._check_rdp_listener(host))
        if 6443 in open_ports:
            findings.extend(self._check_kubernetes_api(host))
        if 10250 in open_ports:
            findings.extend(self._check_kubelet_api(host))
        if 2379 in open_ports:
            findings.extend(self._check_etcd_api(host))
        return findings


    def _check_anonymous_ftp(self, host: HostResult) -> list[Finding]:
        if 21 not in {port.port for port in host.ports if port.state == "open"}:
            return []

        try:
            with ftplib.FTP() as ftp:
                ftp.connect(host.address, 21, timeout=4)
                ftp.login()
                welcome = ftp.getwelcome() or "Anonymous FTP login succeeded."
        except (OSError, ftplib.Error, EOFError):
            return []

        return [
            self.finding(
                finding_id="FTP-001",
                title="Anonymous FTP login allowed",
                severity="high",
                category="service_access",
                target=host.address,
                description="The FTP service accepted an anonymous login.",
                evidence=welcome,
                recommendation="Disable anonymous FTP access unless it is explicitly intended and tightly scoped.",
                confidence="high",
                tags=["network", "ftp", "auth"],
            )
        ]

    def _check_redis(self, host: str) -> list[Finding]:
        response = _send_tcp_payload(host, 6379, b"*1\r\n$4\r\nPING\r\n")
        if response and b"+PONG" in response:
            return [
                self.finding(
                    finding_id="REDIS-001",
                    title="Redis responds without authentication",
                    severity="high",
                    category="service_access",
                    target=host,
                    description="The Redis service responded successfully to an unauthenticated PING request.",
                    evidence=response.decode("utf-8", errors="replace").strip(),
                    recommendation="Require authentication and restrict Redis to trusted networks only.",
                    confidence="high",
                    tags=["network", "redis", "auth"],
                )
            ]
        return []

    def _check_docker_api(self, host: str) -> list[Finding]:
        response = _send_http_request(host, 2375, b"GET /version HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        if response and b"ApiVersion" in response:
            return [
                self.finding(
                    finding_id="DOCKER-001",
                    title="Docker API responded without authentication",
                    severity="critical",
                    category="service_access",
                    target=host,
                    description="The Docker Remote API returned version information over an unauthenticated connection.",
                    evidence=response.decode("utf-8", errors="replace")[:300],
                    recommendation="Disable the unauthenticated Docker TCP listener or restrict it to a trusted administrative network.",
                    confidence="high",
                    tags=["network", "docker", "auth"],
                )
            ]
        return []

    def _check_elasticsearch(self, host: str) -> list[Finding]:
        response = _send_http_request(host, 9200, b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        if response and b"cluster_name" in response:
            return [
                self.finding(
                    finding_id="ES-001",
                    title="Elasticsearch responded without authentication",
                    severity="high",
                    category="service_access",
                    target=host,
                    description="The Elasticsearch HTTP interface returned cluster metadata over an unauthenticated connection.",
                    evidence=response.decode("utf-8", errors="replace")[:300],
                    recommendation="Require authentication and restrict Elasticsearch to trusted networks only.",
                    confidence="high",
                    tags=["network", "elasticsearch", "auth"],
                )
            ]
        return []

    def _check_mongodb(self, host: str) -> list[Finding]:
        response = _send_tcp_payload(host, 27017, b"\x3a\x00\x00\x00\xa7\x41\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00")
        if response:
            return [
                self.finding(
                    finding_id="MONGO-001",
                    title="MongoDB responded to unauthenticated probe",
                    severity="high",
                    category="service_access",
                    target=host,
                    description="The MongoDB service responded to an unauthenticated wire protocol probe.",
                    evidence=f"Received {len(response)} bytes from MongoDB service.",
                    recommendation="Restrict MongoDB to trusted networks and require authentication.",
                    confidence="medium",
                    tags=["network", "mongodb", "auth"],
                )
            ]
        return []

    def _check_smb_signing(self, host: str) -> list[Finding]:
        response = _send_tcp_payload(host, 445, b"\x00")
        if not response:
            return []
        return [
            self.finding(
                finding_id="SMB-001",
                title="SMB service responded to unauthenticated probe",
                severity="medium",
                category="service_access",
                target=host,
                description="The SMB service responded to an unauthenticated network probe and should be reviewed for exposure and signing requirements.",
                evidence=f"Received {len(response)} bytes from TCP/445.",
                recommendation="Restrict SMB to trusted networks and enforce SMB signing where supported.",
                confidence="low",
                tags=["network", "smb", "windows"],
            )
        ]

    def _check_winrm_listener(self, host: str, open_ports: set[int]) -> list[Finding]:
        findings: list[Finding] = []
        if 5985 in open_ports:
            response = _send_http_request(host, 5985, b"POST /wsman HTTP/1.1\r\nHost: target\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            if response and b"WSMan" in response:
                findings.append(
                    self.finding(
                        finding_id="WINRM-009",
                        title="WinRM listener responded over HTTP",
                        severity="medium",
                        category="service_access",
                        target=host,
                        description="The WinRM listener responded over plaintext HTTP.",
                        evidence=response.decode("utf-8", errors="replace")[:300],
                        recommendation="Prefer WinRM over HTTPS and restrict management access to trusted administrative paths.",
                        confidence="medium",
                        tags=["network", "winrm", "windows"],
                    )
                )
        if 5986 in open_ports:
            response = _send_https_request(host, 5986, b"POST /wsman HTTP/1.1\r\nHost: target\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            if response and b"WSMan" in response:
                findings.append(
                    self.finding(
                        finding_id="WINRM-010",
                        title="WinRM over HTTPS listener detected",
                        severity="low",
                        category="service_access",
                        target=host,
                        description="The WinRM HTTPS listener is reachable and should be limited to trusted administrative networks.",
                        evidence=response.decode("utf-8", errors="replace")[:300],
                        recommendation="Restrict WinRM over HTTPS to approved management sources and validate certificate trust.",
                        confidence="medium",
                        tags=["network", "winrm", "windows"],
                    )
                )
        return findings

    def _check_rdp_listener(self, host: str) -> list[Finding]:
        response = _send_tcp_payload(host, 3389, b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00")
        if not response:
            return []
        return [
            self.finding(
                finding_id="RDP-001",
                title="RDP listener responded to network handshake",
                severity="medium",
                category="service_access",
                target=host,
                description="The RDP service completed an initial handshake and is reachable from the scanning network.",
                evidence=f"Received {len(response)} bytes from the RDP listener.",
                recommendation="Restrict RDP to trusted management networks and enforce MFA, NLA, and strong account controls.",
                confidence="medium",
                tags=["network", "rdp", "windows"],
            )
        ]

    def _check_kubernetes_api(self, host: str) -> list[Finding]:
        response = _send_https_request(host, 6443, b"GET /version HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        if response and b"gitVersion" in response:
            return [
                self.finding(
                    finding_id="K8S-001",
                    title="Kubernetes API returned version data",
                    severity="high",
                    category="service_access",
                    target=host,
                    description="The Kubernetes API server returned version metadata over the network.",
                    evidence=response.decode("utf-8", errors="replace")[:300],
                    recommendation="Restrict Kubernetes API exposure to trusted administrative networks and require strong authentication.",
                    confidence="high",
                    tags=["network", "kubernetes", "api"],
                )
            ]
        return []

    def _check_kubelet_api(self, host: str) -> list[Finding]:
        response = _send_https_request(host, 10250, b"GET /pods HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        if response and (b"pods" in response.lower() or b"unauthorized" in response.lower()):
            return [
                self.finding(
                    finding_id="K8S-002",
                    title="Kubelet API responded on the network",
                    severity="high",
                    category="service_access",
                    target=host,
                    description="The kubelet API responded to an unauthenticated network request.",
                    evidence=response.decode("utf-8", errors="replace")[:300],
                    recommendation="Restrict kubelet access to cluster management paths only and review authentication and authorization settings.",
                    confidence="medium",
                    tags=["network", "kubernetes", "kubelet"],
                )
            ]
        return []

    def _check_etcd_api(self, host: str) -> list[Finding]:
        response = _send_http_request(host, 2379, b"GET /version HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        if response and b"etcdserver" in response.lower():
            return [
                self.finding(
                    finding_id="K8S-003",
                    title="etcd API returned version data",
                    severity="critical",
                    category="service_access",
                    target=host,
                    description="The etcd API returned version metadata over the network.",
                    evidence=response.decode("utf-8", errors="replace")[:300],
                    recommendation="Remove direct etcd exposure, restrict access to trusted control-plane nodes, and rotate any exposed cluster secrets if required.",
                    confidence="high",
                    tags=["network", "kubernetes", "etcd"],
                )
            ]
        return []


def _send_tcp_payload(host: str, port: int, payload: bytes, timeout: int = 3) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
            return sock.recv(2048)
    except OSError:
        return b""


def _send_http_request(host: str, port: int, payload: bytes, timeout: int = 3) -> bytes:
    return _send_tcp_payload(host, port, payload, timeout=timeout)


def _send_https_request(host: str, port: int, payload: bytes, timeout: int = 3) -> bytes:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(payload)
                return tls_sock.recv(2048)
    except OSError:
        return b""

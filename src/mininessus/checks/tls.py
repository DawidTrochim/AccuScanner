from __future__ import annotations

import socket
import ssl
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address

from .base import BaseCheck
from .http import fetch_http_observation
from ..models import Finding, HostResult
from ..utils import sanitize_target


TLS_PORTS = {443, 8443}
LEGACY_TLS_VERSIONS = {"TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "MD5", "NULL")


@dataclass(slots=True)
class TLSDetails:
    not_after: str | None
    subject_cn: str | None
    issuer_cn: str | None
    self_signed: bool
    tls_version: str | None
    cipher: str | None
    san_dns_names: list[str]
    validation_error: str | None = None


def inspect_tls_certificate(hostname: str, port: int = 443, timeout: int = 5) -> TLSDetails:
    permissive_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    permissive_context.check_hostname = False
    permissive_context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with permissive_context.wrap_socket(sock, server_hostname=hostname) as wrapped:
            cert_pem = ssl.DER_cert_to_PEM_cert(wrapped.getpeercert(binary_form=True))
            cipher = wrapped.cipher()
            tls_version = wrapped.version()

    decoded_cert = _decode_pem_certificate(cert_pem)
    subject_cn = _extract_name(decoded_cert.get("subject", []), "commonName")
    issuer_cn = _extract_name(decoded_cert.get("issuer", []), "commonName")
    san_dns_names = [value for name, value in decoded_cert.get("subjectAltName", []) if name == "DNS"]

    validation_error = _validate_certificate_chain(hostname, port, timeout)
    return TLSDetails(
        not_after=decoded_cert.get("notAfter"),
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        self_signed=bool(subject_cn and issuer_cn and subject_cn == issuer_cn),
        tls_version=tls_version,
        cipher=cipher[0] if cipher else None,
        san_dns_names=san_dns_names,
        validation_error=validation_error,
    )


def _decode_pem_certificate(cert_pem: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as handle:
        handle.write(cert_pem)
        handle.flush()
        return ssl._ssl._test_decode_cert(handle.name)


def _extract_name(name_blocks: list[tuple[tuple[str, str], ...]], key: str) -> str | None:
    for block in name_blocks:
        for name, value in block:
            if name == key:
                return value
    return None


def _validate_certificate_chain(hostname: str, port: int, timeout: int) -> str | None:
    validating_context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with validating_context.wrap_socket(sock, server_hostname=hostname):
                return None
    except ssl.SSLCertVerificationError as exc:
        return str(exc)
    except ssl.SSLError:
        return None


def _matches_hostname(hostname: str, details: TLSDetails) -> bool:
    candidates = details.san_dns_names or ([details.subject_cn] if details.subject_cn else [])
    return any(_dns_name_matches(hostname, candidate) for candidate in candidates)


def _dns_name_matches(hostname: str, pattern: str | None) -> bool:
    if not pattern:
        return False

    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if hostname == pattern:
        return True
    if not pattern.startswith("*."):
        return False

    suffix = pattern[2:]
    hostname_labels = hostname.split(".")
    suffix_labels = suffix.split(".")
    if len(hostname_labels) != len(suffix_labels) + 1:
        return False
    return hostname.endswith(f".{suffix}")


class TlsCertificateCheck(BaseCheck):
    name = "tls_certificate"

    def run(self, hosts: list[HostResult], target: str) -> Iterable[Finding]:
        findings: list[Finding] = []
        for host in hosts:
            tls_ports = [port.port for port in host.ports if port.state == "open" and port.port in TLS_PORTS]
            if not tls_ports:
                continue

            port = 443 if 443 in tls_ports else tls_ports[0]
            server_name = self._server_name(target, host)
            try:
                details = inspect_tls_certificate(server_name, port=port)
            except OSError as exc:
                if self._https_fetch_succeeded(server_name, port):
                    continue
                findings.append(
                    self.finding(
                        finding_id="TLS-004",
                        title="TLS inspection failed",
                        severity="info",
                        category="tls",
                        target=server_name,
                        description="The TLS service was detected but certificate inspection did not complete.",
                        evidence=str(exc),
                        recommendation="Validate TLS reachability manually and confirm certificate health.",
                    )
                )
                continue

            findings.extend(self._build_certificate_findings(server_name, server_name, details))
        return findings

    @staticmethod
    def _https_fetch_succeeded(server_name: str, port: int) -> bool:
        default_port = 443
        url = f"https://{server_name}" if port == default_port else f"https://{server_name}:{port}"
        for method in ("HEAD", "GET"):
            observation = fetch_http_observation(url, timeout=5, method=method)
            if observation.status is not None and observation.status < 500:
                return True
        return False

    @staticmethod
    def _server_name(target: str, host: HostResult) -> str:
        requested_target = sanitize_target(target)
        if requested_target and TlsCertificateCheck._looks_like_hostname(requested_target):
            return requested_target
        return host.address

    @staticmethod
    def _looks_like_hostname(value: str) -> bool:
        try:
            ip_address(value)
        except ValueError:
            return True
        return False

    def _build_certificate_findings(self, target: str, hostname: str, details: TLSDetails) -> list[Finding]:
        findings: list[Finding] = []
        expiry = _parse_not_after(details.not_after)

        if expiry and expiry < datetime.now(UTC):
            findings.append(
                self.finding(
                    finding_id="TLS-001",
                    title="Expired TLS certificate",
                    severity="high",
                    category="tls",
                    target=target,
                    description="The presented TLS certificate has expired.",
                    evidence=f"Certificate expired at {expiry.isoformat()}",
                    recommendation="Replace the certificate and renew it before expiry.",
                )
            )
        elif expiry and (expiry - datetime.now(UTC)).days <= 30:
            findings.append(
                self.finding(
                    finding_id="TLS-005",
                    title="TLS certificate expiring soon",
                    severity="medium",
                    category="tls",
                    target=target,
                    description="The presented TLS certificate expires soon.",
                    evidence=f"Certificate expires at {expiry.isoformat()}",
                    recommendation="Schedule certificate renewal before the certificate reaches expiry.",
                )
            )

        if details.self_signed:
            findings.append(
                self.finding(
                    finding_id="TLS-002",
                    title="Self-signed TLS certificate",
                    severity="medium",
                    category="tls",
                    target=target,
                    description="The certificate issuer and subject match, suggesting a self-signed certificate.",
                    evidence=f"Subject CN: {details.subject_cn}, Issuer CN: {details.issuer_cn}",
                    recommendation="Use a certificate from a trusted internal or public CA where appropriate.",
                )
            )

        if details.tls_version in LEGACY_TLS_VERSIONS or not details.tls_version:
            findings.append(
                self.finding(
                    finding_id="TLS-003",
                    title="Weak or missing TLS details",
                    severity="medium",
                    category="tls",
                    target=target,
                    description="The endpoint negotiated an outdated TLS version or TLS metadata could not be confirmed.",
                    evidence=f"TLS version: {details.tls_version}, cipher: {details.cipher}",
                    recommendation="Disable legacy protocols and prefer TLS 1.2+ with modern cipher suites.",
                )
            )

        if details.cipher and any(marker in details.cipher.upper() for marker in WEAK_CIPHER_MARKERS):
            findings.append(
                self.finding(
                    finding_id="TLS-006",
                    title="Weak TLS cipher observed",
                    severity="medium",
                    category="tls",
                    target=target,
                    description="The endpoint negotiated a cipher that is generally considered weak.",
                    evidence=f"Cipher: {details.cipher}",
                    recommendation="Prefer strong forward-secret ciphers and disable weak suites.",
                )
            )

        if not _matches_hostname(hostname, details):
            findings.append(
                self.finding(
                    finding_id="TLS-007",
                    title="TLS certificate hostname mismatch",
                    severity="medium",
                    category="tls",
                    target=target,
                    description="The certificate common name or SAN entries do not match the scanned hostname.",
                    evidence=f"Hostname: {hostname}; CN: {details.subject_cn}; SANs: {', '.join(details.san_dns_names) or 'none'}",
                    recommendation="Use a certificate whose subject or SAN names match the intended hostname.",
                )
            )

        if details.validation_error:
            findings.append(
                self.finding(
                    finding_id="TLS-008",
                    title="TLS certificate validation failed",
                    severity="medium",
                    category="tls",
                    target=target,
                    description="The endpoint certificate failed chain or trust validation with the default trust store.",
                    evidence=details.validation_error,
                    recommendation="Fix certificate chain, trust anchors, or hostname alignment to restore successful validation.",
                )
            )

        return findings


def _parse_not_after(not_after: str | None) -> datetime | None:
    if not not_after:
        return None
    return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)

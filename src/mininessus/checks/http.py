from __future__ import annotations

import re
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPHandler, HTTPSHandler, Request, build_opener

from .base import BaseCheck
from ..models import Finding, HostResult


USER_AGENT = "AccuScanner/1.0"
HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}
DEFAULT_PAGE_MARKERS = {
    "apache2 ubuntu default page",
    "welcome to nginx",
    "iis windows server",
    "test page for",
}
DIRECTORY_LISTING_MARKERS = {"<title>index of /", "directory listing for", "index of /"}
SENSITIVE_PATHS = {
    "/.git/HEAD": ("HTTP-013", "Exposed .git metadata", "high"),
    "/.env": ("HTTP-014", "Exposed environment file", "high"),
    "/backup.zip": ("HTTP-015", "Backup file exposed", "high"),
    "/server-status": ("HTTP-016", "Server status page exposed", "medium"),
    "/server-info": ("HTTP-017", "Server info page exposed", "medium"),
    "/phpinfo.php": ("HTTP-018", "phpinfo page exposed", "medium"),
}
COMMON_PATHS = {
    "/admin": ("HTTP-019", "Potential admin interface exposed", "medium"),
    "/login": ("HTTP-020", "Potential login surface exposed", "low"),
    "/uploads": ("HTTP-021", "Uploads directory exposed", "low"),
    "/backup": ("HTTP-022", "Potential backup directory exposed", "medium"),
}
API_DOC_PATHS = {
    "/swagger": ("HTTP-040", "API documentation endpoint exposed", "medium"),
    "/swagger-ui/": ("HTTP-040", "API documentation endpoint exposed", "medium"),
    "/swagger/index.html": ("HTTP-040", "API documentation endpoint exposed", "medium"),
    "/swagger.json": ("HTTP-040", "API documentation endpoint exposed", "medium"),
    "/openapi.json": ("HTTP-041", "OpenAPI schema exposed", "medium"),
    "/v3/api-docs": ("HTTP-041", "OpenAPI schema exposed", "medium"),
    "/api-docs": ("HTTP-041", "OpenAPI schema exposed", "medium"),
}
GRAPHQL_PATHS = ("/graphql", "/api/graphql")
API_ADMIN_PATHS = {
    "/actuator": ("HTTP-047", "Administrative API endpoint exposed", "medium"),
    "/actuator/health": ("HTTP-048", "Health endpoint exposed without authentication", "low"),
    "/metrics": ("HTTP-049", "Metrics endpoint exposed without authentication", "medium"),
    "/api/admin": ("HTTP-047", "Administrative API endpoint exposed", "medium"),
    "/manage/health": ("HTTP-048", "Health endpoint exposed without authentication", "low"),
}
TECH_FINGERPRINTS = {
    "wordpress": ("HTTP-023", "WordPress fingerprint detected", "info"),
    "wp-content": ("HTTP-023", "WordPress fingerprint detected", "info"),
    "phpmyadmin": ("HTTP-024", "phpMyAdmin fingerprint detected", "medium"),
    "jenkins": ("HTTP-025", "Jenkins fingerprint detected", "medium"),
    "grafana": ("HTTP-026", "Grafana fingerprint detected", "info"),
    "tomcat": ("HTTP-027", "Tomcat fingerprint detected", "info"),
    "kibana": ("HTTP-028", "Kibana fingerprint detected", "info"),
    "prometheus": ("HTTP-029", "Prometheus fingerprint detected", "info"),
}


SECURITY_HEADERS = {
    "strict-transport-security": ("HTTP-001", "Missing HSTS header", "medium"),
    "content-security-policy": ("HTTP-002", "Missing CSP header", "medium"),
    "x-frame-options": ("HTTP-003", "Missing X-Frame-Options header", "medium"),
    "x-content-type-options": ("HTTP-004", "Missing X-Content-Type-Options header", "low"),
    "referrer-policy": ("HTTP-030", "Missing Referrer-Policy header", "low"),
    "permissions-policy": ("HTTP-031", "Missing Permissions-Policy header", "low"),
    "cross-origin-opener-policy": ("HTTP-032", "Missing Cross-Origin-Opener-Policy header", "low"),
    "cross-origin-resource-policy": ("HTTP-033", "Missing Cross-Origin-Resource-Policy header", "low"),
    "cross-origin-embedder-policy": ("HTTP-034", "Missing Cross-Origin-Embedder-Policy header", "low"),
}

COOKIE_FLAGS = {
    "Secure": ("HTTP-006", "Cookie missing Secure attribute", "medium"),
    "HttpOnly": ("HTTP-007", "Cookie missing HttpOnly attribute", "medium"),
    "SameSite": ("HTTP-008", "Cookie missing SameSite attribute", "low"),
}
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"),
}


@dataclass(slots=True)
class HttpObservation:
    url: str
    status: int | None
    headers: dict[str, str]
    body_preview: str = ""
    cookies: list[str] = field(default_factory=list)
    redirected_to_https: bool = False
    error: str | None = None


def fetch_http_observation(
    url: str,
    timeout: int = 5,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> HttpObservation:
    context = ssl.create_default_context()
    opener = build_opener(HTTPHandler(), HTTPSHandler(context=context))
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers, method=method)
    try:
        response = opener.open(request, timeout=timeout)
        body = response.read(4096).decode("utf-8", errors="replace") if method != "HEAD" else ""
        headers = {key.lower(): value for key, value in response.headers.items()}
        cookies = response.headers.get_all("Set-Cookie", [])
        redirected = response.geturl().startswith("https://") and url.startswith("http://")
        return HttpObservation(response.geturl(), response.status, headers, body, cookies, redirected)
    except HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace")
        headers = {key.lower(): value for key, value in exc.headers.items()}
        cookies = exc.headers.get_all("Set-Cookie", [])
        redirected = exc.geturl().startswith("https://") and url.startswith("http://")
        return HttpObservation(exc.geturl(), exc.code, headers, body, cookies, redirected, error=str(exc))
    except URLError as exc:
        return HttpObservation(url, None, {}, error=str(exc))


class HttpSecurityCheck(BaseCheck):
    name = "http_security"

    def run(self, hosts: list[HostResult], target: str) -> Iterable[Finding]:
        findings: list[Finding] = []
        for host in hosts:
            for port in (port for port in host.ports if port.state == "open"):
                if port.port in HTTP_PORTS:
                    findings.extend(self._check_endpoint(host, port.port, "http"))
                if port.port in HTTPS_PORTS:
                    findings.extend(self._check_endpoint(host, port.port, "https"))
        return findings

    def _check_endpoint(self, host: HostResult, port: int, scheme: str) -> list[Finding]:
        base_url = self._build_url(scheme, host.address, port)
        observation = fetch_http_observation(base_url)
        if observation.status is None:
            if scheme == "https":
                return [
                    self.finding(
                        finding_id="HTTP-035",
                        title="HTTPS service unavailable",
                        severity="medium",
                        category="web_security",
                        target=host.address,
                        description="The endpoint appears to expose HTTPS but did not return a usable HTTPS response.",
                        evidence=observation.error or f"URL: {base_url}",
                        recommendation="Verify TLS listener health and ensure the HTTPS service is correctly configured.",
                        confidence="medium",
                        tags=["web", "tls"],
                    )
                ]
            return []

        findings = self._build_missing_header_findings(host.address, observation.headers, scheme.upper())
        findings.extend(self._build_cors_findings(host.address, observation.headers))
        findings.extend(self._build_cors_reflection_findings(host.address, base_url))
        findings.extend(self._build_cookie_findings(host.address, observation.cookies))
        findings.extend(self._build_content_findings(host.address, observation, scheme.upper()))
        findings.extend(self._build_secret_exposure_findings(host.address, observation))
        findings.extend(self._build_http_method_findings(host.address, base_url))
        findings.extend(self._build_trace_finding(host.address, base_url))
        findings.extend(self._build_server_header_finding(host.address, observation.headers))
        findings.extend(self._build_auth_surface_findings(host.address, observation))
        findings.extend(self._build_sensitive_path_findings(host.address, base_url))
        findings.extend(self._build_common_path_findings(host.address, base_url))
        findings.extend(self._build_api_surface_findings(host.address, base_url))
        findings.extend(self._build_fingerprint_findings(host.address, observation))

        if scheme == "http" and not observation.redirected_to_https:
            findings.append(
                self.finding(
                    finding_id="HTTP-005",
                    title="HTTP service does not enforce HTTPS",
                    severity="high",
                    category="web_security",
                    target=host.address,
                    description="The server responded over HTTP without redirecting clients to HTTPS.",
                    evidence=f"Observed URL {observation.url} with status {observation.status}.",
                    recommendation="Redirect all plaintext requests to HTTPS and enable HSTS.",
                    confidence="high",
                    tags=["web", "transport"],
                )
            )
        return findings

    def _build_missing_header_findings(self, target: str, headers: dict[str, str], protocol_label: str) -> list[Finding]:
        findings: list[Finding] = []
        for header, (finding_id, title, severity) in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    self.finding(
                        finding_id=finding_id,
                        title=title,
                        severity=severity,
                        category="web_headers",
                        target=target,
                        description=f"The security header `{header}` was not observed on the {protocol_label} response.",
                        evidence=f"Headers observed: {sorted(headers.keys()) or 'none'}.",
                        recommendation="Set the recommended HTTP response header at the application or reverse proxy layer.",
                        confidence="high",
                        tags=["web", "headers"],
                    )
                )
        return findings

    def _build_cookie_findings(self, target: str, cookies: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for cookie in cookies:
            cookie_name = cookie.split("=", 1)[0].strip() or "unnamed cookie"
            lowered = cookie.lower()
            for flag, (finding_id, title, severity) in COOKIE_FLAGS.items():
                if flag.lower() not in lowered:
                    findings.append(
                        self.finding(
                            finding_id=f"{finding_id}-{cookie_name}",
                            title=title,
                            severity=severity,
                            category="web_cookies",
                            target=target,
                            description=f"The cookie `{cookie_name}` did not include the `{flag}` attribute.",
                            evidence=cookie,
                            recommendation="Set secure cookie attributes for all session and sensitive cookies.",
                            confidence="high",
                            tags=["web", "cookies"],
                        )
                    )
            if "domain=" not in lowered:
                continue
            findings.append(
                self.finding(
                    finding_id=f"HTTP-036-{cookie_name}",
                    title="Cookie sets an explicit domain scope",
                    severity="low",
                    category="web_cookies",
                    target=target,
                    description=f"The cookie `{cookie_name}` sets a Domain attribute that may broaden its scope.",
                    evidence=cookie,
                    recommendation="Confirm cookie domain scoping is as narrow as practical for the application.",
                    confidence="medium",
                    tags=["web", "cookies"],
                )
            )
        return findings

    def _build_cors_findings(self, target: str, headers: dict[str, str]) -> list[Finding]:
        origin = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "")
        if origin != "*":
            return []

        findings = [
            self.finding(
                finding_id="HTTP-042",
                title="Wildcard CORS origin allowed",
                severity="medium",
                category="web_cors",
                target=target,
                description="The response allows any origin via the Access-Control-Allow-Origin header.",
                evidence=f"Access-Control-Allow-Origin: {origin}",
                recommendation="Restrict CORS to explicitly trusted origins and review whether cross-origin access is required.",
                confidence="medium",
                tags=["web", "cors"],
            )
        ]
        if credentials.lower() == "true":
            findings.append(
                self.finding(
                    finding_id="HTTP-043",
                    title="CORS allows wildcard origin with credentials",
                    severity="high",
                    category="web_cors",
                    target=target,
                    description="The response combines a wildcard CORS origin policy with credentialed cross-origin access.",
                    evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                    recommendation="Disable wildcard credentialed CORS and allow only specific trusted origins when credentials are required.",
                    confidence="high",
                    tags=["web", "cors"],
                )
            )
        return findings

    def _build_cors_reflection_findings(self, target: str, url: str) -> list[Finding]:
        origin = "https://accuscanner-origin.example"
        observation = fetch_http_observation(url, headers={"Origin": origin})
        allowed_origin = observation.headers.get("access-control-allow-origin", "")
        if allowed_origin != origin:
            return []

        findings = [
            self.finding(
                finding_id="HTTP-045",
                title="CORS reflects arbitrary Origin header",
                severity="medium",
                category="web_cors",
                target=target,
                description="The response reflected an arbitrary Origin header value, which may indicate an overly permissive CORS policy.",
                evidence=f"Origin sent: {origin}; Access-Control-Allow-Origin: {allowed_origin}",
                recommendation="Allow only explicit trusted origins and avoid dynamic origin reflection unless it is tightly validated.",
                confidence="medium",
                tags=["web", "cors"],
            )
        ]
        if observation.headers.get("access-control-allow-credentials", "").lower() == "true":
            findings.append(
                self.finding(
                    finding_id="HTTP-046",
                    title="CORS reflects arbitrary Origin with credentials enabled",
                    severity="high",
                    category="web_cors",
                    target=target,
                    description="The response reflected an arbitrary Origin and also allowed credentialed cross-origin requests.",
                    evidence=(
                        f"Origin sent: {origin}; Access-Control-Allow-Origin: {allowed_origin}; "
                        "Access-Control-Allow-Credentials: true"
                    ),
                    recommendation="Disable reflected credentialed CORS and restrict credentialed access to specific trusted origins only.",
                    confidence="high",
                    tags=["web", "cors"],
                )
            )
        return findings

    def _build_content_findings(self, target: str, observation: HttpObservation, protocol_label: str) -> list[Finding]:
        findings: list[Finding] = []
        body_preview = observation.body_preview.lower()

        if any(marker in body_preview for marker in DIRECTORY_LISTING_MARKERS):
            findings.append(
                self.finding(
                    finding_id="HTTP-009",
                    title="Potential directory listing exposed",
                    severity="medium",
                    category="web_content",
                    target=target,
                    description="The response body looks like a directory listing.",
                    evidence=f"URL: {observation.url}; preview matched directory listing markers.",
                    recommendation="Disable directory browsing and serve explicit index pages instead.",
                    confidence="medium",
                    tags=["web", "content"],
                )
            )

        if any(marker in body_preview for marker in DEFAULT_PAGE_MARKERS):
            findings.append(
                self.finding(
                    finding_id="HTTP-010",
                    title="Default web page detected",
                    severity="low",
                    category="web_content",
                    target=target,
                    description=f"The {protocol_label} service appears to expose a default landing page.",
                    evidence=f"URL: {observation.url}; preview matched a known default page signature.",
                    recommendation="Replace default server pages with a hardened application or maintenance page.",
                    confidence="high",
                    tags=["web", "content"],
                )
            )

        return findings

    def _build_secret_exposure_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        findings: list[Finding] = []
        for secret_name, pattern in SECRET_PATTERNS.items():
            match = pattern.search(observation.body_preview)
            if not match:
                continue
            findings.append(
                self.finding(
                    finding_id=f"HTTP-051-{secret_name}",
                    title="Potential secret material exposed in HTTP response",
                    severity="high",
                    category="web_secrets",
                    target=target,
                    description="The HTTP response body matched a pattern associated with sensitive credential or key material.",
                    evidence=f"URL: {observation.url}; matched pattern: {secret_name}; snippet: {match.group(0)[:80]}",
                    recommendation="Remove secret material from responses immediately, rotate exposed credentials, and review how sensitive data is rendered or stored.",
                    confidence="medium",
                    tags=["web", "secrets", "auth"],
                )
            )
        return findings

    def _build_http_method_findings(self, target: str, url: str) -> list[Finding]:
        observation = fetch_http_observation(url, method="OPTIONS")
        if observation.status is None:
            return []
        allow_header = observation.headers.get("allow", "")
        risky_methods = [method for method in ("TRACE", "PUT", "DELETE") if method in allow_header.upper()]
        if not risky_methods:
            return []
        return [
            self.finding(
                finding_id="HTTP-011",
                title="Risky HTTP methods enabled",
                severity="medium",
                category="web_methods",
                target=target,
                description="The server advertises HTTP methods that are often unnecessary or risky on internet-facing services.",
                evidence=f"Allow header: {allow_header}",
                recommendation="Disable unneeded methods such as TRACE, PUT, and DELETE unless explicitly required.",
                confidence="medium",
                tags=["web", "methods"],
            )
        ]

    def _build_trace_finding(self, target: str, url: str) -> list[Finding]:
        observation = fetch_http_observation(url, method="TRACE")
        if observation.status in {200, 201, 202}:
            return [
                self.finding(
                    finding_id="HTTP-037",
                    title="TRACE method appears to be enabled",
                    severity="medium",
                    category="web_methods",
                    target=target,
                    description="The server returned a successful response to a TRACE request.",
                    evidence=f"TRACE response status: {observation.status}",
                    recommendation="Disable TRACE unless it is explicitly required for diagnostics.",
                    confidence="medium",
                    tags=["web", "methods"],
                )
            ]
        return []

    def _build_server_header_finding(self, target: str, headers: dict[str, str]) -> list[Finding]:
        server_header = headers.get("server")
        if not server_header:
            return []
        return [
            self.finding(
                finding_id="HTTP-012",
                title="Server header discloses implementation details",
                severity="low",
                category="web_headers",
                target=target,
                description="The response included a `Server` header that may help fingerprint the stack.",
                evidence=f"Server: {server_header}",
                recommendation="Suppress or minimize server version disclosure at the application or reverse proxy layer.",
                confidence="high",
                tags=["web", "headers"],
            )
        ]

    def _build_auth_surface_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        findings: list[Finding] = []
        body_preview = observation.body_preview.lower()
        auth_header = observation.headers.get("www-authenticate", "")
        if "basic" in auth_header.lower():
            findings.append(
                self.finding(
                    finding_id="HTTP-038",
                    title="Basic authentication surface detected",
                    severity="medium",
                    category="web_auth",
                    target=target,
                    description="The server advertises HTTP Basic authentication.",
                    evidence=f"WWW-Authenticate: {auth_header}",
                    recommendation="Use strong credentials, TLS, and preferably stronger authentication patterns than Basic auth.",
                    confidence="high",
                    tags=["web", "auth"],
                )
            )
        if "bearer" in auth_header.lower():
            findings.append(
                self.finding(
                    finding_id="HTTP-050",
                    title="Bearer authentication surface detected",
                    severity="low",
                    category="web_auth",
                    target=target,
                    description="The server advertises Bearer authentication for a reachable endpoint.",
                    evidence=f"WWW-Authenticate: {auth_header}",
                    recommendation="Confirm token-based endpoints are exposed intentionally and enforce strong token validation and TLS.",
                    confidence="high",
                    tags=["web", "auth", "api"],
                )
            )
        if any(marker in body_preview for marker in ("admin", "sign in", "log in", "password")):
            findings.append(
                self.finding(
                    finding_id="HTTP-039",
                    title="Login or administrative surface detected",
                    severity="low",
                    category="web_auth",
                    target=target,
                    description="The response body suggests a login or administrative surface is exposed.",
                    evidence=f"URL: {observation.url}",
                    recommendation="Confirm administrative interfaces are restricted to trusted networks and protected with strong authentication.",
                    confidence="low",
                    tags=["web", "auth"],
                )
            )
        return findings

    def _build_sensitive_path_findings(self, target: str, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        for path, (finding_id, title, severity) in SENSITIVE_PATHS.items():
            observation = fetch_http_observation(urljoin(base_url + "/", path.lstrip("/")))
            if observation.status and observation.status < 400:
                findings.append(
                    self.finding(
                        finding_id=finding_id,
                        title=title,
                        severity=severity,
                        category="web_content",
                        target=target,
                        description="A potentially sensitive file or endpoint was directly accessible.",
                        evidence=f"URL: {observation.url}; status: {observation.status}",
                        recommendation="Remove the exposed file or restrict access to trusted administrative paths only.",
                        confidence="medium",
                        tags=["web", "content", "sensitive"],
                    )
                )
                findings.extend(self._build_secret_exposure_findings(target, observation))
        return findings

    def _build_common_path_findings(self, target: str, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        for path, (finding_id, title, severity) in COMMON_PATHS.items():
            observation = fetch_http_observation(urljoin(base_url + "/", path.lstrip("/")))
            if observation.status and observation.status < 400:
                findings.append(
                    self.finding(
                        finding_id=finding_id,
                        title=title,
                        severity=severity,
                        category="web_surface",
                        target=target,
                        description="A common administrative or sensitive path is reachable.",
                        evidence=f"URL: {observation.url}; status: {observation.status}",
                        recommendation="Review whether the exposed path should be internet-facing and restrict it if unnecessary.",
                        confidence="low",
                        tags=["web", "surface"],
                    )
                )
        return findings

    def _build_api_surface_findings(self, target: str, base_url: str) -> list[Finding]:
        findings = self._build_api_documentation_findings(target, base_url)
        findings.extend(self._build_graphql_findings(target, base_url))
        findings.extend(self._build_api_auth_findings(target, base_url))
        return findings

    def _build_api_documentation_findings(self, target: str, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_ids: set[str] = set()
        for path, (finding_id, title, severity) in API_DOC_PATHS.items():
            if finding_id in seen_ids:
                continue
            observation = fetch_http_observation(urljoin(base_url + "/", path.lstrip("/")))
            if not observation.status or observation.status >= 400:
                continue
            findings.append(
                self.finding(
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    category="api_surface",
                    target=target,
                    description="An API documentation or schema endpoint is directly reachable.",
                    evidence=f"URL: {observation.url}; status: {observation.status}",
                    recommendation="Restrict API documentation and schema endpoints to trusted users or non-production environments where appropriate.",
                    confidence="medium",
                    tags=["web", "api"],
                )
            )
            seen_ids.add(finding_id)
        return findings

    def _build_graphql_findings(self, target: str, base_url: str) -> list[Finding]:
        for path in GRAPHQL_PATHS:
            observation = fetch_http_observation(urljoin(base_url + "/", path.lstrip("/")))
            if not observation.status or observation.status >= 400:
                continue
            body_preview = observation.body_preview.lower()
            header_text = " ".join(f"{key}:{value}".lower() for key, value in observation.headers.items())
            combined_text = f"{body_preview} {header_text}"
            if "graphql" not in combined_text and "introspection" not in combined_text:
                continue
            return [
                self.finding(
                    finding_id="HTTP-044",
                    title="GraphQL endpoint detected",
                    severity="medium",
                    category="api_surface",
                    target=target,
                    description="The response suggests a reachable GraphQL endpoint or schema-related response.",
                    evidence=f"URL: {observation.url}; status: {observation.status}",
                    recommendation="Review GraphQL exposure, disable introspection where unnecessary, and require strong authentication on sensitive APIs.",
                    confidence="medium",
                    tags=["web", "api", "graphql"],
                )
            ]
        return []

    def _build_api_auth_findings(self, target: str, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_ids: set[str] = set()
        for path, (finding_id, title, severity) in API_ADMIN_PATHS.items():
            observation = fetch_http_observation(urljoin(base_url + "/", path.lstrip("/")))
            if not observation.status or observation.status >= 400:
                continue
            if observation.headers.get("www-authenticate"):
                continue
            if finding_id in seen_ids:
                continue
            findings.append(
                self.finding(
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    category="api_auth",
                    target=target,
                    description="A potentially sensitive API endpoint was reachable without an authentication challenge.",
                    evidence=f"URL: {observation.url}; status: {observation.status}",
                    recommendation="Require authentication on administrative and introspection endpoints or restrict them to trusted internal networks.",
                    confidence="medium",
                    tags=["web", "api", "auth"],
                )
            )
            seen_ids.add(finding_id)
        return findings

    def _build_fingerprint_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        findings: list[Finding] = []
        text = " ".join([observation.body_preview.lower(), " ".join(f"{k}:{v}".lower() for k, v in observation.headers.items())])
        for marker, (finding_id, title, severity) in TECH_FINGERPRINTS.items():
            if marker in text:
                findings.append(
                    self.finding(
                        finding_id=finding_id,
                        title=title,
                        severity=severity,
                        category="fingerprinting",
                        target=target,
                        description="The response suggests a recognizable platform or administration interface.",
                        evidence=f"Matched fingerprint marker: {marker}",
                        recommendation="Confirm the exposed platform is intentional and hardened according to vendor guidance.",
                        confidence="medium",
                        tags=["web", "fingerprint"],
                    )
                )
        return findings

    @staticmethod
    def _build_url(scheme: str, host: str, port: int) -> str:
        default_port = 80 if scheme == "http" else 443
        return f"{scheme}://{host}" if port == default_port else f"{scheme}://{host}:{port}"

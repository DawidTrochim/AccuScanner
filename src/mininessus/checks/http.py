from __future__ import annotations

import re
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import ip_address
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
from urllib.request import HTTPHandler, HTTPSHandler, Request, build_opener

from .base import BaseCheck
from ..models import Finding, HostResult
from ..utils import sanitize_target


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
    "/crossdomain.xml": ("HTTP-054", "Cross-domain policy file exposed", "low"),
    "/clientaccesspolicy.xml": ("HTTP-055", "Client access policy file exposed", "low"),
    "/web.config": ("HTTP-056", "Web configuration file exposed", "high"),
    "/shell.php": ("HTTP-057", "Potential web shell file exposed", "high"),
    "/cmd.php": ("HTTP-057", "Potential web shell file exposed", "high"),
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
SQL_ERROR_PATTERNS = {
    "mysql": re.compile(r"(sql syntax.*mysql|warning: mysql_|mysql_fetch_|mysql_num_rows)", re.IGNORECASE),
    "postgresql": re.compile(r"(postgresql.*error|pg_query\(|pg_exec\(|psql:)", re.IGNORECASE),
    "mssql": re.compile(r"(sql server|unclosed quotation mark after the character string|microsoft ole db provider for sql server)", re.IGNORECASE),
    "oracle": re.compile(r"(ora-\d{5}|oracle error)", re.IGNORECASE),
    "sqlite": re.compile(r"(sqlite error|sqlite_exception|sqlite3::)", re.IGNORECASE),
}
APPLICATION_ERROR_PATTERNS = {
    "php": re.compile(r"(php warning|php fatal error|stack trace:.*php|unexpected t_[a-z_]+)", re.IGNORECASE),
    "xml": re.compile(r"(xml parsing error|xml parser error|xmlsyntaxerror|entityref: expecting)", re.IGNORECASE),
    "xpath": re.compile(r"(xpath.*error|invalid predicate|xpath exception)", re.IGNORECASE),
    "ldap": re.compile(r"(ldap error|javax\.naming|invalid dn syntax|ldapexception)", re.IGNORECASE),
    "ssi": re.compile(r"(ssi include virtual|server side include|exec cmd=)", re.IGNORECASE),
    "os_command": re.compile(r"(sh: .* not found|command not found|cannot execute|/bin/sh:)", re.IGNORECASE),
    "smtp": re.compile(r"(smtp error|mail command failed|could not instantiate mail function)", re.IGNORECASE),
}
INJECTION_PARAMETER_NAMES = {
    "id",
    "item",
    "user",
    "uid",
    "account",
    "search",
    "query",
    "q",
    "filter",
    "sort",
    "order",
    "page",
    "category",
    "group",
}
FILE_PARAMETER_NAMES = {"file", "path", "page", "template", "include", "document", "folder", "dir"}
URL_PARAMETER_NAMES = {"url", "uri", "link", "dest", "redirect", "return", "next", "target"}
FORM_FIELD_PATTERN = re.compile(r'name=["\']([A-Za-z0-9_.-]{1,64})["\']', re.IGNORECASE)
FORM_TAG_PATTERN = re.compile(r"<form\b", re.IGNORECASE)
FORM_BLOCK_PATTERN = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL)
FORM_ACTION_PATTERN = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
FORM_METHOD_PATTERN = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)
LINK_ATTR_PATTERN = re.compile(r"""(href|src|action)=["']([^"'#]+)""", re.IGNORECASE)
FILE_UPLOAD_PATTERN = re.compile(r'type=["\']file["\']', re.IGNORECASE)
CSRF_TOKEN_PATTERN = re.compile(r'name=["\'](?:csrf|csrf_token|xsrf|authenticity_token|__requestverificationtoken)["\']', re.IGNORECASE)
PASSWORD_RESET_PATTERN = re.compile(r"(forgot password|reset password|password reset|reset your password|forgotten password)", re.IGNORECASE)
WEB_STORAGE_PATTERN = re.compile(r"\b(?:localStorage|sessionStorage|indexedDB)\b", re.IGNORECASE)
SOAP_MARKERS = ("soapenv:", "soap:", "wsdl", "?wsdl", "application/soap+xml")
AJAX_MARKERS = ("xmlhttprequest", "jquery", "fetch(", "axios", "application/json")
SCRIPT_ENDPOINT_PATTERN = re.compile(
    r"""(?:"|')((?:https?://[^"'\\]+|/[A-Za-z0-9._~!$&()*+,;=:@%/\-?=&]+))(?:"|')""",
    re.IGNORECASE,
)
SCRIPT_API_CALL_PATTERNS = (
    re.compile(r"""fetch\(\s*["']([^"']+)["']""", re.IGNORECASE),
    re.compile(r"""axios\.(?:get|post|put|delete|patch)\(\s*["']([^"']+)["']""", re.IGNORECASE),
    re.compile(r"""open\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']""", re.IGNORECASE),
    re.compile(r"""url\s*:\s*["']([^"']+)["']""", re.IGNORECASE),
)
PASSWORD_RESET_FIELD_NAMES = {"email", "username", "user", "token", "reset_token", "new_password", "password", "confirm_password"}
ROBOTS_PATH_PATTERN = re.compile(r"^(?:allow|disallow):\s*(\S+)", re.IGNORECASE | re.MULTILINE)
SITEMAP_LOC_PATTERN = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".txt",
    ".csv",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".tgz",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
}
STATIC_ASSET_EXTENSIONS = {
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".webp",
    ".bmp",
    ".mp4",
    ".webm",
    ".mp3",
}
SURFACE_CRAWL_LIMIT = 8


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
            request_host = self._request_host(target, host)
            for port in (port for port in host.ports if port.state == "open"):
                if port.port in HTTP_PORTS:
                    findings.extend(self._check_endpoint(host, request_host, port.port, "http"))
                if port.port in HTTPS_PORTS:
                    findings.extend(self._check_endpoint(host, request_host, port.port, "https"))
        return findings

    def _check_endpoint(self, host: HostResult, request_host: str, port: int, scheme: str) -> list[Finding]:
        base_url = self._build_url(scheme, request_host, port)
        observation = fetch_http_observation(base_url)
        if observation.status is None:
            if scheme == "https":
                return [
                    self.finding(
                        finding_id="HTTP-035",
                        title="HTTPS service unavailable",
                        severity="medium",
                        category="web_security",
                        target=request_host,
                        description="The endpoint appears to expose HTTPS but did not return a usable HTTPS response.",
                        evidence=observation.error or f"URL: {base_url}",
                        recommendation="Verify TLS listener health and ensure the HTTPS service is correctly configured.",
                        confidence="medium",
                        tags=["web", "tls"],
                    )
                ]
            return []

        findings = self._build_missing_header_findings(request_host, observation.headers, scheme.upper())
        findings.extend(self._build_cors_findings(request_host, observation.headers))
        findings.extend(self._build_cors_reflection_findings(request_host, base_url))
        findings.extend(self._build_cookie_findings(request_host, observation.cookies))
        findings.extend(self._build_content_findings(request_host, observation, scheme.upper()))
        findings.extend(self._build_secret_exposure_findings(request_host, observation))
        findings.extend(self._build_http_method_findings(request_host, base_url))
        findings.extend(self._build_trace_finding(request_host, base_url))
        findings.extend(self._build_server_header_finding(request_host, observation.headers))
        findings.extend(self._build_auth_surface_findings(request_host, observation))
        findings.extend(self._build_passive_injection_findings(request_host, observation))
        findings.extend(self._build_form_posture_findings(request_host, observation))
        findings.extend(self._build_client_side_surface_findings(request_host, observation))
        findings.extend(self._build_protocol_surface_findings(request_host, observation))
        findings.extend(self._build_sensitive_path_findings(request_host, base_url))
        findings.extend(self._build_common_path_findings(request_host, base_url))
        findings.extend(self._build_api_surface_findings(request_host, base_url))
        findings.extend(self._build_fingerprint_findings(request_host, observation))
        findings.extend(self._build_attack_surface_findings(request_host, base_url, observation))

        if scheme == "http" and not observation.redirected_to_https:
            findings.append(
                self.finding(
                    finding_id="HTTP-005",
                    title="HTTP service does not enforce HTTPS",
                    severity="high",
                    category="web_security",
                    target=request_host,
                    description="The server responded over HTTP without redirecting clients to HTTPS.",
                    evidence=f"Observed URL {observation.url} with status {observation.status}.",
                    recommendation="Redirect all plaintext requests to HTTPS and enable HSTS.",
                    confidence="high",
                    tags=["web", "transport"],
                )
            )
        return findings

    @staticmethod
    def _request_host(target: str, host: HostResult) -> str:
        requested_target = sanitize_target(target)
        if requested_target and HttpSecurityCheck._looks_like_hostname(requested_target):
            return requested_target
        return host.address

    @staticmethod
    def _looks_like_hostname(value: str) -> bool:
        if "/" in value:
            return False
        try:
            ip_address(value)
        except ValueError:
            return True
        return False

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
                findings.extend(self._build_passive_injection_findings(target, observation))
                findings.extend(self._build_form_posture_findings(target, observation))
                findings.extend(self._build_client_side_surface_findings(target, observation))
                findings.extend(self._build_protocol_surface_findings(target, observation))
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
                findings.extend(self._build_passive_injection_findings(target, observation))
                findings.extend(self._build_form_posture_findings(target, observation))
                findings.extend(self._build_client_side_surface_findings(target, observation))
                findings.extend(self._build_protocol_surface_findings(target, observation))
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
            requested_url = urljoin(base_url + "/", path.lstrip("/"))
            observation = fetch_http_observation(requested_url)
            if not observation.status or observation.status >= 400:
                continue
            if observation.headers.get("www-authenticate"):
                continue
            if self._redirected_to_login(requested_url, observation):
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

    @staticmethod
    def _redirected_to_login(requested_url: str, observation: HttpObservation) -> bool:
        if observation.url == requested_url:
            return False
        lowered_url = observation.url.lower()
        lowered_body = observation.body_preview.lower()
        login_markers = ("login", "signin", "sign-in", "auth")
        return any(marker in lowered_url or marker in lowered_body for marker in login_markers)

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

    def _build_passive_injection_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._build_sql_error_findings(target, observation))
        findings.extend(self._build_application_error_findings(target, observation))
        findings.extend(self._build_input_surface_findings(target, observation))
        return findings

    def _build_sql_error_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        body_preview = observation.body_preview or ""
        findings: list[Finding] = []
        for backend, pattern in SQL_ERROR_PATTERNS.items():
            match = pattern.search(body_preview)
            if not match:
                continue
            findings.append(
                self.finding(
                    finding_id=f"HTTP-052-{backend}",
                    title="Possible SQL error message exposure",
                    severity="medium",
                    category="input_validation",
                    target=target,
                    description="The response body matched an error pattern commonly associated with database-backed application failures.",
                    evidence=f"URL: {observation.url}; matched backend: {backend}; snippet: {match.group(0)[:120]}",
                    recommendation="Review error handling, suppress backend exception details in responses, and validate input handling on the affected route.",
                    confidence="medium",
                    tags=["web", "input", "manual-review"],
                )
            )
        return findings

    def _build_application_error_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        body_preview = observation.body_preview or ""
        findings: list[Finding] = []
        for family, pattern in APPLICATION_ERROR_PATTERNS.items():
            match = pattern.search(body_preview)
            if not match:
                continue
            findings.append(
                self.finding(
                    finding_id=f"HTTP-058-{family}",
                    title="Possible application error leakage",
                    severity="medium",
                    category="input_validation",
                    target=target,
                    description="The response body matched an error pattern associated with unsafe input handling or backend exception leakage.",
                    evidence=f"URL: {observation.url}; matched family: {family}; snippet: {match.group(0)[:120]}",
                    recommendation="Suppress verbose backend errors, validate untrusted input, and review the affected route during authorized testing.",
                    confidence="medium",
                    tags=["web", "input", "manual-review"],
                )
            )
        return findings

    def _build_input_surface_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        parameter_names = {name.lower() for name, _ in parse_qsl(urlparse(observation.url).query, keep_blank_values=True)}
        parameter_names.update(match.lower() for match in FORM_FIELD_PATTERN.findall(observation.body_preview or ""))
        suspicious_names = sorted(name for name in parameter_names if name in INJECTION_PARAMETER_NAMES)
        findings: list[Finding] = []
        if suspicious_names:
            findings.append(
                self.finding(
                    finding_id="HTTP-053",
                    title="Possible database-backed input surface detected",
                    severity="low",
                    category="input_surface",
                    target=target,
                    description="The endpoint exposes query parameters or form fields commonly associated with database-backed filtering or record lookups.",
                    evidence=f"URL: {observation.url}; parameter candidates: {', '.join(suspicious_names)}",
                    recommendation="Review server-side input handling, parameterized query usage, and validation on the identified parameters during authorized testing.",
                    confidence="low",
                    tags=["web", "input", "manual-review"],
                )
            )
        file_names = sorted(name for name in parameter_names if name in FILE_PARAMETER_NAMES)
        if file_names:
            findings.append(
                self.finding(
                    finding_id="HTTP-059",
                    title="Possible file inclusion or traversal surface detected",
                    severity="low",
                    category="input_surface",
                    target=target,
                    description="The endpoint exposes parameters commonly associated with file path selection or template inclusion.",
                    evidence=f"URL: {observation.url}; parameter candidates: {', '.join(file_names)}",
                    recommendation="Review path handling, allowlists, and path normalization for the identified parameters during authorized testing.",
                    confidence="low",
                    tags=["web", "input", "manual-review"],
                )
            )
        url_names = sorted(name for name in parameter_names if name in URL_PARAMETER_NAMES)
        if url_names:
            findings.append(
                self.finding(
                    finding_id="HTTP-060",
                    title="Possible URL fetch or redirect surface detected",
                    severity="low",
                    category="input_surface",
                    target=target,
                    description="The endpoint exposes parameters commonly associated with redirects or server-side URL fetching.",
                    evidence=f"URL: {observation.url}; parameter candidates: {', '.join(url_names)}",
                    recommendation="Review redirect validation, outbound request allowlists, and URL handling logic for the identified parameters during authorized testing.",
                    confidence="low",
                    tags=["web", "input", "manual-review"],
                )
            )
        return findings

    def _build_form_posture_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        body_preview = observation.body_preview or ""
        findings: list[Finding] = []
        form_details = self._extract_form_details(observation.url, body_preview)
        if form_details and not CSRF_TOKEN_PATTERN.search(body_preview):
            findings.append(
                self.finding(
                    finding_id="HTTP-061",
                    title="HTML form lacks obvious anti-CSRF token",
                    severity="low",
                    category="session_security",
                    target=target,
                    description="The page contains an HTML form but no common anti-CSRF token field was observed in the captured response.",
                    evidence=f"URL: {observation.url}",
                    recommendation="Confirm state-changing forms include anti-CSRF protections and same-site cookie defenses where appropriate.",
                    confidence="low",
                    tags=["web", "forms", "manual-review"],
                )
            )
        upload_form = next((detail for detail in form_details if detail.has_file_upload), None)
        if upload_form:
            findings.append(
                self.finding(
                    finding_id="HTTP-062",
                    title="File upload surface detected",
                    severity="medium",
                    category="web_surface",
                    target=target,
                    description="The page appears to expose a file upload field.",
                    evidence=f"URL: {observation.url}; form action: {upload_form.action}; method: {upload_form.method}",
                    recommendation="Review upload validation, file type restrictions, storage paths, and malware scanning controls on the identified upload flow.",
                    confidence="medium",
                    tags=["web", "upload", "manual-review"],
                )
            )
        reset_form = next((detail for detail in form_details if self._looks_like_password_reset_form(detail)), None)
        if reset_form or self._looks_like_password_reset_page(observation):
            findings.append(
                self.finding(
                    finding_id="HTTP-063",
                    title="Password reset surface detected",
                    severity="low",
                    category="auth_surface",
                    target=target,
                    description="The response suggests a password reset workflow is reachable.",
                    evidence=f"URL: {observation.url}" + (
                        f"; form action: {reset_form.action}; fields: {', '.join(reset_form.fields[:6])}" if reset_form else ""
                    ),
                    recommendation="Review reset token entropy, host header handling, expiration, and account verification controls on the reset workflow.",
                    confidence="low",
                    tags=["web", "auth", "manual-review"],
                )
            )
        return findings

    def _build_client_side_surface_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        body_preview = observation.body_preview or ""
        lowered = body_preview.lower()
        findings: list[Finding] = []
        if WEB_STORAGE_PATTERN.search(body_preview):
            findings.append(
                self.finding(
                    finding_id="HTTP-064",
                    title="Client-side web storage usage detected",
                    severity="low",
                    category="client_security",
                    target=target,
                    description="The response references browser storage APIs such as localStorage or sessionStorage.",
                    evidence=f"URL: {observation.url}",
                    recommendation="Review whether sensitive data is stored client-side and ensure storage usage aligns with session-security requirements.",
                    confidence="low",
                    tags=["web", "client", "manual-review"],
                )
            )
        ajax_matches = [marker for marker in AJAX_MARKERS if marker in lowered]
        if len(ajax_matches) >= 2 or ("application/json" in lowered and any(token in lowered for token in ("fetch(", "axios", "xmlhttprequest"))):
            findings.append(
                self.finding(
                    finding_id="HTTP-065",
                    title="AJAX or JSON-heavy application surface detected",
                    severity="low",
                    category="client_security",
                    target=target,
                    description="The response suggests a JavaScript-heavy or API-driven application surface.",
                    evidence=f"URL: {observation.url}; matched markers: {', '.join(sorted(set(ajax_matches or ['application/json'])))}",
                    recommendation="Review client-side request handling, API authorization, and JSON response controls for the identified application surface.",
                    confidence="low",
                    tags=["web", "client", "api", "manual-review"],
                )
            )
        return findings

    def _build_protocol_surface_findings(self, target: str, observation: HttpObservation) -> list[Finding]:
        text = " ".join(
            [
                (observation.body_preview or "").lower(),
                " ".join(f"{key}:{value}".lower() for key, value in observation.headers.items()),
            ]
        )
        findings: list[Finding] = []
        soap_matches = [marker for marker in SOAP_MARKERS if marker in text]
        if "soapenv:" in text or "application/soap+xml" in text or len(soap_matches) >= 2:
            findings.append(
                self.finding(
                    finding_id="HTTP-066",
                    title="SOAP or WSDL application surface detected",
                    severity="low",
                    category="api_surface",
                    target=target,
                    description="The response suggests a SOAP-based service or WSDL-related application surface.",
                    evidence=f"URL: {observation.url}; matched markers: {', '.join(sorted(set(soap_matches)))}",
                    recommendation="Review SOAP endpoint exposure, XML parser hardening, and access controls on the identified service.",
                    confidence="low",
                    tags=["web", "api", "xml", "manual-review"],
                )
            )
        dav_header = observation.headers.get("dav")
        if dav_header:
            findings.append(
                self.finding(
                    finding_id="HTTP-067",
                    title="WebDAV support advertised",
                    severity="medium",
                    category="configuration",
                    target=target,
                    description="The response advertised WebDAV support via the DAV header.",
                    evidence=f"DAV: {dav_header}",
                    recommendation="Confirm WebDAV is intentionally exposed and restrict authoring methods or access if it is not required.",
                    confidence="medium",
                    tags=["web", "configuration", "manual-review"],
                )
            )
        return findings

    def _build_attack_surface_findings(self, target: str, base_url: str, base_observation: HttpObservation) -> list[Finding]:
        findings: list[Finding] = []
        discoveries = self._discover_same_host_surfaces(base_url, base_observation)
        seen_items: set[tuple[str, str]] = set()
        for discovery in discoveries:
            discovery_key = (discovery.kind, discovery.url)
            if discovery_key in seen_items:
                continue
            seen_items.add(discovery_key)
            findings.append(
                self.finding(
                    finding_id=f"HTTP-068-{discovery.kind}",
                    title=f"Discovered {discovery.kind.replace('_', ' ')} surface",
                    severity="info",
                    category="attack_surface",
                    target=target,
                    description="The passive crawler discovered an additional same-host application surface during the web review.",
                    evidence=f"{discovery.kind}: {discovery.url}",
                    recommendation="Review the discovered route as part of application attack-surface inventory and confirm it is intended to be exposed.",
                    confidence="medium",
                    tags=["web", "surface", "manual-review"],
                )
            )
            if discovery.observation and discovery.kind in {"page", "form_action"}:
                findings.extend(self._build_passive_injection_findings(target, discovery.observation))
                findings.extend(self._build_form_posture_findings(target, discovery.observation))
                findings.extend(self._build_client_side_surface_findings(target, discovery.observation))
                findings.extend(self._build_protocol_surface_findings(target, discovery.observation))
                findings.extend(self._build_api_surface_findings(target, discovery.url))
        return findings

    def _discover_same_host_surfaces(self, base_url: str, base_observation: HttpObservation) -> list["SurfaceDiscovery"]:
        discoveries: list[SurfaceDiscovery] = []
        queue: list[str] = [base_observation.url or base_url]
        visited: set[str] = set()
        base_netloc = urlparse(base_url).netloc

        for seed_url in self._discover_seed_urls(base_url, base_netloc):
            normalized_seed = self._normalize_surface_url(seed_url)
            if not normalized_seed:
                continue
            discovered_kind = "document" if self._looks_like_document(normalized_seed) else "page"
            if (discovered_kind, normalized_seed) not in {(item.kind, item.url) for item in discoveries}:
                discoveries.append(SurfaceDiscovery(kind=discovered_kind, url=normalized_seed))
            if discovered_kind == "page" and normalized_seed not in queue:
                queue.append(normalized_seed)

        while queue and len(visited) < SURFACE_CRAWL_LIMIT:
            current_url = queue.pop(0)
            normalized_current = self._normalize_surface_url(current_url)
            if normalized_current in visited:
                continue
            visited.add(normalized_current)
            observation = base_observation if normalized_current == self._normalize_surface_url(base_observation.url or base_url) else fetch_http_observation(current_url)
            if observation.status is None or observation.status >= 500:
                continue

            for kind, discovered_url in self._extract_surface_urls(current_url, observation.body_preview):
                normalized_url = self._normalize_surface_url(discovered_url)
                if not normalized_url or urlparse(normalized_url).netloc != base_netloc:
                    continue
                if (kind, normalized_url) not in {(item.kind, item.url) for item in discoveries}:
                    discoveries.append(SurfaceDiscovery(kind=kind, url=normalized_url))
                if kind in {"page", "form_action"} and normalized_url not in visited and normalized_url not in queue and len(visited) + len(queue) < SURFACE_CRAWL_LIMIT:
                    queue.append(normalized_url)
                if kind in {"page", "form_action", "script_asset"}:
                    for item in discoveries:
                        if item.url == normalized_url and item.kind == kind and item.observation is None:
                            item.observation = fetch_http_observation(normalized_url)
                            if kind == "script_asset" and item.observation.status and item.observation.status < 500:
                                for endpoint in self._extract_script_endpoints(normalized_url, item.observation.body_preview, base_netloc):
                                    discoveries.append(SurfaceDiscovery(kind="script_endpoint", url=endpoint))
                            break
            for parameter_name in self._extract_query_parameter_names(observation.url):
                discoveries.append(SurfaceDiscovery(kind="query_parameter", url=parameter_name))
            for field_name in self._extract_form_field_names(observation.body_preview):
                discoveries.append(SurfaceDiscovery(kind="form_field", url=field_name))
            if self._looks_like_script_asset(normalized_current):
                for endpoint in self._extract_script_endpoints(normalized_current, observation.body_preview, base_netloc):
                    discoveries.append(SurfaceDiscovery(kind="script_endpoint", url=endpoint))
        return discoveries

    def _discover_seed_urls(self, base_url: str, base_netloc: str) -> list[str]:
        seeds: list[str] = []
        for seed_path in ("/robots.txt", "/sitemap.xml"):
            observation = fetch_http_observation(urljoin(base_url + "/", seed_path.lstrip("/")))
            if not observation.status or observation.status >= 400:
                continue
            if seed_path.endswith("robots.txt"):
                candidates = ROBOTS_PATH_PATTERN.findall(observation.body_preview or "")
                normalized_candidates = [urljoin(base_url + "/", candidate.lstrip("/")) for candidate in candidates]
            else:
                normalized_candidates = SITEMAP_LOC_PATTERN.findall(observation.body_preview or "")
            for candidate in normalized_candidates:
                normalized = self._normalize_surface_url(candidate)
                if not normalized or urlparse(normalized).netloc != base_netloc:
                    continue
                if normalized not in seeds:
                    seeds.append(normalized)
        return seeds

    def _extract_surface_urls(self, base_url: str, body_preview: str) -> list[tuple[str, str]]:
        surfaces: list[tuple[str, str]] = []
        for attribute, raw_url in LINK_ATTR_PATTERN.findall(body_preview or ""):
            joined_url = self._normalize_surface_url(urljoin(base_url, raw_url))
            if not joined_url:
                continue
            kind = "page"
            if attribute.lower() == "src" and raw_url.lower().endswith(".js"):
                kind = "script_asset"
            elif attribute.lower() == "action":
                kind = "form_action"
            elif self._looks_like_document(joined_url):
                kind = "document"
            elif self._looks_like_static_asset(joined_url):
                kind = "static_asset"
            surfaces.append((kind, joined_url))
        for form_detail in self._extract_form_details(base_url, body_preview):
            surfaces.append(("form_action", form_detail.action))
        return surfaces

    @staticmethod
    def _extract_query_parameter_names(url: str) -> list[str]:
        return sorted({name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if name})

    @staticmethod
    def _extract_form_field_names(body_preview: str) -> list[str]:
        return sorted({field_name.lower() for field_name in FORM_FIELD_PATTERN.findall(body_preview or "")})

    def _extract_script_endpoints(self, base_url: str, body_preview: str, base_netloc: str) -> list[str]:
        endpoints: list[str] = []
        candidates: list[str] = []
        for pattern in SCRIPT_API_CALL_PATTERNS:
            candidates.extend(pattern.findall(body_preview or ""))
        candidates.extend(SCRIPT_ENDPOINT_PATTERN.findall(body_preview or ""))
        for raw_value in candidates:
            normalized = self._normalize_surface_url(urljoin(base_url, raw_value))
            if not normalized:
                continue
            parsed = urlparse(normalized)
            if parsed.netloc != base_netloc:
                continue
            if self._looks_like_document(normalized) or self._looks_like_static_asset(normalized) or self._looks_like_script_asset(normalized):
                continue
            if not self._looks_like_api_endpoint(normalized):
                continue
            if normalized not in endpoints:
                endpoints.append(normalized)
        return endpoints

    def _extract_form_details(self, base_url: str, body_preview: str) -> list["FormDetail"]:
        details: list[FormDetail] = []
        for match in FORM_BLOCK_PATTERN.finditer(body_preview or ""):
            attrs = match.group("attrs") or ""
            body = match.group("body") or ""
            action_match = FORM_ACTION_PATTERN.search(attrs)
            method_match = FORM_METHOD_PATTERN.search(attrs)
            raw_action = action_match.group(1) if action_match else ""
            normalized_action = self._normalize_surface_url(urljoin(base_url, raw_action or urlparse(base_url).path or "/"))
            if not normalized_action:
                continue
            fields = sorted({field_name.lower() for field_name in FORM_FIELD_PATTERN.findall(body)})
            details.append(
                FormDetail(
                    action=normalized_action,
                    method=(method_match.group(1).upper() if method_match else "GET"),
                    fields=fields,
                    has_file_upload=bool(FILE_UPLOAD_PATTERN.search(body)),
                )
            )
        return details

    @staticmethod
    def _path_extension(url: str) -> str:
        path = urlparse(url).path.lower()
        if "." not in path.rsplit("/", 1)[-1]:
            return ""
        return "." + path.rsplit(".", 1)[-1]

    @classmethod
    def _looks_like_document(cls, url: str) -> bool:
        return cls._path_extension(url) in DOCUMENT_EXTENSIONS

    @classmethod
    def _looks_like_static_asset(cls, url: str) -> bool:
        return cls._path_extension(url) in STATIC_ASSET_EXTENSIONS

    @classmethod
    def _looks_like_script_asset(cls, url: str) -> bool:
        return cls._path_extension(url) == ".js"

    @staticmethod
    def _looks_like_api_endpoint(url: str) -> bool:
        lowered = urlparse(url).path.lower()
        return any(token in lowered for token in ("/api", "/graphql", "/rest", "/services", "/json", "/xml", "/soap", "/ajax", "/endpoint"))

    @staticmethod
    def _looks_like_password_reset_form(form_detail: "FormDetail") -> bool:
        action_text = form_detail.action.lower()
        field_set = set(form_detail.fields)
        return (
            any(token in action_text for token in ("reset", "forgot", "recover", "password"))
            or ("email" in field_set and len(field_set & PASSWORD_RESET_FIELD_NAMES) >= 2)
            or "reset_token" in field_set
        )

    @staticmethod
    def _looks_like_password_reset_page(observation: HttpObservation) -> bool:
        lowered_url = observation.url.lower()
        lowered_body = (observation.body_preview or "").lower()
        if not PASSWORD_RESET_PATTERN.search(lowered_body):
            return False
        return any(token in lowered_url for token in ("reset", "forgot", "recover"))

    @staticmethod
    def _normalize_surface_url(url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        normalized = parsed._replace(fragment="")
        path = normalized.path or "/"
        return urlunparse(normalized._replace(path=path))

    @staticmethod
    def _build_url(scheme: str, host: str, port: int) -> str:
        default_port = 80 if scheme == "http" else 443
        return f"{scheme}://{host}" if port == default_port else f"{scheme}://{host}:{port}"


@dataclass(slots=True)
class SurfaceDiscovery:
    kind: str
    url: str
    observation: HttpObservation | None = None


@dataclass(slots=True)
class FormDetail:
    action: str
    method: str
    fields: list[str]
    has_file_upload: bool = False

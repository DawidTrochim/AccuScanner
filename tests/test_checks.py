import ssl
from urllib.error import URLError
from unittest.mock import patch

from mininessus.checks.banner import BannerExposureCheck
from mininessus.checks.http import HttpObservation, HttpSecurityCheck, fetch_http_observation
from mininessus.checks.ports import RiskyPortCheck
from mininessus.checks.services import ServiceExposureCheck
from mininessus.checks.tls import TLSDetails, TlsCertificateCheck
from mininessus.models import HostResult, PortService


def sample_host() -> HostResult:
    return HostResult(
        address="10.0.0.5",
        hostname="app.internal",
        status="up",
        ports=[
            PortService(port=80, protocol="tcp", state="open", service="http"),
            PortService(port=443, protocol="tcp", state="open", service="https", tunnel="ssl"),
            PortService(port=21, protocol="tcp", state="open", service="ftp", product="vsftpd", version="3.0.3"),
        ],
    )


def test_risky_port_check_finds_ftp():
    findings = list(RiskyPortCheck().run([sample_host()], "10.0.0.5"))
    assert any(f.id == "PORT-21" for f in findings)


@patch("mininessus.checks.http._open_http_request")
def test_fetch_http_observation_retries_https_without_tls_validation(mock_open_request):
    ssl_error = URLError(ssl.SSLCertVerificationError("certificate verify failed"))

    def side_effect(request, original_url: str, *, timeout: int, verify_tls: bool):
        if verify_tls:
            raise ssl_error
        return HttpObservation(
            url=original_url,
            status=200,
            headers={"server": "apache"},
            body_preview="ok",
            redirected_to_https=False,
        )

    mock_open_request.side_effect = side_effect

    observation = fetch_http_observation("https://example.test")

    assert observation.status == 200
    assert mock_open_request.call_count == 2


@patch("mininessus.checks.http.fetch_http_observation")
def test_http_security_check_flags_missing_headers_and_surfaces(mock_fetch):
    def fake_fetch(
        url: str,
        timeout: int = 5,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpObservation:
        if method == "OPTIONS":
            return HttpObservation(url=url, status=200, headers={"allow": "GET, HEAD, TRACE"}, redirected_to_https=False)
        if method == "TRACE":
            return HttpObservation(url=url, status=200, headers={}, redirected_to_https=False)
        if url.endswith("/.git/HEAD"):
            return HttpObservation(url=url, status=200, headers={}, body_preview="ref: refs/heads/main")
        if url.endswith("/.env"):
            return HttpObservation(url=url, status=200, headers={}, body_preview="AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF")
        if url.endswith("/admin"):
            return HttpObservation(url=url, status=200, headers={}, body_preview="Admin login")
        if url.endswith("/swagger.json"):
            return HttpObservation(url=url, status=200, headers={"content-type": "application/json"}, body_preview='{"openapi":"3.0.0"}')
        if url.endswith("/graphql"):
            return HttpObservation(
                url=url,
                status=200,
                headers={"content-type": "application/json"},
                body_preview='{"errors":[{"message":"GraphQL introspection disabled"}]}',
            )
        if url.endswith("/actuator"):
            return HttpObservation(url=url, status=200, headers={}, body_preview='{"_links":{"self":{"href":"/actuator"}}}')
        if url.endswith("/metrics"):
            return HttpObservation(url=url, status=200, headers={}, body_preview='{"names":["http.server.requests"]}')
        if url.endswith("/manage/health"):
            return HttpObservation(url=url, status=200, headers={}, body_preview='{"status":"UP"}')
        if url.endswith("/backup"):
            return HttpObservation(
                url="http://10.0.0.5/account/reset?id=42&sort=asc&file=report.txt&url=https://example.com",
                status=200,
                headers={},
                body_preview='<form action="/account/reset" method="post"><input name="email"><input name="token"><input type="file" name="upload"></form> reset password localStorage',
            )
        if url.endswith("/crossdomain.xml"):
            return HttpObservation(url=url, status=200, headers={"content-type": "application/xml"}, body_preview='<cross-domain-policy></cross-domain-policy>')
        if headers and headers.get("Origin") == "https://accuscanner-origin.example":
            return HttpObservation(
                url=url,
                status=200,
                headers={
                    "access-control-allow-origin": "https://accuscanner-origin.example",
                    "access-control-allow-credentials": "true",
                },
                redirected_to_https=False,
            )
        if url.startswith("http://10.0.0.5"):
            return HttpObservation(
                url=url,
                status=200,
                headers={
                    "server": "nginx/1.25",
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                    "www-authenticate": 'Bearer realm="example-api"',
                },
                body_preview="Index of / Welcome to nginx phpmyadmin",
                cookies=["sessionid=abc"],
                redirected_to_https=False,
            )
        if url.startswith("https://10.0.0.5"):
            return HttpObservation(
                url=url,
                status=200,
                headers={"server": "nginx/1.25", "x-frame-options": "DENY", "dav": "1,2"},
                body_preview="PostgreSQL ERROR: syntax error at or near SELECT soapenv:Envelope PHP Warning: include() failed",
                cookies=["sessionid=abc; Secure"],
                redirected_to_https=False,
            )
        return HttpObservation(
            url=url,
            status=200,
            headers={"server": "nginx/1.25", "x-frame-options": "DENY"},
            body_preview="Welcome to nginx",
            cookies=["sessionid=abc; Secure"],
            redirected_to_https=False,
        )

    mock_fetch.side_effect = fake_fetch
    findings = list(HttpSecurityCheck().run([sample_host()], "10.0.0.5"))
    ids = {finding.id for finding in findings}
    assert {"HTTP-005", "HTTP-001", "HTTP-002", "HTTP-004", "HTTP-009", "HTTP-011", "HTTP-012"} <= ids
    assert "HTTP-013" in ids
    assert "HTTP-051-aws_access_key" in ids
    assert "HTTP-019" in ids
    assert "HTTP-023" in ids or "HTTP-024" in ids
    assert "HTTP-037" in ids
    assert "HTTP-040" in ids
    assert "HTTP-043" in ids
    assert "HTTP-044" in ids
    assert "HTTP-045" in ids
    assert "HTTP-046" in ids
    assert "HTTP-047" in ids
    assert "HTTP-048" in ids
    assert "HTTP-049" in ids
    assert "HTTP-050" in ids
    assert "HTTP-052-postgresql" in ids
    assert "HTTP-053" in ids
    assert "HTTP-054" in ids
    assert "HTTP-058-php" in ids
    assert "HTTP-059" in ids
    assert "HTTP-060" in ids
    assert "HTTP-061" in ids
    assert "HTTP-062" in ids
    assert "HTTP-063" in ids
    assert "HTTP-064" in ids
    assert "HTTP-066" in ids
    assert "HTTP-067" in ids


@patch("mininessus.checks.http.fetch_http_observation")
def test_http_security_check_prefers_requested_hostname_for_web_checks(mock_fetch):
    def fake_fetch(
        url: str,
        timeout: int = 5,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpObservation:
        return HttpObservation(
            url=url,
            status=200,
            headers={"server": "cloudflare"},
            body_preview="Welcome to nginx",
            redirected_to_https=False,
        )

    mock_fetch.side_effect = fake_fetch
    findings = list(HttpSecurityCheck().run([sample_host()], "https://msp365.sa1cloud.com"))

    assert findings
    assert all(finding.target == "msp365.sa1cloud.com" for finding in findings)
    observed_urls = [call.args[0] for call in mock_fetch.call_args_list]
    assert any(url.startswith("http://msp365.sa1cloud.com") for url in observed_urls)
    assert not any(url.startswith("http://10.0.0.5") for url in observed_urls)


@patch("mininessus.checks.http.fetch_http_observation")
def test_http_security_check_discovers_same_host_attack_surface(mock_fetch):
    def fake_fetch(
        url: str,
        timeout: int = 5,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpObservation:
        if method in {"OPTIONS", "TRACE"}:
            return HttpObservation(url=url, status=405, headers={}, redirected_to_https=False)
        if url == "https://app.example":
            return HttpObservation(
                url=url,
                status=200,
                headers={"server": "nginx"},
                body_preview='<a href="/portal?id=7">Portal</a><script src="/static/app.js"></script><form action="/submit"><input name="search"></form>',
                redirected_to_https=False,
            )
        if url == "https://app.example/portal?id=7":
            return HttpObservation(url=url, status=200, headers={"server": "nginx"}, body_preview="Portal", redirected_to_https=False)
        if url == "https://app.example/submit":
            return HttpObservation(url=url, status=200, headers={"server": "nginx"}, body_preview="Submit", redirected_to_https=False)
        if url == "https://app.example/static/app.js":
            return HttpObservation(url=url, status=200, headers={"content-type": "application/javascript"}, body_preview="fetch('/api')", redirected_to_https=False)
        return HttpObservation(url=url, status=404, headers={}, body_preview="Not Found", redirected_to_https=False)

    host = HostResult(
        address="203.0.113.10",
        hostname="app.example",
        status="up",
        ports=[PortService(port=443, protocol="tcp", state="open", service="https", tunnel="ssl")],
    )

    mock_fetch.side_effect = fake_fetch
    findings = list(HttpSecurityCheck().run([host], "https://app.example"))

    surface_ids = {finding.id for finding in findings if finding.category == "attack_surface"}
    assert "HTTP-068-page" in surface_ids
    assert "HTTP-068-form_action" in surface_ids
    assert "HTTP-068-script_asset" in surface_ids
    assert "HTTP-068-query_parameter" in surface_ids
    assert "HTTP-068-form_field" in surface_ids
    assert "HTTP-068-script_endpoint" in surface_ids


@patch("mininessus.checks.http.fetch_http_observation")
def test_http_security_check_uses_robots_and_sitemap_as_discovery_seeds(mock_fetch):
    def fake_fetch(
        url: str,
        timeout: int = 5,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpObservation:
        if method in {"OPTIONS", "TRACE"}:
            return HttpObservation(url=url, status=405, headers={}, redirected_to_https=False)
        if url == "https://app.example":
            return HttpObservation(url=url, status=200, headers={"server": "nginx"}, body_preview="Home", redirected_to_https=False)
        if url == "https://app.example/robots.txt":
            return HttpObservation(url=url, status=200, headers={"content-type": "text/plain"}, body_preview="Allow: /hidden\nDisallow: /private/report.pdf\nAllow: /images/logo.png", redirected_to_https=False)
        if url == "https://app.example/sitemap.xml":
            return HttpObservation(url=url, status=200, headers={"content-type": "application/xml"}, body_preview="<urlset><url><loc>https://app.example/catalog</loc></url></urlset>", redirected_to_https=False)
        if url in {"https://app.example/hidden", "https://app.example/catalog"}:
            return HttpObservation(url=url, status=200, headers={"server": "nginx"}, body_preview="Page", redirected_to_https=False)
        if url == "https://app.example/images/logo.png":
            return HttpObservation(url=url, status=200, headers={"content-type": "image/png"}, body_preview="", redirected_to_https=False)
        return HttpObservation(url=url, status=404, headers={}, body_preview="Not Found", redirected_to_https=False)

    host = HostResult(
        address="203.0.113.10",
        hostname="app.example",
        status="up",
        ports=[PortService(port=443, protocol="tcp", state="open", service="https", tunnel="ssl")],
    )

    mock_fetch.side_effect = fake_fetch
    findings = list(HttpSecurityCheck().run([host], "https://app.example"))

    evidences = {finding.evidence for finding in findings if finding.category == "attack_surface"}
    assert "page: https://app.example/hidden" in evidences
    assert "page: https://app.example/catalog" in evidences
    assert "document: https://app.example/private/report.pdf" in evidences
    assert "static_asset: https://app.example/images/logo.png" in evidences


@patch("mininessus.checks.http.fetch_http_observation")
def test_http_security_check_does_not_flag_password_reset_from_loose_training_text(mock_fetch):
    def fake_fetch(
        url: str,
        timeout: int = 5,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpObservation:
        if method in {"OPTIONS", "TRACE"}:
            return HttpObservation(url=url, status=405, headers={}, redirected_to_https=False)
        return HttpObservation(
            url=url,
            status=200,
            headers={"server": "nginx"},
            body_preview="This training page discusses password reset poisoning and forgot password attacks.",
            redirected_to_https=False,
        )

    host = HostResult(
        address="203.0.113.10",
        hostname="app.example",
        status="up",
        ports=[PortService(port=443, protocol="tcp", state="open", service="https", tunnel="ssl")],
    )

    mock_fetch.side_effect = fake_fetch
    findings = list(HttpSecurityCheck().run([host], "https://app.example"))

    assert "HTTP-063" not in {finding.id for finding in findings}


@patch("mininessus.checks.http.fetch_http_observation")
def test_http_security_check_does_not_treat_meta_names_or_partial_asset_paths_as_surface(mock_fetch):
    def fake_fetch(
        url: str,
        timeout: int = 5,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpObservation:
        if method in {"OPTIONS", "TRACE"}:
            return HttpObservation(url=url, status=405, headers={}, redirected_to_https=False)
        if url == "https://app.example":
            return HttpObservation(
                url=url,
                status=200,
                headers={"server": "nginx"},
                body_preview='<meta name="viewport" content="width=device-width"><a href="/images/b">broken</a>',
                redirected_to_https=False,
            )
        return HttpObservation(url=url, status=404, headers={}, body_preview="Not Found", redirected_to_https=False)

    host = HostResult(
        address="203.0.113.10",
        hostname="app.example",
        status="up",
        ports=[PortService(port=443, protocol="tcp", state="open", service="https", tunnel="ssl")],
    )

    mock_fetch.side_effect = fake_fetch
    findings = list(HttpSecurityCheck().run([host], "https://app.example"))

    evidences = {finding.evidence for finding in findings if finding.category == "attack_surface"}
    assert "form_field: viewport" not in evidences
    assert "page: https://app.example/images/b" not in evidences


@patch("mininessus.checks.tls.inspect_tls_certificate")
def test_tls_check_detects_expired_and_self_signed(mock_inspect):
    mock_inspect.return_value = TLSDetails(
        not_after="Jan 01 00:00:00 2020 GMT",
        subject_cn="app.internal",
        issuer_cn="app.internal",
        self_signed=True,
        tls_version="TLSv1",
        cipher="ECDHE-RSA-AES128-SHA",
        san_dns_names=["app.internal"],
        validation_error="certificate verify failed: self-signed certificate",
    )
    findings = list(TlsCertificateCheck().run([sample_host()], "10.0.0.5"))
    ids = {finding.id for finding in findings}
    assert {"TLS-001", "TLS-002", "TLS-003", "TLS-008"} <= ids


@patch("mininessus.checks.tls.inspect_tls_certificate")
def test_tls_check_prefers_requested_hostname(mock_inspect):
    mock_inspect.return_value = TLSDetails(
        not_after="Jan 01 00:00:00 2030 GMT",
        subject_cn="msp365.sa1cloud.com",
        issuer_cn="Example CA",
        self_signed=False,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        san_dns_names=["msp365.sa1cloud.com"],
        validation_error=None,
    )

    list(TlsCertificateCheck().run([sample_host()], "https://msp365.sa1cloud.com"))

    mock_inspect.assert_called_once_with("msp365.sa1cloud.com", port=443)


@patch("mininessus.checks.tls.inspect_tls_certificate")
def test_tls_check_accepts_wildcard_san_without_hostname_mismatch(mock_inspect):
    mock_inspect.return_value = TLSDetails(
        not_after="Jan 01 00:00:00 2030 GMT",
        subject_cn="sa1cloud.com",
        issuer_cn="Example CA",
        self_signed=False,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        san_dns_names=["*.sa1cloud.com", "sa1cloud.com"],
        validation_error=None,
    )

    findings = list(TlsCertificateCheck().run([sample_host()], "https://msp365.sa1cloud.com"))

    assert "TLS-007" not in {finding.id for finding in findings}


def test_banner_exposure_check_reports_service_metadata():
    findings = list(BannerExposureCheck().run([sample_host()], "10.0.0.5"))
    assert any(finding.id == "BANNER-21" for finding in findings)


@patch("mininessus.checks.http.fetch_http_observation")
def test_http_security_check_skips_api_auth_finding_when_redirected_to_login(mock_fetch):
    def fake_fetch(
        url: str,
        timeout: int = 5,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpObservation:
        if method == "OPTIONS":
            return HttpObservation(url=url, status=405, headers={}, redirected_to_https=False)
        if method == "TRACE":
            return HttpObservation(url=url, status=405, headers={}, redirected_to_https=False)
        if url.endswith("/manage/health"):
            return HttpObservation(
                url="https://msp365.sa1cloud.com:8443/manage/account/login?redirect=%2Fmanage%2Fhealth",
                status=200,
                headers={},
                body_preview="UniFi Network Login",
                redirected_to_https=False,
            )
        if url == "https://msp365.sa1cloud.com:8443":
            return HttpObservation(
                url=url,
                status=200,
                headers={"server": "cloudflare", "x-frame-options": "DENY"},
                body_preview="Portal",
                redirected_to_https=False,
            )
        return HttpObservation(
            url=url,
            status=404,
            headers={},
            body_preview="Not Found",
            redirected_to_https=False,
        )

    host = HostResult(
        address="104.21.45.46",
        hostname="msp365.sa1cloud.com",
        status="up",
        ports=[PortService(port=8443, protocol="tcp", state="open", service="http", tunnel="ssl")],
    )

    mock_fetch.side_effect = fake_fetch
    findings = list(HttpSecurityCheck().run([host], "https://msp365.sa1cloud.com"))

    assert "HTTP-048" not in {finding.id for finding in findings}


@patch("mininessus.checks.services._send_http_request")
@patch("mininessus.checks.services._send_https_request")
@patch("mininessus.checks.services._send_tcp_payload")
@patch("mininessus.checks.services.ftplib.FTP")
def test_service_exposure_check_reports_active_service_responses(mock_ftp_class, mock_tcp, mock_https, mock_http):
    ftp_instance = mock_ftp_class.return_value.__enter__.return_value
    ftp_instance.getwelcome.return_value = "220 Anonymous access allowed"

    def fake_tcp(host: str, port: int, payload: bytes, timeout: int = 3) -> bytes:
        if port == 6379:
            return b"+PONG\r\n"
        if port == 27017:
            return b"mongo"
        if port == 445:
            return b"\x00\x00\x00\x10SMB"
        if port == 3389:
            return b"\x03\x00\x00\x13\xd0"
        return b""

    def fake_http(host: str, port: int, payload: bytes, timeout: int = 3) -> bytes:
        if port == 2375:
            return b'{"ApiVersion":"1.44"}'
        if port == 9200:
            return b'{"cluster_name":"lab-es"}'
        if port == 5985:
            return b"HTTP/1.1 200 OK\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\nWSMan"
        if port == 2379:
            return b'{"etcdserver":"3.5.0","etcdcluster":"3.5.0"}'
        return b""

    def fake_https(host: str, port: int, payload: bytes, timeout: int = 3) -> bytes:
        if port == 5986:
            return b"HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\nWSMan"
        if port == 6443:
            return b'{"major":"1","minor":"28","gitVersion":"v1.28.0"}'
        if port == 10250:
            return b"HTTP/1.1 401 Unauthorized\r\n\r\nunauthorized"
        return b""

    mock_tcp.side_effect = fake_tcp
    mock_https.side_effect = fake_https
    mock_http.side_effect = fake_http

    host = HostResult(
        address="10.0.0.6",
        status="up",
        ports=[
            PortService(port=21, protocol="tcp", state="open", service="ftp"),
            PortService(port=445, protocol="tcp", state="open", service="microsoft-ds"),
            PortService(port=3389, protocol="tcp", state="open", service="ms-wbt-server"),
            PortService(port=5985, protocol="tcp", state="open", service="http"),
            PortService(port=5986, protocol="tcp", state="open", service="https"),
            PortService(port=6379, protocol="tcp", state="open", service="redis"),
            PortService(port=6443, protocol="tcp", state="open", service="https"),
            PortService(port=10250, protocol="tcp", state="open", service="https"),
            PortService(port=2379, protocol="tcp", state="open", service="etcd"),
            PortService(port=2375, protocol="tcp", state="open", service="docker"),
            PortService(port=9200, protocol="tcp", state="open", service="elasticsearch"),
            PortService(port=27017, protocol="tcp", state="open", service="mongodb"),
        ],
    )

    findings = list(ServiceExposureCheck().run([host], "10.0.0.6"))
    ids = {finding.id for finding in findings}
    assert {"SVC-6379", "FTP-001", "REDIS-001", "DOCKER-001", "ES-001", "MONGO-001"} <= ids
    assert {"SMB-001", "RDP-001", "WINRM-009", "WINRM-010", "K8S-001", "K8S-002", "K8S-003"} <= ids

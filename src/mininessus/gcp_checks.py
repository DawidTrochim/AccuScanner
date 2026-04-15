from __future__ import annotations

import logging
from collections.abc import Iterable

from .checks.ports import RISKY_PORTS
from .models import Finding, build_finding
from .utils import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)

try:
    from google.cloud import compute_v1, storage
except ImportError:  # pragma: no cover
    compute_v1 = None
    storage = None


def run_gcp_checks(project_id: str | None = None) -> list[Finding]:
    if compute_v1 is None or storage is None:
        return [
            build_finding(
                finding_id="GCP-000",
                title="GCP checks unavailable",
                severity="info",
                category="gcp",
                target="gcp",
                description="Google Cloud SDK dependencies are not installed, so GCP checks were skipped.",
                evidence="Install the GCP optional dependencies and authenticate to Google Cloud to enable cloud checks.",
                recommendation="Install with `pip install -e .[gcp]` and configure GCP credentials before using GCP checks.",
                confidence="high",
                tags=["cloud", "gcp"],
            )
        ]
    if not project_id:
        return [
            build_finding(
                finding_id="GCP-001",
                title="GCP project ID not provided",
                severity="info",
                category="gcp",
                target="gcp",
                description="GCP checks require a project ID to enumerate resources.",
                evidence="No project ID was supplied.",
                recommendation="Provide `--gcp-project-id` or enable GCP checks with a configured project.",
                confidence="high",
                tags=["cloud", "gcp"],
            )
        ]

    findings: list[Finding] = []
    findings.extend(_check_firewall_rules(project_id))
    findings.extend(_check_public_instances(project_id))
    findings.extend(_check_public_buckets(project_id))
    findings.extend(_check_service_accounts(project_id))
    return findings


def _check_firewall_rules(project_id: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    try:
        client = compute_v1.FirewallsClient()
        for rule in client.list(project=project_id):
            if getattr(rule, "direction", "") != "INGRESS":
                continue
            source_ranges = set(getattr(rule, "source_ranges", []) or [])
            if not source_ranges & {"0.0.0.0/0", "::/0"}:
                continue
            for allowed in getattr(rule, "allowed", []) or []:
                ports = [int(port) for port in (getattr(allowed, "ports", []) or []) if str(port).isdigit()]
                if any(port in RISKY_PORTS for port in ports):
                    findings.append(
                        build_finding(
                            finding_id="GCP-NET-001",
                            title="GCP firewall rule exposes risky ports to the internet",
                            severity="high",
                            category="gcp_network",
                            target=getattr(rule, "name", "unknown-firewall"),
                            description="A GCP firewall rule allows internet ingress on one or more risky ports.",
                            evidence=f"Sources: {sorted(source_ranges)}; ports: {ports}",
                            recommendation="Restrict firewall rules to trusted source ranges and avoid direct exposure of management services.",
                            confidence="high",
                            tags=["cloud", "gcp", "network"],
                        )
                    )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate GCP firewall rules for project %s: %s", project_id, exc)
    return findings


def _check_public_instances(project_id: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    try:
        client = compute_v1.InstancesClient()
        aggregated = client.aggregated_list(project=project_id)
        for _, scoped_list in aggregated:
            for instance in getattr(scoped_list, "instances", []) or []:
                public_ips = []
                for interface in getattr(instance, "network_interfaces", []) or []:
                    for access_config in getattr(interface, "access_configs", []) or []:
                        nat_ip = getattr(access_config, "nat_i_p", None) or getattr(access_config, "nat_ip", None)
                        if nat_ip:
                            public_ips.append(nat_ip)
                if public_ips:
                    findings.append(
                        build_finding(
                            finding_id="GCP-COMP-001",
                            title="Public GCP compute instance detected",
                            severity="info",
                            category="gcp_inventory",
                            target=getattr(instance, "name", "unknown-instance"),
                            description="The compute instance has a public IP address and should be included in exposure review.",
                            evidence=f"Public IPs: {', '.join(public_ips)}",
                            recommendation="Confirm the instance requires direct internet exposure and is covered by hardening controls.",
                            confidence="high",
                            tags=["cloud", "gcp", "compute"],
                        )
                    )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate GCP instances for project %s: %s", project_id, exc)
    return findings


def _check_public_buckets(project_id: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    try:
        client = storage.Client(project=project_id)
        for bucket in client.list_buckets(project=project_id):
            iam_policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in getattr(iam_policy, "bindings", []):
                members = set(binding.get("members", []))
                if members & {"allUsers", "allAuthenticatedUsers"}:
                    findings.append(
                        build_finding(
                            finding_id="GCP-STOR-001",
                            title="GCP bucket may be publicly accessible",
                            severity="high",
                            category="gcp_storage",
                            target=bucket.name,
                            description="The bucket IAM policy includes public principals.",
                            evidence=f"Role: {binding.get('role')}; members: {sorted(members)}",
                            recommendation="Remove public members unless the bucket is explicitly intended for public content.",
                            confidence="high",
                            tags=["cloud", "gcp", "storage"],
                        )
                    )
                    break
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate GCP buckets for project %s: %s", project_id, exc)
    return findings


def _check_service_accounts(project_id: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    try:
        from google.cloud import iam_admin_v1
    except ImportError:  # pragma: no cover
        return []

    try:
        client = iam_admin_v1.IAMClient()
        parent = f"projects/{project_id}"
        for account in client.list_service_accounts(request={"name": parent}):
            email = getattr(account, "email", "unknown-service-account")
            findings.append(
                build_finding(
                    finding_id="GCP-IAM-001",
                    title="GCP service account discovered",
                    severity="info",
                    category="gcp_iam",
                    target=email,
                    description="A Google Cloud service account was discovered and should be reviewed for privilege scope and key management.",
                    evidence=f"Service account: {email}",
                    recommendation="Review service account roles, key usage, and whether the principal remains necessary.",
                    confidence="high",
                    tags=["cloud", "gcp", "iam"],
                )
            )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate GCP service accounts for project %s: %s", project_id, exc)
    return findings

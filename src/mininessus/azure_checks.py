from __future__ import annotations

import logging
import os
from collections.abc import Iterable

from .checks.ports import RISKY_PORTS
from .models import Finding, build_finding
from .utils import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import SubscriptionClient
    from azure.mgmt.storage import StorageManagementClient
except ImportError:  # pragma: no cover
    DefaultAzureCredential = None
    ComputeManagementClient = None
    NetworkManagementClient = None
    SubscriptionClient = None
    StorageManagementClient = None


def run_azure_checks(subscription_id: str | None = None) -> list[Finding]:
    if DefaultAzureCredential is None:
        return [
            build_finding(
                finding_id="AZURE-000",
                title="Azure checks unavailable",
                severity="info",
                category="azure",
                target="azure",
                description="Azure SDK dependencies are not installed, so Azure checks were skipped.",
                evidence="Install the Azure optional dependencies and authenticate with Azure to enable cloud checks.",
                recommendation="Install with `pip install -e .[azure]` and configure Azure credentials before using azure mode.",
                confidence="high",
                tags=["cloud", "azure"],
            )
        ]

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
    subscription_ids = [subscription_id] if subscription_id else _discover_subscription_ids(credential)
    findings: list[Finding] = []
    for sub_id in subscription_ids:
        public_ip_map = _collect_public_ip_map(credential, sub_id)
        risky_nsgs = _collect_risky_network_security_groups(credential, sub_id)
        findings.extend(_check_public_ip_inventory(public_ip_map))
        findings.extend(_check_network_security_groups(risky_nsgs))
        findings.extend(_correlate_public_vm_exposure(credential, sub_id, public_ip_map, risky_nsgs))
        findings.extend(_check_storage_accounts(credential, sub_id))
        findings.extend(_check_virtual_machines(credential, sub_id))
        findings.extend(_check_role_assignments(credential, sub_id))
    return findings


def _discover_subscription_ids(credential) -> list[str]:
    env_subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    if env_subscription_id:
        return [env_subscription_id]

    subscription_client = SubscriptionClient(credential)
    return [subscription.subscription_id for subscription in subscription_client.subscriptions.list()]


def _collect_public_ip_map(credential, subscription_id: str) -> dict[str, dict[str, str]]:
    client = NetworkManagementClient(credential, subscription_id)
    public_ip_map: dict[str, dict[str, str]] = {}
    try:
        public_ips = client.public_ip_addresses.list_all()
        for public_ip in public_ips:
            address = getattr(public_ip, "ip_address", None)
            if not address:
                continue
            public_ip_map[getattr(public_ip, "id", address)] = {"address": address, "resource_id": getattr(public_ip, "id", "")}
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate Azure public IPs for subscription %s: %s", subscription_id, exc)
    return public_ip_map


def _check_public_ip_inventory(public_ip_map: dict[str, dict[str, str]]) -> Iterable[Finding]:
    findings: list[Finding] = []
    for details in public_ip_map.values():
        findings.append(
            build_finding(
                finding_id="AZURE-NET-001",
                title="Public Azure IP address detected",
                severity="info",
                category="azure_network",
                target=details["address"],
                description="A public IP address is attached to an Azure resource and should be included in exposure reviews.",
                evidence=f"Resource: {details['resource_id']}",
                recommendation="Confirm the public IP is required and that attached services are appropriately hardened.",
                confidence="high",
                tags=["cloud", "azure", "network"],
            )
        )
    return findings


def _collect_risky_network_security_groups(credential, subscription_id: str) -> dict[str, dict[str, object]]:
    client = NetworkManagementClient(credential, subscription_id)
    risky_nsgs: dict[str, dict[str, object]] = {}
    try:
        groups = client.network_security_groups.list_all()
        for group in groups:
            risky_rules: list[str] = []
            risky_ports: set[int] = set()
            for rule in getattr(group, "security_rules", []) or []:
                access = getattr(rule, "access", "")
                direction = getattr(rule, "direction", "")
                source = getattr(rule, "source_address_prefix", "")
                destination_port = getattr(rule, "destination_port_range", "")
                if access != "Allow" or direction != "Inbound":
                    continue
                if source not in {"*", "Internet", "0.0.0.0/0"}:
                    continue
                if destination_port.isdigit() and int(destination_port) in RISKY_PORTS:
                    risky_rules.append(f"Rule: {rule.name}; source: {source}; port: {destination_port}")
                    risky_ports.add(int(destination_port))
            if risky_rules:
                group_id = getattr(group, "id", group.name)
                risky_nsgs[group_id] = {
                    "name": group.name,
                    "rules": risky_rules,
                    "ports": sorted(risky_ports),
                }
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate Azure NSGs for subscription %s: %s", subscription_id, exc)
    return risky_nsgs


def _check_network_security_groups(risky_nsgs: dict[str, dict[str, object]]) -> Iterable[Finding]:
    findings: list[Finding] = []
    for details in risky_nsgs.values():
        for rule in details["rules"]:
            findings.append(
                build_finding(
                    finding_id="AZURE-NET-002",
                    title="Azure NSG allows risky inbound internet access",
                    severity="high",
                    category="azure_network",
                    target=str(details["name"]),
                    description="The network security group allows inbound internet access on a risky port.",
                    evidence=str(rule),
                    recommendation="Restrict the NSG rule to approved source ranges or a controlled administrative path.",
                    confidence="high",
                    tags=["cloud", "azure", "network"],
                )
            )
    return findings


def _correlate_public_vm_exposure(
    credential,
    subscription_id: str,
    public_ip_map: dict[str, dict[str, str]],
    risky_nsgs: dict[str, dict[str, object]],
) -> Iterable[Finding]:
    if not public_ip_map or not risky_nsgs:
        return []

    client = NetworkManagementClient(credential, subscription_id)
    findings: list[Finding] = []
    try:
        interfaces = client.network_interfaces.list_all()
        for interface in interfaces:
            interface_public_ips = _interface_public_ip_addresses(interface, public_ip_map)
            if not interface_public_ips:
                continue
            nsg_id = getattr(getattr(interface, "network_security_group", None), "id", None)
            if nsg_id not in risky_nsgs:
                continue
            nsg_details = risky_nsgs[nsg_id]
            vm_name = _resource_name(getattr(getattr(interface, "virtual_machine", None), "id", None)) or interface.name
            findings.append(
                build_finding(
                    finding_id="AZURE-NET-003",
                    title="Public Azure workload is attached to a risky NSG",
                    severity="high",
                    category="azure_correlation",
                    target=vm_name,
                    description="A workload with a public IP address is attached to a network security group that exposes risky ports to the internet.",
                    evidence=(
                        f"Public IPs: {', '.join(interface_public_ips)}; "
                        f"NSG: {nsg_details['name']}; risky ports: {nsg_details['ports']}"
                    ),
                    recommendation="Restrict the exposed management ports to trusted ranges and remove unnecessary direct internet exposure.",
                    confidence="high",
                    tags=["cloud", "azure", "correlation"],
                )
            )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to correlate Azure public exposure for subscription %s: %s", subscription_id, exc)
    return findings


def _interface_public_ip_addresses(interface, public_ip_map: dict[str, dict[str, str]]) -> list[str]:
    addresses: list[str] = []
    for configuration in getattr(interface, "ip_configurations", []) or []:
        public_ip = getattr(configuration, "public_ip_address", None)
        public_ip_id = getattr(public_ip, "id", None)
        if public_ip_id in public_ip_map:
            addresses.append(public_ip_map[public_ip_id]["address"])
    return addresses


def _resource_name(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    return resource_id.rstrip("/").split("/")[-1] or None


def _check_storage_accounts(credential, subscription_id: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    client = StorageManagementClient(credential, subscription_id)
    try:
        accounts = client.storage_accounts.list()
        for account in accounts:
            public_access = getattr(account, "allow_blob_public_access", None)
            public_network = getattr(account, "public_network_access", None)
            if public_access:
                findings.append(
                    build_finding(
                        finding_id="AZURE-STOR-001",
                        title="Azure storage account allows blob public access",
                        severity="high",
                        category="azure_storage",
                        target=account.name,
                        description="The storage account permits blob public access.",
                        evidence=f"allow_blob_public_access={public_access}",
                        recommendation="Disable blob public access unless the account is explicitly intended for public content.",
                        confidence="high",
                        tags=["cloud", "azure", "storage"],
                    )
                )
            if str(public_network).lower() == "enabled":
                findings.append(
                    build_finding(
                        finding_id="AZURE-STOR-002",
                        title="Azure storage account has public network access enabled",
                        severity="medium",
                        category="azure_storage",
                        target=account.name,
                        description="The storage account accepts traffic from public networks.",
                        evidence=f"public_network_access={public_network}",
                        recommendation="Prefer private endpoints or tightly scoped firewall rules where appropriate.",
                        confidence="medium",
                        tags=["cloud", "azure", "storage"],
                    )
                )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate Azure storage accounts for subscription %s: %s", subscription_id, exc)
    return findings


def _check_virtual_machines(credential, subscription_id: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    client = ComputeManagementClient(credential, subscription_id)
    try:
        virtual_machines = client.virtual_machines.list_all()
        for vm in virtual_machines:
            findings.append(
                build_finding(
                    finding_id="AZURE-COMP-001",
                    title="Azure VM discovered",
                    severity="info",
                    category="azure_inventory",
                    target=vm.name,
                    description="The virtual machine was discovered in the Azure subscription inventory.",
                    evidence=f"Resource ID: {vm.id}",
                    recommendation="Review whether the VM requires internet exposure and whether it is covered by baseline hardening controls.",
                    confidence="high",
                    tags=["cloud", "azure", "compute"],
                )
            )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate Azure virtual machines for subscription %s: %s", subscription_id, exc)
    return findings


def _check_role_assignments(credential, subscription_id: str) -> Iterable[Finding]:
    findings: list[Finding] = []
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient
    except ImportError:  # pragma: no cover
        return []

    client = AuthorizationManagementClient(credential, subscription_id)
    risky_role_markers = {"owner", "contributor", "user access administrator"}
    try:
        for assignment in client.role_assignments.list():
            role_definition_id = getattr(assignment, "role_definition_id", "") or ""
            role_name = role_definition_id.rstrip("/").split("/")[-1]
            if role_name.lower() not in risky_role_markers:
                continue
            findings.append(
                build_finding(
                    finding_id="AZURE-IAM-001",
                    title="Potentially privileged Azure role assignment detected",
                    severity="medium",
                    category="azure_iam",
                    target=getattr(assignment, "principal_id", "unknown-principal"),
                    description="A privileged Azure role assignment was detected and should be reviewed against least-privilege expectations.",
                    evidence=f"Role definition: {role_definition_id}; scope: {getattr(assignment, 'scope', 'unknown')}",
                    recommendation="Review privileged role assignments and restrict Owner or Contributor access to approved administrators only.",
                    confidence="medium",
                    tags=["cloud", "azure", "iam"],
                )
            )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to enumerate Azure role assignments for subscription %s: %s", subscription_id, exc)
    return findings

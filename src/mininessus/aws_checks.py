from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC, datetime

from .checks.ports import RISKY_PORTS
from .models import Finding, build_finding
from .utils import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = Exception


def run_aws_checks(region: str | None = None) -> list[Finding]:
    if boto3 is None:
        return [
            build_finding(
                finding_id="AWS-000",
                title="AWS checks unavailable",
                severity="info",
                category="aws",
                target="aws",
                description="boto3 is not installed, so AWS checks were skipped.",
                evidence="Install boto3 and configure AWS credentials to enable cloud checks.",
                recommendation="Install project dependencies and export valid AWS credentials before using aws mode.",
            )
        ]
    session = boto3.Session(region_name=region)
    findings: list[Finding] = []
    risky_groups = _collect_risky_security_groups(session)
    findings.extend(_check_s3_buckets(session))
    findings.extend(_check_security_groups(risky_groups))
    findings.extend(_summarize_public_ec2(session))
    findings.extend(_correlate_public_ec2_exposure(session, risky_groups))
    findings.extend(_check_public_rds(session))
    findings.extend(_check_internet_facing_load_balancers(session))
    findings.extend(_check_iam_password_policy(session))
    findings.extend(_check_iam_users_without_mfa(session))
    findings.extend(_check_stale_iam_access_keys(session))
    findings.extend(_check_iam_inline_policies(session))
    findings.extend(_check_public_snapshots(session))
    findings.extend(_check_public_amis(session))
    return findings


def _check_s3_buckets(session) -> Iterable[Finding]:
    findings: list[Finding] = []
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate S3 buckets: %s", exc)
        return []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            public_block = s3.get_public_access_block(Bucket=name)
            block_config = public_block.get("PublicAccessBlockConfiguration", {})
            if not all(block_config.get(flag, False) for flag in block_config):
                findings.append(
                    build_finding(
                        finding_id="AWS-S3-001",
                        title="S3 bucket may allow public access",
                        severity="high",
                        category="aws_s3",
                        target=name,
                        description="The bucket does not have all public access block settings enabled.",
                        evidence=str(block_config),
                        recommendation="Enable S3 Block Public Access and review bucket policies and ACLs.",
                    )
                )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchPublicAccessBlockConfiguration":
                findings.append(
                    build_finding(
                        finding_id="AWS-S3-001",
                        title="S3 bucket may allow public access",
                        severity="high",
                        category="aws_s3",
                        target=name,
                        description="No public access block configuration was present for the bucket.",
                        evidence="NoSuchPublicAccessBlockConfiguration",
                        recommendation="Enable S3 Block Public Access and review bucket policies and ACLs.",
                    )
                )
    return findings


def _collect_risky_security_groups(session) -> dict[str, dict[str, object]]:
    ec2 = session.client("ec2")
    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate security groups: %s", exc)
        return {}

    risky_groups: dict[str, dict[str, object]] = {}
    for group in groups:
        risky_rules: list[str] = []
        risky_ports: set[int] = set()
        for permission in group.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            for cidr in permission.get("IpRanges", []):
                if cidr.get("CidrIp") != "0.0.0.0/0":
                    continue
                if from_port in RISKY_PORTS or to_port in RISKY_PORTS:
                    risky_rules.append(f"Port range {from_port}-{to_port}, CIDR 0.0.0.0/0")
                    if isinstance(from_port, int):
                        risky_ports.add(from_port)
                    if isinstance(to_port, int):
                        risky_ports.add(to_port)
        if risky_rules:
            group_id = group.get("GroupId", "unknown")
            risky_groups[group_id] = {
                "name": group.get("GroupName", group_id),
                "rules": risky_rules,
                "ports": sorted(risky_ports),
            }
    return risky_groups


def _check_security_groups(risky_groups: dict[str, dict[str, object]]) -> Iterable[Finding]:
    findings: list[Finding] = []
    for details in risky_groups.values():
        group_name = str(details["name"])
        for rule in details["rules"]:
            findings.append(
                build_finding(
                    finding_id="AWS-EC2-001",
                    title="Security group exposes risky port to the internet",
                    severity="high",
                    category="aws_network",
                    target=group_name,
                    description="The security group allows 0.0.0.0/0 access on a risky port.",
                    evidence=str(rule),
                    recommendation="Restrict ingress to approved source ranges or a VPN/bastion path.",
                    tags=["cloud", "aws", "network"],
                    confidence="high",
                )
            )
    return findings


def _correlate_public_ec2_exposure(session, risky_groups: dict[str, dict[str, object]]) -> Iterable[Finding]:
    findings: list[Finding] = []
    if not risky_groups:
        return findings

    ec2 = session.client("ec2")
    try:
        reservations = ec2.describe_instances().get("Reservations", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to correlate EC2 exposure: %s", exc)
        return []
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            public_ip = instance.get("PublicIpAddress")
            if not public_ip:
                continue
            group_matches = [risky_groups[group["GroupId"]] for group in instance.get("SecurityGroups", []) if group.get("GroupId") in risky_groups]
            if not group_matches:
                continue
            ports = sorted({port for match in group_matches for port in match.get("ports", [])})
            group_names = ", ".join(str(match["name"]) for match in group_matches)
            findings.append(
                build_finding(
                    finding_id="AWS-EC2-003",
                    title="Public EC2 instance is attached to risky internet-facing security groups",
                    severity="high",
                    category="aws_correlation",
                    target=instance.get("InstanceId", public_ip),
                    description="The instance has a public IP address and is attached to security groups exposing risky ports to the internet.",
                    evidence=f"Public IP: {public_ip}; security groups: {group_names}; risky ports: {ports}",
                    recommendation="Remove direct internet exposure where possible and restrict risky management ports to trusted source ranges only.",
                    tags=["cloud", "aws", "correlation"],
                    confidence="high",
                )
            )
    return findings


def _summarize_public_ec2(session) -> Iterable[Finding]:
    findings: list[Finding] = []
    ec2 = session.client("ec2")
    try:
        reservations = ec2.describe_instances().get("Reservations", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate EC2 instances: %s", exc)
        return []
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            public_ip = instance.get("PublicIpAddress")
            if public_ip:
                findings.append(
                    build_finding(
                        finding_id="AWS-EC2-002",
                        title="Public EC2 instance detected",
                        severity="info",
                        category="aws_inventory",
                        target=instance.get("InstanceId", public_ip),
                        description="The instance has a public IPv4 address and should be included in exposure reviews.",
                        evidence=f"Public IP: {public_ip}",
                        recommendation="Confirm the instance requires direct internet exposure and is covered by hardening controls.",
                    )
                )
    return findings


def _check_public_rds(session) -> Iterable[Finding]:
    findings: list[Finding] = []
    rds = session.client("rds")
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate RDS instances: %s", exc)
        return []
    for instance in instances:
        if instance.get("PubliclyAccessible"):
            findings.append(
                build_finding(
                    finding_id="AWS-RDS-001",
                    title="Public RDS instance detected",
                    severity="high",
                    category="aws_rds",
                    target=instance.get("DBInstanceIdentifier", "unknown-rds"),
                    description="The RDS instance is marked as publicly accessible.",
                    evidence=f"Endpoint: {instance.get('Endpoint', {}).get('Address', 'unknown')}",
                    recommendation="Confirm public accessibility is required and restrict inbound access to approved ranges only.",
                )
            )
    return findings


def _check_internet_facing_load_balancers(session) -> Iterable[Finding]:
    findings: list[Finding] = []
    for service_name in ("elbv2", "elb"):
        client = session.client(service_name)
        try:
            if service_name == "elbv2":
                load_balancers = client.describe_load_balancers().get("LoadBalancers", [])
                for load_balancer in load_balancers:
                    if load_balancer.get("Scheme") == "internet-facing":
                        findings.append(
                            build_finding(
                                finding_id="AWS-ELB-001",
                                title="Internet-facing load balancer detected",
                                severity="info",
                                category="aws_network",
                                target=load_balancer.get("LoadBalancerName", "unknown-elb"),
                                description="The load balancer is publicly reachable and should be reviewed as part of exposure management.",
                                evidence=f"DNS: {load_balancer.get('DNSName', 'unknown')}",
                                recommendation="Review listener rules, TLS configuration, and upstream targets for appropriate hardening.",
                            )
                        )
            else:
                load_balancers = client.describe_load_balancers().get("LoadBalancerDescriptions", [])
                for load_balancer in load_balancers:
                    if load_balancer.get("Scheme") == "internet-facing":
                        findings.append(
                            build_finding(
                                finding_id="AWS-ELB-001",
                                title="Internet-facing load balancer detected",
                                severity="info",
                                category="aws_network",
                                target=load_balancer.get("LoadBalancerName", "unknown-elb"),
                                description="The load balancer is publicly reachable and should be reviewed as part of exposure management.",
                                evidence=f"DNS: {load_balancer.get('DNSName', 'unknown')}",
                                recommendation="Review listener rules, TLS configuration, and upstream targets for appropriate hardening.",
                            )
                        )
        except (BotoCoreError, ClientError) as exc:
            logger.warning("Failed to enumerate %s load balancers: %s", service_name, exc)
    return findings


def _check_iam_password_policy(session) -> Iterable[Finding]:
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "NoSuchEntity":
            return [
                build_finding(
                    finding_id="AWS-IAM-001",
                    title="IAM account password policy missing",
                    severity="medium",
                    category="aws_iam",
                    target="iam-account",
                    description="No IAM account password policy was configured.",
                    evidence="NoSuchEntity",
                    recommendation="Configure an IAM password policy that enforces minimum length and complexity requirements.",
                )
            ]
        logger.warning("Failed to fetch IAM password policy: %s", exc)
        return []
    except BotoCoreError as exc:
        logger.warning("Failed to fetch IAM password policy: %s", exc)
        return []

    weak_controls: list[str] = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        weak_controls.append("minimum length below 14")
    if not policy.get("RequireSymbols"):
        weak_controls.append("symbols not required")
    if not policy.get("RequireNumbers"):
        weak_controls.append("numbers not required")
    if not policy.get("RequireUppercaseCharacters"):
        weak_controls.append("uppercase characters not required")
    if not policy.get("RequireLowercaseCharacters"):
        weak_controls.append("lowercase characters not required")

    if not weak_controls:
        return []

    return [
        build_finding(
            finding_id="AWS-IAM-002",
            title="Weak IAM account password policy",
            severity="medium",
            category="aws_iam",
            target="iam-account",
            description="The IAM account password policy does not enforce common baseline controls.",
            evidence=", ".join(weak_controls),
            recommendation="Strengthen the IAM password policy to require length and complexity suitable for administrative access.",
        )
    ]


def _check_public_snapshots(session) -> Iterable[Finding]:
    ec2 = session.client("ec2")
    try:
        snapshots = ec2.describe_snapshots(OwnerIds=["self"], RestorableByUserIds=["all"]).get("Snapshots", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate public snapshots: %s", exc)
        return []
    return [
        build_finding(
            finding_id="AWS-EBS-001",
            title="Public EBS snapshot detected",
            severity="high",
            category="aws_storage",
            target=snapshot.get("SnapshotId", "unknown-snapshot"),
            description="The EBS snapshot is restorable by all AWS accounts.",
            evidence=f"Volume size: {snapshot.get('VolumeSize', 'unknown')} GiB",
            recommendation="Restrict snapshot sharing to explicit AWS account IDs and review contained data.",
        )
        for snapshot in snapshots
    ]


def _check_public_amis(session) -> Iterable[Finding]:
    ec2 = session.client("ec2")
    try:
        images = ec2.describe_images(Owners=["self"], ExecutableUsers=["all"]).get("Images", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate public AMIs: %s", exc)
        return []
    return [
        build_finding(
            finding_id="AWS-AMI-001",
            title="Public AMI detected",
            severity="medium",
            category="aws_compute",
            target=image.get("ImageId", "unknown-ami"),
            description="The AMI is executable by all AWS accounts.",
            evidence=image.get("Name", "Unnamed image"),
            recommendation="Restrict AMI launch permissions to intended accounts only.",
        )
        for image in images
    ]


def _check_iam_users_without_mfa(session) -> Iterable[Finding]:
    iam = session.client("iam")
    findings: list[Finding] = []
    try:
        users = iam.list_users().get("Users", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate IAM users for MFA review: %s", exc)
        return []

    for user in users:
        user_name = user.get("UserName", "unknown-user")
        try:
            mfa_devices = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
            login_profile_present = True
            try:
                iam.get_login_profile(UserName=user_name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                    login_profile_present = False
                else:
                    raise
            if login_profile_present and not mfa_devices:
                findings.append(
                    build_finding(
                        finding_id="AWS-IAM-003",
                        title="IAM user with console access appears to lack MFA",
                        severity="high",
                        category="aws_iam",
                        target=user_name,
                        description="An IAM user appears to have a console login profile without a registered MFA device.",
                        evidence=f"UserName={user_name}; MFA devices={len(mfa_devices)}",
                        recommendation="Require MFA for IAM users with console access or migrate human access to identity federation.",
                        confidence="high",
                        tags=["cloud", "aws", "auth"],
                    )
                )
        except (BotoCoreError, ClientError) as exc:
            logger.warning("Failed MFA review for IAM user %s: %s", user_name, exc)
    return findings


def _check_stale_iam_access_keys(session) -> Iterable[Finding]:
    iam = session.client("iam")
    findings: list[Finding] = []
    try:
        users = iam.list_users().get("Users", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate IAM users for access key review: %s", exc)
        return []

    for user in users:
        user_name = user.get("UserName", "unknown-user")
        try:
            access_keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        except (BotoCoreError, ClientError) as exc:
            logger.warning("Failed to list access keys for IAM user %s: %s", user_name, exc)
            continue
        for access_key in access_keys:
            created = access_key.get("CreateDate")
            if created is None:
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            age_days = (datetime.now(UTC) - created).days
            if age_days <= 90:
                continue
            findings.append(
                build_finding(
                    finding_id="AWS-IAM-004",
                    title="IAM access key appears older than 90 days",
                    severity="medium",
                    category="aws_iam",
                    target=user_name,
                    description="An IAM access key appears older than 90 days and may not meet common key rotation baselines.",
                    evidence=f"AccessKeyId={access_key.get('AccessKeyId', 'unknown')}; age_days={age_days}",
                    recommendation="Rotate long-lived IAM access keys, prefer short-lived credentials, and remove unused keys.",
                    confidence="high",
                    tags=["cloud", "aws", "auth"],
                )
            )
    return findings


def _check_iam_inline_policies(session) -> Iterable[Finding]:
    iam = session.client("iam")
    findings: list[Finding] = []
    try:
        users = iam.list_users().get("Users", [])
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed to enumerate IAM users for inline policy review: %s", exc)
        return []

    for user in users:
        user_name = user.get("UserName", "unknown-user")
        try:
            policy_names = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])
        except (BotoCoreError, ClientError) as exc:
            logger.warning("Failed to list inline policies for IAM user %s: %s", user_name, exc)
            continue
        if not policy_names:
            continue
        findings.append(
            build_finding(
                finding_id="AWS-IAM-005",
                title="IAM user has inline policies attached",
                severity="medium",
                category="aws_iam",
                target=user_name,
                description="The IAM user has one or more inline policies attached directly to the principal.",
                evidence=f"Inline policies: {', '.join(policy_names)}",
                recommendation="Prefer centrally managed policies and review whether direct inline policies are still justified.",
                confidence="medium",
                tags=["cloud", "aws", "iam"],
            )
        )
    return findings

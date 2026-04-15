from types import SimpleNamespace

from mininessus.aws_checks import _collect_risky_security_groups, _correlate_public_ec2_exposure
from mininessus.azure_checks import _correlate_public_vm_exposure


class _AwsSession:
    def __init__(self, security_groups, reservations):
        self._security_groups = security_groups
        self._reservations = reservations

    def client(self, service_name: str):
        if service_name != "ec2":
            raise AssertionError(f"Unexpected service: {service_name}")
        return SimpleNamespace(
            describe_security_groups=lambda: {"SecurityGroups": self._security_groups},
            describe_instances=lambda: {"Reservations": self._reservations},
        )


class _AzureNetworkClient:
    def __init__(self, interfaces):
        self.network_interfaces = SimpleNamespace(list_all=lambda: interfaces)


def test_aws_cloud_correlation_flags_public_instance_with_risky_group():
    session = _AwsSession(
        security_groups=[
            {
                "GroupId": "sg-123",
                "GroupName": "internet-admin",
                "IpPermissions": [
                    {
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ],
        reservations=[
            {
                "Instances": [
                    {
                        "InstanceId": "i-123",
                        "PublicIpAddress": "18.0.0.10",
                        "SecurityGroups": [{"GroupId": "sg-123"}],
                    }
                ]
            }
        ],
    )

    risky_groups = _collect_risky_security_groups(session)
    findings = list(_correlate_public_ec2_exposure(session, risky_groups))

    assert len(findings) == 1
    assert findings[0].id == "AWS-EC2-003"
    assert "3389" in findings[0].evidence


def test_azure_cloud_correlation_flags_public_interface_with_risky_nsg():
    interfaces = [
        SimpleNamespace(
            name="nic-web-01",
            network_security_group=SimpleNamespace(id="/nsgs/risky"),
            virtual_machine=SimpleNamespace(id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-web-01"),
            ip_configurations=[
                SimpleNamespace(public_ip_address=SimpleNamespace(id="/publicIps/pip-1"))
            ],
        )
    ]
    credential = object()
    public_ip_map = {"/publicIps/pip-1": {"address": "20.0.0.15", "resource_id": "/publicIps/pip-1"}}
    risky_nsgs = {"/nsgs/risky": {"name": "risky-nsg", "ports": [3389], "rules": ["Rule: allow-rdp"]}}

    from mininessus import azure_checks

    original_client = azure_checks.NetworkManagementClient
    azure_checks.NetworkManagementClient = lambda credential, subscription_id: _AzureNetworkClient(interfaces)
    try:
        findings = list(_correlate_public_vm_exposure(credential, "sub-1", public_ip_map, risky_nsgs))
    finally:
        azure_checks.NetworkManagementClient = original_client

    assert len(findings) == 1
    assert findings[0].id == "AZURE-NET-003"
    assert "20.0.0.15" in findings[0].evidence


from mininessus.checks.base import BaseCheck


class ExampleSshPolicyCheck(BaseCheck):
    name = "example_custom_ssh"

    def run(self, hosts, target):
        findings = []
        for host in hosts:
            for port in host.ports:
                if port.state == "open" and port.port == 22:
                    findings.append(
                        self.finding(
                            finding_id="CUSTOM-SSH-001",
                            title="Example custom SSH review finding",
                            severity="info",
                            category="custom_policy",
                            target=host.address,
                            description="This sample plugin demonstrates how to add custom checks without editing the core package.",
                            evidence=f"SSH service observed on {host.address}:{port.port}",
                            recommendation="Replace this example with your own organization-specific security policy checks.",
                            confidence="high",
                            tags=["custom", "plugin", "ssh"],
                        )
                    )
        return findings


def get_checks():
    return [ExampleSshPolicyCheck()]

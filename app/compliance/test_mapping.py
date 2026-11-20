
from app.compliance.mapping import map_finding_to_compliance


def test_compliance_workflow():

    sample_findings = [
        # Storage findings
        {
            "resource_name": "teststorageaccount",
            "issue": "HTTPS-only traffic is disabled",
            "severity": "high"
        },
        {
            "resource_name": "teststorageaccount",
            "issue": "Storage account allows access from all networks",
            "severity": "high"
        },

        # NSG findings
        {
            "resource_name": "test-nsg",
            "issue": "SSH port 22 is exposed to the internet",
            "severity": "high"
        },
        {
            "resource_name": "test-nsg",
            "issue": "RDP port 3389 is exposed to the internet",
            "severity": "high"
        },
        {
            "resource_name": "test-nsg",
            "issue": "All ports are exposed to the internet",
            "severity": "critical"
        },

        # Key Vault findings
        {
            "resource_name": "test-keyvault",
            "issue": "Key Vault purge protection is disabled",
            "severity": "high"
        },
        {
            "resource_name": "test-keyvault",
            "issue": "Key Vault allows unrestricted public network access",
            "severity": "high"
        },

        # RBAC findings
        {
            "resource_name": "user-001",
            "issue": "Owner role assigned at subscription scope",
            "severity": "high"
        },
        {
            "resource_name": "user-002",
            "issue": "Contributor role assigned at subscription scope",
            "severity": "high"
        },

        # App Service findings
        {
            "resource_name": "insecure-web-app",
            "issue": "HTTPS-only traffic is disabled",
            "severity": "high"
        },
        {
            "resource_name": "insecure-web-app",
            "issue": "Weak minimum TLS version: 1.0",
            "severity": "high"
        },
        {
            "resource_name": "insecure-web-app",
            "issue": "Unencrypted FTP access is enabled",
            "severity": "medium"
        }
    ]

    mapped_findings = [
        map_finding_to_compliance(finding)
        for finding in sample_findings
    ]

    report = {
        "total_findings": len(mapped_findings),
        "findings": mapped_findings
    }

    print("CloudGuard AI Compliance Workflow")
    print("-" * 45)
    print("Total findings:", report["total_findings"])

    for finding in report["findings"]:
        print("\nResource:", finding["resource_name"])
        print("Issue:", finding["issue"])
        print("Severity:", finding["severity"])

        print("Compliance Mapping:")

        for control in finding["compliance"]:
            print(
                f"- {control['name']} | "
                f"{control['control']}"
            )

    assert report["total_findings"] == 12

    for finding in mapped_findings:
        assert len(finding["compliance"]) > 0

    print("\nCompliance workflow test passed!")


if __name__ == "__main__":
    test_compliance_workflow()

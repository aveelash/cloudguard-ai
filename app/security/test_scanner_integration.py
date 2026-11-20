
from unittest.mock import patch

from app.security.scanner import run_security_scan


def test_scanner_integration():

    sample_nsg_findings = [
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
        }
    ]

    sample_keyvault_findings = [
        {
            "resource_name": "test-keyvault",
            "issue": "Key Vault purge protection is disabled",
            "severity": "high"
        },
        {
            "resource_name": "test-keyvault",
            "issue": "Key Vault allows unrestricted public network access",
            "severity": "high"
        }
    ]

    sample_rbac_findings = [
        {
            "resource_name": "user-001",
            "issue": "Owner role assigned at subscription scope",
            "severity": "high"
        },
        {
            "resource_name": "user-002",
            "issue": "Contributor role assigned at subscription scope",
            "severity": "high"
        }
    ]

    sample_app_service_findings = [
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

    with (
        patch(
            "app.security.scanner.get_azure_resources",
            return_value=[]
        ),
        patch(
            "app.security.scanner.scan_azure_storage_accounts",
            return_value={
                "total_storage_accounts_scanned": 0,
                "findings": []
            }
        ),
        patch(
            "app.security.scanner.scan_azure_network_security_groups",
            return_value={
                "total_nsgs_scanned": 1,
                "findings": sample_nsg_findings
            }
        ),
        patch(
            "app.security.scanner.scan_azure_keyvaults",
            return_value={
                "total_keyvaults_scanned": 1,
                "findings": sample_keyvault_findings
            }
        ),
        patch(
            "app.security.scanner.scan_azure_role_assignments",
            return_value={
                "total_role_assignments_scanned": 2,
                "findings": sample_rbac_findings
            }
        ),
        patch(
            "app.security.scanner.scan_azure_app_services",
            return_value={
                "total_app_services_scanned": 1,
                "findings": sample_app_service_findings
            }
        )
    ):
        report = run_security_scan({})

    print("CloudGuard AI - Complete Scanner Integration")
    print("-" * 50)

    print("Resources scanned:", report["total_resources_scanned"])
    print("Storage accounts scanned:", report["storage_accounts_scanned"])
    print(
        "Network Security Groups scanned:",
        report["network_security_groups_scanned"]
    )
    print("Key Vaults scanned:", report["keyvaults_scanned"])
    print("Role assignments scanned:", report["role_assignments_scanned"])
    print("App Services scanned:", report["app_services_scanned"])
    print("Total findings:", report["total_findings"])

    for finding in report["findings"]:
        print("\nIssue:", finding["issue"])
        print("Severity:", finding["severity"])
        print("Compliance:", finding["compliance"])

    assert report["total_findings"] == 10
    assert report["network_security_groups_scanned"] == 1
    assert report["keyvaults_scanned"] == 1
    assert report["role_assignments_scanned"] == 2
    assert report["app_services_scanned"] == 1

    print("\nComplete scanner integration test passed!")


if __name__ == "__main__":
    test_scanner_integration()

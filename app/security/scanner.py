
from app.azure.inventory import get_azure_resources

from app.security.rules import check_resource_security
from app.security.storage_rules import scan_azure_storage_accounts
from app.security.network_rules import scan_azure_network_security_groups
from app.security.keyvault_rules import scan_azure_keyvaults
from app.security.authorization_rules import scan_azure_role_assignments
from app.security.app_service_rules import scan_azure_app_services

from app.compliance.mapping import map_finding_to_compliance


def run_security_scan(azure_config: dict):
    resources = get_azure_resources(azure_config)

    all_findings = []

    for resource in resources:
        findings = check_resource_security(resource)
        all_findings.extend(findings)

    storage_report = scan_azure_storage_accounts(azure_config)
    all_findings.extend(storage_report["findings"])

    network_report = scan_azure_network_security_groups(azure_config)
    all_findings.extend(network_report["findings"])

    keyvault_report = scan_azure_keyvaults(azure_config)
    all_findings.extend(keyvault_report["findings"])

    authorization_report = scan_azure_role_assignments(azure_config)
    all_findings.extend(authorization_report["findings"])

    app_service_report = scan_azure_app_services(azure_config)
    all_findings.extend(app_service_report["findings"])

    mapped_findings = [
        map_finding_to_compliance(finding)
        for finding in all_findings
    ]

    return {
        "total_resources_scanned": len(resources),
        "storage_accounts_scanned": storage_report["total_storage_accounts_scanned"],
        "network_security_groups_scanned": network_report["total_nsgs_scanned"],
        "keyvaults_scanned": keyvault_report["total_keyvaults_scanned"],
        "role_assignments_scanned": authorization_report["total_role_assignments_scanned"],
        "app_services_scanned": app_service_report["total_app_services_scanned"],
        "total_findings": len(mapped_findings),
        "findings": mapped_findings
    }

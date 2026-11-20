
from app.azure.keyvault_client import get_keyvault_client


def check_keyvault_security(vault):
    findings = []

    properties = vault.properties

    # Check purge protection
    if properties.enable_purge_protection is False:
        findings.append({
            "resource_name": vault.name,
            "issue": "Key Vault purge protection is disabled",
            "severity": "high"
        })

    # Check unrestricted public network access
    network_acls = properties.network_acls

    public_access_enabled = (
        str(properties.public_network_access or "").lower() == "enabled"
    )

    unrestricted_network = (
        network_acls is None
        or str(network_acls.default_action or "").lower() == "allow"
    )

    if public_access_enabled and unrestricted_network:
        findings.append({
            "resource_name": vault.name,
            "issue": "Key Vault allows unrestricted public network access",
            "severity": "high"
        })

    return findings


def scan_azure_keyvaults(azure_config: dict):
    client = get_keyvault_client(azure_config)

    vaults = list(client.vaults.list_by_subscription())

    all_findings = []

    for vault in vaults:
        findings = check_keyvault_security(vault)
        all_findings.extend(findings)

    return {
        "total_keyvaults_scanned": len(vaults),
        "total_findings": len(all_findings),
        "findings": all_findings
    }

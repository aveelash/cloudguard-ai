
from app.azure.storage_client import get_storage_client


def check_storage_security(storage_account):
    findings = []

    if storage_account.enable_https_traffic_only is False:
        findings.append({
            "resource_name": storage_account.name,
            "issue": "HTTPS-only traffic is disabled",
            "severity": "high"
        })

    network_rules = storage_account.network_rule_set

    if (
        storage_account.public_network_access == "Enabled"
        and network_rules is not None
        and network_rules.default_action == "Allow"
    ):
        findings.append({
            "resource_name": storage_account.name,
            "issue": "Storage account allows access from all networks",
            "severity": "high"
        })

    return findings


def scan_azure_storage_accounts(azure_config: dict):
    client = get_storage_client(azure_config)

    accounts = list(client.storage_accounts.list())

    all_findings = []

    for account in accounts:
        findings = check_storage_security(account)
        all_findings.extend(findings)

    return {
        "total_storage_accounts_scanned": len(accounts),
        "total_findings": len(all_findings),
        "findings": all_findings
    }

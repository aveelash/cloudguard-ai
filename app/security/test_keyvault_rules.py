
from types import SimpleNamespace

from app.security.keyvault_rules import check_keyvault_security


def create_vault(
    name,
    purge_protection,
    public_access,
    default_action
):
    return SimpleNamespace(
        name=name,
        properties=SimpleNamespace(
            enable_purge_protection=purge_protection,
            public_network_access=public_access,
            network_acls=SimpleNamespace(
                default_action=default_action
            )
        )
    )


def test_keyvault_security():

    sample_vaults = [
        create_vault("insecure-vault", False, "Enabled", "Allow"),
        create_vault("secure-vault", True, "Disabled", "Deny"),
        create_vault("purge-disabled-vault", False, "Disabled", "Deny"),
        create_vault("restricted-vault", True, "Enabled", "Deny")
    ]

    all_findings = []

    for vault in sample_vaults:
        findings = check_keyvault_security(vault)
        all_findings.extend(findings)

    print("CloudGuard AI - Key Vault Security Test")
    print("-" * 50)
    print("Total vaults tested:", len(sample_vaults))
    print("Total findings:", len(all_findings))

    for finding in all_findings:
        print("\nResource:", finding["resource_name"])
        print("Issue:", finding["issue"])
        print("Severity:", finding["severity"])

    assert len(all_findings) == 3

    print("\nKey Vault security test passed!")


if __name__ == "__main__":
    test_keyvault_security()

from types import SimpleNamespace

from app.security.storage_rules import check_storage_security


def test_storage_security():
    test_storage_account = SimpleNamespace(
    name="teststorageaccount",
    enable_https_traffic_only=False,
    public_network_access="Enabled",
    network_rule_set=SimpleNamespace(
        default_action="Allow"
    )
)

    findings = check_storage_security(test_storage_account)

    print("Storage Security Check Completed!")
    print("Total findings:", len(findings))

    for finding in findings:
        print(finding)


if __name__ == "__main__":
    test_storage_security()
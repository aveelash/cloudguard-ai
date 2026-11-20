from app.security.rules import check_resource_security


def test_security_rules():
    test_resource = {
        "name": "teststorageaccount",
        "type": "Microsoft.Storage/storageAccounts"
    }

    findings = check_resource_security(test_resource)

    print("Security scan completed!")
    print("Total findings:", len(findings))

    for finding in findings:
        print(finding)


if __name__ == "__main__":
    test_security_rules()
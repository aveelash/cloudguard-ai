from types import SimpleNamespace

from app.security.authorization_rules import check_role_assignment


def create_assignment(role_scope, principal_id):
    return SimpleNamespace(
        properties=SimpleNamespace(
            scope=role_scope,
            principal_id=principal_id
        )
    )


def test_authorization_rules():

    subscription_id = "test-subscription-123"

    subscription_scope = f"/subscriptions/{subscription_id}"

    sample_assignments = [
        (create_assignment(subscription_scope, "user-001"), "Owner"),
        (create_assignment(subscription_scope, "user-002"), "Contributor"),
        (create_assignment(subscription_scope, "user-003"), "Reader"),
        (
            create_assignment(
                subscription_scope + "/resourceGroups/test-rg",
                "user-004"
            ),
            "Owner"
        )
    ]

    all_findings = []

    for assignment, role_name in sample_assignments:
        findings = check_role_assignment(
            assignment,
            role_name,
            subscription_id
        )
        all_findings.extend(findings)

    print("CloudGuard AI - Azure RBAC Security Test")
    print("-" * 50)
    print("Total assignments tested:", len(sample_assignments))
    print("Total findings:", len(all_findings))

    for finding in all_findings:
        print("\nPrincipal:", finding["resource_name"])
        print("Issue:", finding["issue"])
        print("Severity:", finding["severity"])

    assert len(all_findings) == 2

    print("\nRBAC security test passed!")


if __name__ == "__main__":
    test_authorization_rules()
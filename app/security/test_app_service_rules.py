
from app.security.app_service_rules import check_app_service_security


def test_app_service_security():

    sample_app_services = [
        {
            "name": "insecure-web-app",
            "https_only": False,
            "min_tls_version": "1.0",
            "ftps_state": "AllAllowed"
        },
        {
            "name": "secure-web-app",
            "https_only": True,
            "min_tls_version": "1.2",
            "ftps_state": "Disabled"
        }
    ]

    findings = check_app_service_security(sample_app_services)

    print("CloudGuard AI - App Service Security Test")
    print("-" * 50)

    print(f"Total App Services tested: {len(sample_app_services)}")
    print(f"Total findings: {len(findings)}")

    for finding in findings:
        print()
        print(f"Resource: {finding['resource_name']}")
        print(f"Issue: {finding['issue']}")
        print(f"Severity: {finding['severity']}")

    assert len(findings) == 3

    print()
    print("App Service security test passed!")


if __name__ == "__main__":
    test_app_service_security()

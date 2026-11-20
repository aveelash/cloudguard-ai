
from app.security.scanner import run_security_scan


def test_security_scan(monkeypatch):
    sample_finding = {
        "resource_name": "test-storage",
        "issue": "HTTPS-only traffic is disabled",
        "severity": "high"
    }

    monkeypatch.setattr(
        "app.security.scanner.get_azure_resources",
        lambda config: []
    )

    monkeypatch.setattr(
        "app.security.scanner.scan_storage_accounts",
        lambda config: {}
    ) if False else None

    monkeypatch.setattr(
        "app.security.scanner.scan_azure_storage_accounts",
        lambda config: {
            "total_storage_accounts_scanned": 1,
            "findings": [sample_finding]
        }
    )

    monkeypatch.setattr(
        "app.security.scanner.scan_azure_network_security_groups",
        lambda config: {
            "total_nsgs_scanned": 0,
            "findings": []
        }
    )

    monkeypatch.setattr(
        "app.security.scanner.scan_azure_keyvaults",
        lambda config: {
            "total_keyvaults_scanned": 0,
            "findings": []
        }
    )

    monkeypatch.setattr(
        "app.security.scanner.scan_azure_role_assignments",
        lambda config: {
            "total_role_assignments_scanned": 0,
            "findings": []
        }
    )

    monkeypatch.setattr(
        "app.security.scanner.scan_azure_app_services",
        lambda config: {
            "total_app_services_scanned": 0,
            "findings": []
        }
    )

    report = run_security_scan({
        "subscription_id": "test-subscription"
    })

    assert report["total_resources_scanned"] == 0
    assert report["storage_accounts_scanned"] == 1
    assert report["total_findings"] == 1

    finding = report["findings"][0]

    assert finding["severity"] == "high"
    assert finding["resource_name"] == "test-storage"
    assert "compliance" in finding

    print("CloudGuard AI scanner integration test passed!")
    print("Total findings:", report["total_findings"])

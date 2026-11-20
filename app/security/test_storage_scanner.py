
from types import SimpleNamespace

from app.security.storage_rules import scan_azure_storage_accounts


def test_storage_scanner(monkeypatch):
    sample_accounts = [
        SimpleNamespace(
            name="test-storage-1",
            enable_https_traffic_only=False,
            public_network_access="Enabled",
            network_rule_set=SimpleNamespace(default_action="Allow")
        ),
        SimpleNamespace(
            name="test-storage-2",
            enable_https_traffic_only=True,
            public_network_access="Disabled",
            network_rule_set=None
        )
    ]

    mock_client = SimpleNamespace(
        storage_accounts=SimpleNamespace(
            list=lambda: sample_accounts
        )
    )

    monkeypatch.setattr(
        "app.security.storage_rules.get_storage_client",
        lambda azure_config: mock_client
    )

    report = scan_azure_storage_accounts({
        "subscription_id": "test-subscription"
    })

    assert report["total_storage_accounts_scanned"] == 2
    assert report["total_findings"] == 2


if __name__ == "__main__":
    test_storage_scanner()

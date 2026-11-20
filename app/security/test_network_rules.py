
from types import SimpleNamespace

from app.security.network_rules import check_network_security
from app.compliance.mapping import map_finding_to_compliance


def test_network_security():
    sample_nsg = SimpleNamespace(
        name="test-nsg",
        security_rules=[
            SimpleNamespace(
                direction="Inbound",
                access="Allow",
                source_address_prefix="0.0.0.0/0",
                source_address_prefixes=None,
                destination_port_range="22",
                destination_port_ranges=None
            ),
            SimpleNamespace(
                direction="Inbound",
                access="Allow",
                source_address_prefix="Internet",
                source_address_prefixes=None,
                destination_port_range="3389",
                destination_port_ranges=None
            ),
            SimpleNamespace(
                direction="Inbound",
                access="Allow",
                source_address_prefix=None,
                source_address_prefixes=["*", "10.0.0.0/8"],
                destination_port_range=None,
                destination_port_ranges=["*"]
            ),
            SimpleNamespace(
                direction="Inbound",
                access="Allow",
                source_address_prefix="0.0.0.0/0",
                source_address_prefixes=None,
                destination_port_range="20-25",
                destination_port_ranges=None
            ),
            SimpleNamespace(
                direction="Outbound",
                access="Allow",
                source_address_prefix="*",
                source_address_prefixes=None,
                destination_port_range="22",
                destination_port_ranges=None
            )
        ]
    )

    findings = check_network_security(sample_nsg)

    mapped_findings = [
        map_finding_to_compliance(finding)
        for finding in findings
    ]

    print("CloudGuard AI - NSG Security & Compliance Test")
    print("-" * 50)
    print("Total findings:", len(mapped_findings))

    for finding in mapped_findings:
        print("\nResource:", finding["resource_name"])
        print("Issue:", finding["issue"])
        print("Severity:", finding["severity"])
        print("Compliance Mapping:")

        for framework in finding["compliance"]:
            print(
                f"- {framework['name']} | "
                f"{framework['control']}"
            )


if __name__ == "__main__":
    test_network_security()

from app.security.finding_comparator import compare_findings


previous_findings = [
    {
        "resource_name": "Azure Subscription",
        "issue": "Owner role assigned at subscription scope",
        "severity": "high"
    },
    {
        "resource_name": "Storage Account",
        "issue": "HTTPS-only traffic is disabled",
        "severity": "high"
    }
]


current_findings = [
    {
        "resource_name": "Azure Subscription",
        "issue": "Owner role assigned at subscription scope",
        "severity": "high"
    },
    {
        "resource_name": "Key Vault",
        "issue": "Purge protection is disabled",
        "severity": "high"
    }
]


result = compare_findings(
    previous_findings,
    current_findings
)


print("New findings:", result["new_count"])
print("Resolved findings:", result["resolved_count"])
print("Existing findings:", result["existing_count"])

assert result["new_count"] == 1
assert result["resolved_count"] == 1
assert result["existing_count"] == 1

print("Finding comparison test passed!")
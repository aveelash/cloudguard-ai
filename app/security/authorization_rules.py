
from app.azure.authorization_client import get_authorization_client



def check_role_assignment(assignment, role_name, subscription_id):
    findings = []

    # Support both simulated test objects and Azure SDK objects
    properties = getattr(assignment, "properties", assignment)

    role_name = role_name.lower()
    scope = (properties.scope or "").rstrip("/").lower()

    principal_id = properties.principal_id

    subscription_scope = (
        f"/subscriptions/{subscription_id}".lower()
    )

    # Check broad permissions at subscription level
    if scope == subscription_scope:

        if role_name == "owner":
            findings.append({
                "resource_name": "Azure Subscription",
                "resource_id": principal_id,
                "issue": "Owner role assigned at subscription scope",
                "severity": "high"
            })

        elif role_name == "contributor":
            findings.append({
                "resource_name": "Azure Subscription",
                "resource_id": principal_id,
                "issue": "Contributor role assigned at subscription scope",
                "severity": "high"
            })

    return findings


def scan_azure_role_assignments(azure_config: dict):
    client = get_authorization_client(azure_config)

    assignments = list(
        client.role_assignments.list_for_subscription()
    )

    role_definitions = list(client.role_definitions.list(
        f"/subscriptions/{azure_config['subscription_id']}"
    ))

    # Azure SDK 4.0.0 exposes role_name directly
    role_names = {
        definition.id.lower(): definition.role_name
        for definition in role_definitions
        if definition.id and definition.role_name
    }

    all_findings = []

    for assignment in assignments:

        role_definition_id = getattr(
            assignment,
            "role_definition_id",
            None
        )

        if not role_definition_id:
            continue

        role_name = role_names.get(role_definition_id.lower())

        if role_name:
            findings = check_role_assignment(
                assignment,
                role_name,
                azure_config["subscription_id"]
            )
            all_findings.extend(findings)

    return {
        "total_role_assignments_scanned": len(assignments),
        "total_findings": len(all_findings),
        "findings": all_findings
    }

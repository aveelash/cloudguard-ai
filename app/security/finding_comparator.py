def get_finding_key(finding):
    return (
        finding.get("resource_name", ""),
        finding.get("issue", ""),
        finding.get("severity", "")
    )


def compare_findings(previous_findings, current_findings):

    previous_map = {
        get_finding_key(finding): finding
        for finding in previous_findings
    }

    current_map = {
        get_finding_key(finding): finding
        for finding in current_findings
    }

    new_findings = [
        finding
        for key, finding in current_map.items()
        if key not in previous_map
    ]

    resolved_findings = [
        finding
        for key, finding in previous_map.items()
        if key not in current_map
    ]

    existing_findings = [
        finding
        for key, finding in current_map.items()
        if key in previous_map
    ]

    return {
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "existing_findings": existing_findings,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "existing_count": len(existing_findings)
    }
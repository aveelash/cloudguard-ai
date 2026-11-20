from app.azure.network_client import get_network_client

def check_network_security(nsg):
    findings = []

    for rule in nsg.security_rules or []:

        if rule.direction != "Inbound":
            continue

        if rule.access != "Allow":
            continue

        # Check single and multiple source addresses
        sources = []

        if rule.source_address_prefix:
            sources.append(rule.source_address_prefix)

        sources.extend(rule.source_address_prefixes or [])

        # Check single and multiple destination ports
        ports = []

        if rule.destination_port_range:
            ports.append(rule.destination_port_range)

        ports.extend(rule.destination_port_ranges or [])

        # Check whether the rule allows internet access
        internet_exposed = any(
            source in ["*", "0.0.0.0/0", "::/0", "Internet"]
            for source in sources
        )

        if not internet_exposed:
            continue

        # Check all-port exposure
        if "*" in ports or "0-65535" in ports:
            findings.append({
                "resource_name": nsg.name,
                "issue": "All ports are exposed to the internet",
                "severity": "critical"
            })

            continue

        # Check SSH and RDP exposure
        for port in ports:

            if port == "22" or port == "22-22":
                findings.append({
                    "resource_name": nsg.name,
                    "issue": "SSH port 22 is exposed to the internet",
                    "severity": "high"
                })

            elif port == "3389" or port == "3389-3389":
                findings.append({
                    "resource_name": nsg.name,
                    "issue": "RDP port 3389 is exposed to the internet",
                    "severity": "high"
                })

            elif "-" in port:
                start, end = map(int, port.split("-"))

                if start <= 22 <= end:
                    findings.append({
                        "resource_name": nsg.name,
                        "issue": "SSH port 22 is exposed to the internet",
                        "severity": "high"
                    })

                if start <= 3389 <= end:
                    findings.append({
                        "resource_name": nsg.name,
                        "issue": "RDP port 3389 is exposed to the internet",
                        "severity": "high"
                    })

    return findings


def scan_azure_network_security_groups(azure_config: dict):
    client = get_network_client(azure_config)

    nsgs = list(
        client.network_security_groups.list_all()
    )

    all_findings = []

    for nsg in nsgs:
        findings = check_network_security(nsg)
        all_findings.extend(findings)

    return {
        "total_nsgs_scanned": len(nsgs),
        "total_findings": len(all_findings),
        "findings": all_findings
    }


from app.azure.app_service_client import get_azure_app_services


def check_app_service_security(app_services):
    findings = []

    for app in app_services:

        # Check HTTPS-only setting
        if app.get("https_only") is False:
            findings.append({
                "resource_name": app.get("name"),
                "resource_type": "Azure App Service",
                "issue": "HTTPS-only traffic is disabled",
                "severity": "high"
            })

        # Check minimum TLS version
        tls_version = app.get("min_tls_version")

        if tls_version and tls_version not in ["1.2", "1.3"]:
            findings.append({
                "resource_name": app.get("name"),
                "resource_type": "Azure App Service",
                "issue": f"Weak minimum TLS version: {tls_version}",
                "severity": "high"
            })

        # Check FTP/FTPS access
        ftps_state = app.get("ftps_state")

        if ftps_state == "AllAllowed":
            findings.append({
                "resource_name": app.get("name"),
                "resource_type": "Azure App Service",
                "issue": "Unencrypted FTP access is enabled",
                "severity": "medium"
            })

    return findings


def scan_azure_app_services(azure_config: dict):
    app_services = get_azure_app_services(azure_config)

    findings = check_app_service_security(app_services)

    return {
        "total_app_services_scanned": len(app_services),
        "findings": findings
    }

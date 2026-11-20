
from azure.mgmt.web import WebSiteManagementClient

from app.azure.session import get_azure_credential


def get_azure_app_services(azure_config: dict):
    credential = get_azure_credential(azure_config)

    client = WebSiteManagementClient(
        credential,
        azure_config["subscription_id"]
    )

    app_services = []

    for app in client.web_apps.list():

        resource_group = None

        if app.id and "/resourceGroups/" in app.id:
            resource_group = (
                app.id.split("/resourceGroups/")[1].split("/")[0]
            )

        site_config = app.site_config

        app_services.append({
            "name": app.name,
            "resource_group": resource_group,
            "location": app.location,
            "https_only": app.https_only,
            "min_tls_version": (
                site_config.min_tls_version if site_config else None
            ),
            "ftps_state": (
                site_config.ftps_state if site_config else None
            )
        })

    return app_services

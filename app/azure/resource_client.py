
from azure.mgmt.resource.resources import ResourceManagementClient

from app.azure.session import get_azure_credential


def get_resource_client(azure_config: dict):
    credential = get_azure_credential(azure_config)

    client = ResourceManagementClient(
        credential=credential,
        subscription_id=azure_config["subscription_id"]
    )

    return client

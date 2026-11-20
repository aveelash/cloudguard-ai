
from azure.mgmt.storage import StorageManagementClient

from app.azure.session import get_azure_credential


def get_storage_client(azure_config: dict):
    credential = get_azure_credential(azure_config)

    client = StorageManagementClient(
        credential=credential,
        subscription_id=azure_config["subscription_id"]
    )

    return client

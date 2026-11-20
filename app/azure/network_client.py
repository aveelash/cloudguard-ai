
from azure.mgmt.network import NetworkManagementClient

from app.azure.session import get_azure_credential


def get_network_client(azure_config: dict):
    credential = get_azure_credential(azure_config)

    client = NetworkManagementClient(
        credential=credential,
        subscription_id=azure_config["subscription_id"]
    )

    return client

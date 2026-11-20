
from azure.mgmt.keyvault import KeyVaultManagementClient

from app.azure.session import get_azure_credential


def get_keyvault_client(azure_config: dict):
    credential = get_azure_credential(azure_config)

    client = KeyVaultManagementClient(
        credential=credential,
        subscription_id=azure_config["subscription_id"]
    )

    return client

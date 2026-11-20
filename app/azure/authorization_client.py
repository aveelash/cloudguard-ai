
from azure.mgmt.authorization import AuthorizationManagementClient

from app.azure.session import get_azure_credential


def get_authorization_client(azure_config: dict):
    credential = get_azure_credential(azure_config)

    client = AuthorizationManagementClient(
        credential=credential,
        subscription_id=azure_config["subscription_id"]
    )

    return client

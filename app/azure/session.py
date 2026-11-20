
from azure.identity import ClientSecretCredential


def get_azure_credential(azure_config: dict):
    credential = ClientSecretCredential(
        tenant_id=azure_config["tenant_id"],
        client_id=azure_config["client_id"],
        client_secret=azure_config["client_secret"]
    )

    return credential

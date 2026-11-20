
from app.azure.resource_client import get_resource_client


def get_azure_resources(azure_config: dict):
    client = get_resource_client(azure_config)

    resources = client.resources.list()

    resource_list = []

    for resource in resources:
        resource_list.append({
            "name": resource.name,
            "type": resource.type,
            "id": resource.id,
            "location": resource.location
        })

    return resource_list

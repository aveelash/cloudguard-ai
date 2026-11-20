
from app.azure.resource_client import get_resource_client
from app.azure.connection_service import get_azure_connection
from app.db import SessionLocal


def test_azure_resources(company_id: int):
    db = SessionLocal()

    try:
        azure_config = get_azure_connection(db, company_id)

        client = get_resource_client(azure_config)

        print("Connected to Azure Resource Manager!")

        resources = list(client.resources.list())

        print("Total resources found:", len(resources))

        for resource in resources:
            print(
                "Resource:",
                resource.name,
                "| Type:",
                resource.type
            )

    finally:
        db.close()


if __name__ == "__main__":
    test_azure_resources(1)

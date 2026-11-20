
from app.azure.inventory import get_azure_resources
from app.azure.connection_service import get_azure_connection
from app.db import SessionLocal


def test_inventory(company_id: int):
    db = SessionLocal()

    try:
        azure_config = get_azure_connection(db, company_id)

        resources = get_azure_resources(azure_config)

        print("Azure Inventory completed!")
        print("Total resources:", len(resources))

        for resource in resources:
            print(resource)

    finally:
        db.close()


if __name__ == "__main__":
    test_inventory(1)

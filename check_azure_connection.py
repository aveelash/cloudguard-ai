
from app.azure.connection_service import get_azure_connection
from app.azure.resource_client import get_resource_client
from app.db import SessionLocal


def test_azure_subscription_access():
    db = SessionLocal()

    try:
        azure_config = get_azure_connection(db, company_id=1)

        client = get_resource_client(azure_config)

        resource_groups = list(
            client.resource_groups.list()
        )

        print("Azure subscription access successful!")
        print("Total resource groups:", len(resource_groups))

        for group in resource_groups:
            print("-", group.name)

    except Exception as e:
        print("Azure subscription access failed.")
        print("Error type:", type(e).__name__)
        print("Error:", str(e))

    finally:
        db.close()


if __name__ == "__main__":
    test_azure_subscription_access()

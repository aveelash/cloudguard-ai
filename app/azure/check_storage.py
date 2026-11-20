
from app.azure.storage_client import get_storage_client
from app.azure.connection_service import get_azure_connection
from app.db import SessionLocal


def test_storage_connection(company_id: int):
    db = SessionLocal()

    try:
        azure_config = get_azure_connection(db, company_id)

        client = get_storage_client(azure_config)

        print("Azure Storage Management client created successfully!")

        accounts = list(client.storage_accounts.list())

        print("Total storage accounts:", len(accounts))

    finally:
        db.close()


if __name__ == "__main__":
    test_storage_connection(1)

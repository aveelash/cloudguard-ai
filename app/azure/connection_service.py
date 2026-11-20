
from sqlalchemy.orm import Session

from app.db.models import AzureConnection
from app.core.encryption import encrypt_secret, decrypt_secret



def save_azure_connection(
    db: Session,
    company_id: int,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    subscription_id: str
):
    try:
        connection = (
            db.query(AzureConnection)
            .filter(AzureConnection.company_id == company_id)
            .first()
        )

        encrypted_secret = encrypt_secret(client_secret)

        if connection:
            connection.tenant_id = tenant_id
            connection.client_id = client_id
            connection.encrypted_client_secret = encrypted_secret
            connection.subscription_id = subscription_id
            connection.is_active = True

        else:
            connection = AzureConnection(
                company_id=company_id,
                tenant_id=tenant_id,
                client_id=client_id,
                encrypted_client_secret=encrypted_secret,
                subscription_id=subscription_id,
                is_active=True
            )

            db.add(connection)

        db.commit()
        db.refresh(connection)

        return connection

    except Exception:
        db.rollback()
        raise



def get_azure_connection(db: Session, company_id: int):
    connection = (
        db.query(AzureConnection)
        .filter(
            AzureConnection.company_id == company_id,
            AzureConnection.is_active.is_(True)
        )
        .first()
    )

    if not connection:
        raise ValueError(
            "No active Azure connection configured for this company."
        )

    return {
        "tenant_id": connection.tenant_id,
        "client_id": connection.client_id,
        "client_secret": decrypt_secret(
            connection.encrypted_client_secret
        ),
        "subscription_id": connection.subscription_id
    }

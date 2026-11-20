
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.db import get_db
from app.db.models import User
from app.schemas import AzureConnectionCreate
from app.azure.connection_service import save_azure_connection


router = APIRouter(
    prefix="/api/azure-connection",
    tags=["Azure Connection"]
)


@router.post("/")
def configure_azure_connection(
    connection_data: AzureConnectionCreate,
    current_user: User = Depends(
        require_roles("owner", "admin")
    ),
    db: Session = Depends(get_db)
):
    try:
        connection = save_azure_connection(
            db=db,
            company_id=current_user.company_id,
            tenant_id=connection_data.tenant_id,
            client_id=connection_data.client_id,
            client_secret=connection_data.client_secret,
            subscription_id=connection_data.subscription_id
        )

        return {
            "message": "Azure connection configured successfully.",
            "company_id": connection.company_id,
            "tenant_id": connection.tenant_id,
            "client_id": connection.client_id,
            "subscription_id": connection.subscription_id,
            "is_active": connection.is_active
        }

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to configure Azure connection."
        )


from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.azure.inventory import get_azure_resources
from app.azure.connection_service import get_azure_connection

from app.auth.dependencies import get_current_user
from app.db import get_db
from app.db.models import User


router = APIRouter(
    prefix="/api/inventory",
    tags=["Azure Inventory"]
)


@router.get("/resources")
def list_azure_resources(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        azure_config = get_azure_connection(
            db,
            current_user.company_id
        )

        resources = get_azure_resources(azure_config)

        return {
            "total_resources": len(resources),
            "resources": resources
        }

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve Azure resources."
        )

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.auth.security import hash_password
from app.db import get_db
from app.db.models import User
from app.schemas import (
    CompanyUserCreate,
    CompanyUserResponse,
    CompanyUserStatusUpdate,
    CompanyUserUpdate,
)


router = APIRouter(
    prefix="/api/users",
    tags=["Company User Management"]
)


@router.get("/", response_model=list[CompanyUserResponse])
def list_company_users(
    current_user: User = Depends(require_roles("owner", "admin")),
    db: Session = Depends(get_db)
):
    users = (
        db.query(User)
        .filter(User.company_id == current_user.company_id)
        .all()
    )

    return [
        {
            "id": user.id,
            "email": user.email,
            "company_id": user.company_id,
            "role": user.role,
            "is_active": user.is_active
        }
        for user in users
    ]


@router.post("/", response_model=CompanyUserResponse, status_code=status.HTTP_201_CREATED)
def create_company_user(
    user_data: CompanyUserCreate,
    current_user: User = Depends(require_roles("owner")),
    db: Session = Depends(get_db)
):
    existing_user = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered."
        )

    try:
        new_user = User(
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            company_name=current_user.company_name,
            company_id=current_user.company_id,
            role=user_data.role,
            is_active=True
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create company user."
        )

    return new_user



@router.patch("/{user_id}/role", response_model=CompanyUserResponse)
def update_company_user_role(
    user_id: int,
    user_data: CompanyUserUpdate,
    current_user: User = Depends(require_roles("owner")),
    db: Session = Depends(get_db)
):
    target_user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.company_id == current_user.company_id
        )
        .first()
    )

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if target_user.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner roles cannot be changed through this endpoint."
        )

    try:
        target_user.role = user_data.role
        db.commit()
        db.refresh(target_user)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to update user role."
        )

    return target_user


@router.patch("/{user_id}/status", response_model=CompanyUserResponse)
def update_company_user_status(
    user_id: int,
    user_data: CompanyUserStatusUpdate,
    current_user: User = Depends(require_roles("owner")),
    db: Session = Depends(get_db)
):
    if user_id == current_user.id and not user_data.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot deactivate your own account."
        )

    target_user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.company_id == current_user.company_id
        )
        .first()
    )

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if target_user.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner account status cannot be changed through this endpoint."
        )

    try:
        target_user.is_active = user_data.is_active
        db.commit()
        db.refresh(target_user)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to update user status."
        )

    return target_user

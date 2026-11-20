from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.auth.dependencies import get_current_user
from app.schemas import UserResponse
from app.db import get_db
from app.db.models import User, Company
from app.auth.security import hash_password, verify_password, create_access_token
from app.schemas import UserRegister, UserLogin, TokenResponse


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)



@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    existing_user = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Email is already registered."
        )

    try:
        new_company = Company(
            name=user_data.company_name
        )

        db.add(new_company)
        db.flush()

        new_user = User(
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            company_name=user_data.company_name,
            company_id=new_company.id,
            role="owner",
            is_active=True
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {
            "message": "Account created successfully.",
            "user_id": new_user.id,
            "email": new_user.email,
            "company_name": new_user.company_name,
            "company_id": new_user.company_id,
            "role": new_user.role
        }

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to create account."
        )



@router.post("/login", response_model=TokenResponse)
def login_user(
    user_data: UserLogin,
    db: Session = Depends(get_db)
):
    user = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if not user or not verify_password(
        user_data.password,
        user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is inactive."
        )

    access_token = create_access_token(user.id)

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@router.get("/me", response_model=UserResponse)
def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "company_name": current_user.company_name,
        "is_active": current_user.is_active
    }
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    company_name: str = Field(min_length=2, max_length=255)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    company_name: str
    is_active: bool

class CompanyUserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(pattern="^(admin|analyst)$")


class CompanyUserUpdate(BaseModel):
    role: str = Field(pattern="^(admin|analyst)$")


class CompanyUserResponse(BaseModel):
    id: int
    email: EmailStr
    company_id: int
    role: str
    is_active: bool

class CompanyUserStatusUpdate(BaseModel):
    is_active: bool

class AzureConnectionCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=255)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = Field(min_length=1, max_length=1024)
    subscription_id: str = Field(min_length=1, max_length=255)

    @field_validator(
        "tenant_id",
        "client_id",
        "client_secret",
        "subscription_id"
    )
    @classmethod
    def validate_not_empty(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("This field cannot be empty.")

        return value
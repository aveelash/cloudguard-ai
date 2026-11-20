from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "CloudGuard AI"
    APP_ENV: str = "development"
    DEBUG: bool = True

    OPENAI_API_KEY: str = ""

    DATABASE_URL: str = "sqlite:///./cloudguard.db"

    AZURE_SUBSCRIPTION_ID: str = ""
    AZURE_TENANT_ID: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""

    AZURE_CREDENTIAL_ENCRYPTION_KEY: str = ""

    JWT_SECRET_KEY: str = ""


    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )


settings = Settings()

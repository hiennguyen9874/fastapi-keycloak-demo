from typing import Optional, Dict, Any
from pydantic import (
    BaseSettings,
    AnyHttpUrl,
    EmailStr,
    PostgresDsn,
    validator,
    HttpUrl,
)


class Settings(BaseSettings):
    TIME_ZONE: str

    API_V1_STR: str = "/api/v1"

    SECRET_KEY: str

    SERVER_HOST: str

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8

    PROJECT_NAME: str

    POSTGRES_HOST: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_PORT: str
    SQLALCHEMY_DATABASE_URI: Optional[PostgresDsn] = None

    @property
    def ASYNC_SQLALCHEMY_DATABASE_URI(self) -> Optional[str]:
        return (
            self.SQLALCHEMY_DATABASE_URI.replace("postgresql://", "postgresql+asyncpg://")
            if self.SQLALCHEMY_DATABASE_URI
            else self.SQLALCHEMY_DATABASE_URI
        )

    DB_ECHO_LOG: bool = False

    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v

        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_HOST"),  # type: ignore
            port=values.get("POSTGRES_PORT"),
            path=f"/{values.get('POSTGRES_DB') or ''}",
        )

    FIRST_SUPERUSER: EmailStr
    FIRST_SUPERUSER_PASSWORD: str

    USERS_OPEN_REGISTRATION: bool

    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str

    SENTRY_DSN: Optional[HttpUrl] = None

    @validator("SENTRY_DSN", pre=True)
    def sentry_dsn_can_be_blank(cls, v: str) -> Optional[str]:
        if len(v) == 0:
            return None
        return v

    # Emails
    SMTP_TLS: bool = True
    SMTP_PORT: Optional[int] = None
    SMTP_HOST: Optional[str] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None

    EMAIL_TEMPLATES_DIR: str = "/app/app/email-templates/build"
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = 48
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None

    EMAILS_FROM_NAME: Optional[str] = None

    @validator("EMAILS_FROM_NAME")
    def get_project_name(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if not v:
            return values["PROJECT_NAME"]
        return v

    EMAILS_ENABLED: bool = False

    @validator("EMAILS_ENABLED", pre=True)
    def get_emails_enabled(cls, v: bool, values: Dict[str, Any]) -> bool:
        return bool(
            values.get("SMTP_HOST") and values.get("SMTP_PORT") and values.get("EMAILS_FROM_EMAIL")
        )

    KEYCLOAK_SERVER: AnyHttpUrl
    KEYCLOAK_SERVER_EXTERNAL: AnyHttpUrl
    KEYCLOAK_REALM: str
    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str

    @property
    def KEYCLOAK_DISCOVERY_URL(self) -> str:
        return f"{settings.KEYCLOAK_SERVER}/auth/realms/{settings.KEYCLOAK_REALM}/.well-known/openid-configuration"

    @property
    def KEYCLOAK_DISCOVERY_EXTERNAL_URL(self) -> str:
        return f"{settings.KEYCLOAK_SERVER_EXTERNAL}/auth/realms/{settings.KEYCLOAK_REALM}/.well-known/openid-configuration"

    @property
    def KEYCLOAK_TOKEN_ENDPOINT(self) -> str:
        return f"{settings.KEYCLOAK_SERVER}/auth/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"

    class Config:
        case_sensitive = True


settings = Settings()

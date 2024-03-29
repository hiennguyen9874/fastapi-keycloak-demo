import sentry_sdk
from fastapi import FastAPI
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api.api_v1.api import api_router
from app.api.deps import add_swagger_config
from app.core.settings import settings

sentry_sdk.init(settings.SENTRY_DSN)

app = FastAPI(title=settings.PROJECT_NAME, openapi_url=f"{settings.API_V1_STR}/openapi.json")

app.add_middleware(SentryAsgiMiddleware)
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY, https_only=True)
add_swagger_config(app)

app.include_router(api_router, prefix=settings.API_V1_STR)

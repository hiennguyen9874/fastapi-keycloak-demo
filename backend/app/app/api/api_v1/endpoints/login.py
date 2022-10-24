from datetime import timedelta
from typing import Any

from app import crud, models, schemas
from app.api import deps
from app.core import security
from app.core.settings import settings
from app.utils.emails import (
    generate_password_reset_token,
    send_reset_password_email,
    verify_password_reset_token,
)
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

router = APIRouter()


@router.get("/login/keycloak")
async def login_via_keycloak(request: Request):
    redirect_uri = request.url_for("auth_via_keycloak")
    return await deps.oauth.keycloak.authorize_redirect(request, redirect_uri)


@app.get("/auth/keycloak")
async def auth_via_keycloak(request: Request, response: Response):
    tokenResponse = deps.oauth.keycloak.authorize_access_token()

    userinfo = deps.oauth.keycloak.userinfo(request)
    idToken = deps.oauth.keycloak.parse_id_token(tokenResponse)

    if idToken:
        response.set_cookie(key="user", value=idToken, httponly=True)
        response.set_cookie(key="tokenResponse", value=tokenResponse, httponly=True)

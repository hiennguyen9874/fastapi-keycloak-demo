from datetime import timedelta
from typing import Any
import json
from base64 import b64decode, b64encode
from itsdangerous.exc import BadSignature

from app import crud, models, schemas
from app.api import deps
from app.core import security
from app.core.settings import settings
from app.utils import dict_encode_value
from fastapi import APIRouter, Body, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/login/keycloak")
async def login_via_keycloak(request: Request):
    redirect_uri = request.url_for("auth_via_keycloak")
    return await deps.oauth.keycloak.authorize_redirect(request, redirect_uri)


@router.get("/auth/keycloak")
async def auth_via_keycloak(request: Request):
    authorization_token = await deps.oauth.keycloak.authorize_access_token(request)

    response = RedirectResponse("/docs/oauth2-redirect")
    response.set_cookie(key="authorization_token", value=authorization_token, httponly=True)
    return response


# @router.get("/logout")
# async def logout(request: Request):
#     tokenResponse = request.cookies.get("tokenResponse", None)
#     if tokenResponse:
#         # TODO: Call end session api
#         pass
#     response.delete_cookie("tokenResponse")
#     return response

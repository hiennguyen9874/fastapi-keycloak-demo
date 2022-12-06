from typing import Any

from fastapi import APIRouter
from fastapi.responses import RedirectResponse
from starlette.requests import Request

from app.api import deps

router = APIRouter()


@router.get("/login/keycloak")
async def login_via_keycloak(request: Request) -> Any:
    redirect_uri = request.url_for("auth_via_keycloak")
    return await deps.oauth.keycloak.authorize_redirect(request, redirect_uri)


@router.get("/auth/keycloak")
async def auth_via_keycloak(request: Request) -> Any:
    authorization_token = await deps.oauth.keycloak.authorize_access_token(request)

    userinfo = authorization_token.get("userinfo")
    if userinfo:
        request.session["userinfo"] = dict(userinfo)
    return RedirectResponse("/")


@router.get("/logout")
async def logout(request: Request):
    request.session.pop("userinfo", None)
    return RedirectResponse("/")

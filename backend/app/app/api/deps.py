from typing import AsyncGenerator, Generator, Any
import json
from app import crud, models, schemas
from app.core import security
from app.core.settings import settings
from app.db.session import async_session
from fastapi import Depends, HTTPException, status, FastAPI
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from authlib.integrations.starlette_client import OAuth
from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.integrations.starlette_client.apps import StarletteOAuth2App, StarletteOAuth1App
from authlib.integrations.starlette_client.integration import StarletteIntegration
from authlib.oidc.core import UserInfo
from authlib.integrations.base_client import BaseOAuth
from fastapi.security import OAuth2, OpenIdConnect
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi import Request
from fastapi.security.utils import get_authorization_scheme_param
from fastapi import HTTPException
from fastapi import status
from typing import Optional
from typing import Dict

from typing import Optional

from fastapi.openapi.models import OpenIdConnect as OpenIdConnectModel
from fastapi.security.base import SecurityBase
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app.utils import decode


class StarletteOAuth2AppCustom(StarletteOAuth2App):
    async def fetch_userinfo(self, access_token, **kwargs):
        metadata = await self.load_server_metadata()

        introspection_endpoint = metadata.get("introspection_endpoint")
        if not introspection_endpoint:
            raise RuntimeError('Missing "introspection_endpoint" value')

        async with self._get_oauth_client(**metadata) as client:
            resp = await client.request(
                "POST",
                introspection_endpoint,
                withhold_token=True,
                data={
                    "token": access_token,
                    "client_id": client.client_id,
                    "client_secret": client.client_secret,
                },
                **kwargs,
            )
        resp.raise_for_status()
        data = resp.json()

        active = data.get("active")

        if active is None:
            raise RuntimeError('Missing "active" value')

        if active == False:
            return None

        return UserInfo(data)


class OAuthCustom(BaseOAuth):
    oauth1_client_cls = StarletteOAuth1App
    oauth2_client_cls = StarletteOAuth2AppCustom
    framework_integration_cls = StarletteIntegration

    def __init__(self, config=None, cache=None, fetch_token=None, update_token=None):
        super(OAuthCustom, self).__init__(
            cache=cache, fetch_token=fetch_token, update_token=update_token
        )
        self.config = config


oauth = OAuthCustom()
oauth.register(
    name="keycloak",
    client_id=settings.KEYCLOAK_CLIENT_ID,
    client_secret=settings.KEYCLOAK_CLIENT_SECRET,
    server_metadata_url=settings.KEYCLOAK_DISCOVERY_URL,
    client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},  # enable PKCE
)


class OpenIdConnectWithCookie(SecurityBase):
    def __init__(
        self,
        *,
        openIdConnectUrl: str,
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        self.model = OpenIdConnectModel(openIdConnectUrl=openIdConnectUrl, description=description)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        # TODO: Decode access_token token to check token is expired or not
        authorization_token = request.cookies.get("authorization_token")

        if authorization_token:
            authorization_token = json.loads(decode(authorization_token))

            userinfo = authorization_token.get("userinfo")  # type: ignore

            if not userinfo:
                if self.auto_error:
                    raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
                else:
                    return None

            return userinfo

        authorization = request.headers.get("Authorization")

        scheme, param = get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None

        userinfo = await oauth.keycloak.fetch_userinfo(access_token=param)

        if not userinfo:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None

        return userinfo


# reusable_oauth2 = OAuth2PasswordBearerWithCookie(tokenUrl=settings.KEYCLOAK_TOKEN_ENDPOINT)
reusable_oidc = OpenIdConnectWithCookie(openIdConnectUrl=settings.KEYCLOAK_DISCOVERY_EXTERNAL_URL)


def add_swagger_config(app: FastAPI):
    app.swagger_ui_init_oauth = {
        # "usePkceWithAuthorizationCodeGrant": True,
        "useBasicAuthenticationWithAccessCodeGrant": True,
        "clientId": settings.KEYCLOAK_CLIENT_ID,
        "clientSecret": settings.KEYCLOAK_CLIENT_SECRET,
        "scopes": "openid",
        "appName": "fastapi-keycloak-demo",
    }


async def get_db() -> AsyncGenerator:
    """
    Dependency function that yields db sessions
    """
    async with async_session() as session:
        yield session
        await session.commit()


async def get_current_user(userInfo: Dict[str, Any] = Depends(reusable_oidc)) -> schemas.OIDCUser:
    return schemas.OIDCUser(**userInfo)

from typing import Any, AsyncGenerator, Dict, Optional

from authlib.integrations.base_client import BaseOAuth
from authlib.integrations.starlette_client.apps import StarletteOAuth1App, StarletteOAuth2App
from authlib.integrations.starlette_client.integration import StarletteIntegration
from authlib.oidc.core import UserInfo
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.openapi.models import OpenIdConnect as OpenIdConnectModel
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from starlette.status import HTTP_401_UNAUTHORIZED

from app import schemas
from app.core.settings import settings
from app.db.session import async_session


class StarletteOAuth2AppCustom(StarletteOAuth2App):
    async def fetch_userinfo(self, access_token: str, **kwargs) -> UserInfo:  # type: ignore
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

        if active is False:
            return None

        return UserInfo(data)


class OAuthCustom(BaseOAuth):
    oauth1_client_cls = StarletteOAuth1App
    oauth2_client_cls = StarletteOAuth2AppCustom
    framework_integration_cls = StarletteIntegration

    def __init__(self, config=None, cache=None, fetch_token=None, update_token=None) -> None:  # type: ignore
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
        # TODO: Refresh access_token using refresh_token if access_token is expired
        userinfo = request.session.get("userinfo")

        if userinfo:
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


def add_swagger_config(app: FastAPI) -> None:
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

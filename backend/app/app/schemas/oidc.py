from typing import Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field


class OIDCUser(BaseModel):
    active: Optional[bool] = True
    iss: str
    azp: str
    aud: str
    sub: str
    typ: str
    iat: str
    exp: str

    jti: Optional[str]
    email: Optional[EmailStr]
    username: Optional[str]
    client_id: Optional[str]
    sid: Optional[str]
    scope: Optional[str]
    session_state: Optional[str]
    email_verified: Optional[bool]
    acr: Optional[str]
    realm_access: Optional[Dict[str, List[str]]]
    resource_access: Optional[Dict[str, Dict[str, List[str]]]]
    allowed_origins: Optional[List[str]] = Field(alias="allowed-origins")

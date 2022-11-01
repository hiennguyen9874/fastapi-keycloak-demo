from datetime import timedelta
from typing import Any

from app import crud, models, schemas
from app.api import deps
from app.core import security
from app.core.settings import settings
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

router = APIRouter()


@router.get("/identity-providers")
def get_identity_providers():
    pass


@router.get("/idp-configuration")
def get_idp_config():
    pass

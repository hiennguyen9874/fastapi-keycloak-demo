from typing import Any, List, Dict

from app import crud, models, schemas
from app.api import deps
from app.core.settings import settings
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic.networks import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()


@router.get("/me", response_model=schemas.OIDCUser)
async def read_user_me(
    db: AsyncSession = Depends(deps.get_db),
    current_user: schemas.OIDCUser = Depends(deps.get_current_user),
) -> Any:
    """
    Get current user.
    """

    return current_user

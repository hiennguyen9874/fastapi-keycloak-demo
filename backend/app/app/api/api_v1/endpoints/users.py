from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app import schemas
from app.api import deps

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

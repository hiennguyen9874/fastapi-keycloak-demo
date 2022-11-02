from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud, schemas
from app.api import deps

router = APIRouter()


@router.get("/", response_model=List[schemas.Item])
async def read_items(
    db: AsyncSession = Depends(deps.get_db),
    skip: int = 0,
    limit: int = 100,
    by_owner: bool = False,
    current_user: schemas.OIDCUser = Depends(deps.get_current_user),
) -> Any:
    """
    Retrieve items.
    """
    if by_owner:
        items = await crud.item.get_multi_by_owner(
            db=db, owner_id=current_user.sub, skip=skip, limit=limit
        )
    else:
        items = await crud.item.get_multi(db, skip=skip, limit=limit)
    return items


@router.post("/", response_model=schemas.Item)
async def create_item(
    *,
    db: AsyncSession = Depends(deps.get_db),
    item_in: schemas.ItemCreate,
    current_user: schemas.OIDCUser = Depends(deps.get_current_user),
) -> Any:
    """
    Create new item.
    """
    item = await crud.item.create_with_owner(db=db, obj_in=item_in, owner_id=current_user.sub)
    return item


@router.put("/{id}", response_model=schemas.Item)
async def update_item(
    *,
    db: AsyncSession = Depends(deps.get_db),
    id: int,
    item_in: schemas.ItemUpdate,
    current_user: schemas.OIDCUser = Depends(deps.get_current_user),
) -> Any:
    """
    Update an item.
    """
    item = await crud.item.get(db=db, id=id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item = await crud.item.update(db=db, db_obj=item, obj_in=item_in)
    return item


@router.get("/{id}", response_model=schemas.Item)
async def read_item(
    *,
    db: AsyncSession = Depends(deps.get_db),
    id: int,
    current_user: schemas.OIDCUser = Depends(deps.get_current_user),
) -> Any:
    """
    Get item by ID.
    """
    item = await crud.item.get(db=db, id=id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@router.delete("/{id}", response_model=schemas.Item)
async def delete_item(
    *,
    db: AsyncSession = Depends(deps.get_db),
    id: int,
    current_user: schemas.OIDCUser = Depends(deps.get_current_user),
) -> Any:
    """
    Delete an item.
    """
    # TODO: Two time query

    item = await crud.item.get(db=db, id=id)

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    item = await crud.item.remove(db=db, id=id)

    return item

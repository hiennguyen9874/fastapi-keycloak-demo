from typing import Any

from fastapi import APIRouter, Depends

from app import schemas
from app.api import deps
from app.worker import test_celery as test_celery_task

router = APIRouter()


@router.post("/test-celery/", response_model=schemas.Msg, status_code=201)
async def test_celery(
    msg: schemas.Msg,
    current_user: schemas.OIDCUser = Depends(deps.get_current_user),
) -> Any:
    """
    Test Celery worker.
    """
    task = test_celery_task.delay(msg.msg)
    task.get()
    return {"msg": "Word received"}


# Calling this endpoint to see if the setup works. If yes, an error message will show in Sentry dashboard
@router.get("/test-sentry")
async def test_sentry() -> Any:
    """
    Test Sentry.
    """
    raise Exception("Test sentry integration")

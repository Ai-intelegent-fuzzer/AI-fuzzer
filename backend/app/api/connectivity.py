from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.adapters.manager import target_manager
from app.connectivity.models import ConnectivityResult
from app.connectivity.tester import connectivity_tester


router = APIRouter(
    prefix="/targets",
    tags=["Connectivity"],
)


class ConnectivityAuthorization(BaseModel):
    authorization_confirmed: bool = False


@router.post(
    "/{target_id}/connectivity",
    response_model=ConnectivityResult,
)
def test_target_connectivity(
    target_id: str,
    authorization: ConnectivityAuthorization,
) -> ConnectivityResult:
    if not authorization.authorization_confirmed:
        raise HTTPException(
            status_code=403,
            detail="Explicit authorization confirmation is required before testing a target.",
        )

    target = target_manager.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    result = connectivity_tester.test(target)
    if not target_manager.update_connectivity(
        target_id,
        result.status.value,
        datetime.now(timezone.utc),
    ):
        raise HTTPException(status_code=404, detail="Target not found")
    return result

from fastapi import APIRouter, HTTPException

from app.adapters.manager import target_manager
from app.connectivity.models import ConnectivityResult
from app.connectivity.tester import connectivity_tester


router = APIRouter(
    prefix="/targets",
    tags=["Connectivity"],
)


@router.post(
    "/{target_id}/connectivity",
    response_model=ConnectivityResult,
)
def test_target_connectivity(target_id: str) -> ConnectivityResult:

    target = target_manager.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    return connectivity_tester.test(target)

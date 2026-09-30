from fastapi import APIRouter, HTTPException, Query

from app.adapters.manager import target_manager
from app.fuzzing.engine import fuzz_engine


router = APIRouter(
    prefix="/targets",
    tags=["Fuzzing"],
)


@router.post(
    "/{target_id}/fuzz-cases",
)
def generate_fuzz_cases(
    target_id: str,
    count: int = Query(default=4, ge=1, le=100),
):
    target = target_manager.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    return fuzz_engine.generate(count)

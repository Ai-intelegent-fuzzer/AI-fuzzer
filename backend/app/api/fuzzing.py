from fastapi import APIRouter, HTTPException

from app.adapters.manager import target_manager
from app.fuzzing.generator import fuzz_case_generator
from app.fuzzing.models import FuzzCase


router = APIRouter(
    prefix="/targets",
    tags=["Fuzzing"],
)


@router.post(
    "/{target_id}/fuzz-cases",
    response_model=list[FuzzCase],
)
def generate_fuzz_cases(target_id: str, count: int = 4):

    target = target_manager.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    if count < 1 or count > 4:
        raise HTTPException(
            status_code=400,
            detail="count must be between 1 and 4",
        )

    return fuzz_case_generator.generate(count)

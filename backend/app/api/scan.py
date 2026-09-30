from fastapi import APIRouter, HTTPException, Query

from app.fuzzing.orchestrator import fuzz_orchestrator
from app.execution.models import ExecutionResult


router = APIRouter(
    prefix="/targets",
    tags=["Fuzzing"],
)


@router.post(
    "/{target_id}/fuzz",
    response_model=list[ExecutionResult],
)
def run_fuzz(
    target_id: str,
    count: int = Query(default=4, ge=1, le=100),
):
    results = fuzz_orchestrator.run(
        target_id=target_id,
        count=count,
    )

    if results is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    return results

from fastapi import APIRouter, HTTPException

from app.adapters.manager import target_manager
from app.execution.executor import fuzz_executor
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase


router = APIRouter(
    prefix="/targets",
    tags=["Execution"],
)


@router.post(
    "/{target_id}/execute",
    response_model=ExecutionResult,
)
def execute_fuzz_case(
    target_id: str,
    fuzz_case: FuzzCase,
) -> ExecutionResult:

    target = target_manager.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    return fuzz_executor.execute(target, fuzz_case)

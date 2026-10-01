from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.analysis.models import AnalysisResult
from app.execution.models import ExecutionResult
from app.fuzzing.orchestrator import fuzz_orchestrator

class ScanResult(BaseModel):
    execution: ExecutionResult
    analysis: AnalysisResult

router = APIRouter(
    prefix="/targets",
    tags=["Fuzzing"],
)

@router.post(
    "/{target_id}/fuzz",
    response_model=list[ScanResult],
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

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from app.analysis.models import AnalysisResult
from app.execution.models import ExecutionResult
from app.fuzzing.orchestrator import fuzz_orchestrator
from app.adapters.manager import target_manager
from app.fuzzing.models import ScanCreateRequest, ScanRecord
from app.fuzzing.scheduler import scan_scheduler

class ScanResult(BaseModel):
    execution: ExecutionResult
    analysis: AnalysisResult

router = APIRouter(
    prefix="/targets",
    tags=["Fuzzing"],
)

scan_lifecycle_router = APIRouter(prefix="/scans", tags=["Scans"])

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


@scan_lifecycle_router.post("", response_model=ScanRecord, status_code=status.HTTP_202_ACCEPTED)
def start_scan(request: ScanCreateRequest) -> ScanRecord:
    if target_manager.get(request.target_id) is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return scan_scheduler.start(request)


@scan_lifecycle_router.get("/{scan_id}", response_model=ScanRecord)
def get_scan(scan_id: str) -> ScanRecord:
    scan = scan_scheduler.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@scan_lifecycle_router.get("/{scan_id}/results")
def get_scan_results(scan_id: str) -> list[dict[str, object]]:
    results = scan_scheduler.get_results(scan_id)
    if results is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return results


@scan_lifecycle_router.post("/{scan_id}/cancel", response_model=ScanRecord)
def cancel_scan(scan_id: str) -> ScanRecord:
    scan = scan_scheduler.cancel(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

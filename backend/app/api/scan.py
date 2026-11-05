from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel

from app.analysis.models import AnalysisResult, AnalysisStatus, Finding, Severity
from app.execution.models import ExecutionResult
from app.fuzzing.orchestrator import fuzz_orchestrator
from app.attacks.registry import attack_registry
from app.fuzzing.engine import FUZZ_TEMPLATES
from app.adapters.manager import target_manager
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanRecord, ScanStatus
from app.fuzzing.scheduler import scan_scheduler

class ScanResult(BaseModel):
    case: FuzzCase
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
        total_case_limit=count,
    )

    if results is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    return results


@scan_lifecycle_router.get("", response_model=list[ScanRecord])
def list_scans() -> list[ScanRecord]:
    return scan_scheduler.list()


@scan_lifecycle_router.post("", response_model=ScanRecord, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    request: ScanCreateRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=160),
) -> ScanRecord:
    if target_manager.get(request.target_id) is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not request.authorization_confirmed:
        raise HTTPException(
            status_code=403,
            detail="Explicit authorization confirmation is required to start a scan.",
        )
    supported_categories = set(attack_registry.list_categories()) | set(FUZZ_TEMPLATES)
    requested_categories = request.categories or sorted(supported_categories)
    unsupported_categories = sorted(set(requested_categories) - supported_categories)
    if unsupported_categories:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported test categories: {', '.join(unsupported_categories)}",
        )
    return scan_scheduler.start(request, idempotency_key=idempotency_key)


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


@scan_lifecycle_router.get("/{scan_id}/findings", response_model=list[Finding])
def get_scan_findings(scan_id: str) -> list[Finding]:
    results = scan_scheduler.get_results(scan_id)
    if results is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings: list[Finding] = []
    for result in results:
        analysis = result.get("analysis")
        if isinstance(analysis, AnalysisResult):
            findings.extend(
                finding.model_copy(update={"analysis_status": analysis.status})
                for finding in analysis.findings
            )
    return findings


@scan_lifecycle_router.get("/analytics/overview")
def overview() -> dict[str, object]:
    scans = scan_scheduler.list()
    findings: list[Finding] = []
    for scan in scans:
        for result in scan_scheduler.get_results(scan.scan_id) or []:
            analysis = result.get("analysis")
            if isinstance(analysis, AnalysisResult):
                findings.extend(analysis.findings)

    severity_counts = {level.value: 0 for level in Severity}
    for finding in findings:
        severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

    return {
        "total_scans": len(scans),
        "completed_scans": sum(1 for scan in scans if scan.status == ScanStatus.COMPLETED),
        "failed_scans": sum(1 for scan in scans if scan.status == ScanStatus.FAILED),
        "tests_executed": sum(scan.metrics.total_executed_cases for scan in scans),
        "total_findings": len(findings),
        "critical_high_findings": sum(
            1 for finding in findings if finding.severity in {Severity.CRITICAL, Severity.HIGH}
        ),
        "severity_counts": severity_counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@scan_lifecycle_router.get("/analytics/trends")
def trends() -> list[dict[str, object]]:
    scans = scan_scheduler.list()
    buckets: dict[str, dict[str, int]] = {}
    for scan in scans:
        day = scan.created_at.date().isoformat()
        entry = buckets.setdefault(day, {"date": day, "scans": 0, "findings": 0})
        entry["scans"] += 1
        for result in scan_scheduler.get_results(scan.scan_id) or []:
            analysis = result.get("analysis")
            if isinstance(analysis, AnalysisResult):
                entry["findings"] += len(analysis.findings)
    return sorted(buckets.values(), key=lambda item: item["date"])


@scan_lifecycle_router.get("/analytics/categories")
def category_distribution() -> list[dict[str, int | str]]:
    counts: dict[str, int] = {}
    for scan in scan_scheduler.list():
        for result in scan_scheduler.get_results(scan.scan_id) or []:
            analysis = result.get("analysis")
            if isinstance(analysis, AnalysisResult):
                for finding in analysis.findings:
                    counts[finding.category] = counts.get(finding.category, 0) + 1
    return [{"name": key, "value": value} for key, value in sorted(counts.items())]


@scan_lifecycle_router.get("/analytics/severity")
def severity_distribution() -> list[dict[str, int | str]]:
    counts: dict[str, int] = {level.value: 0 for level in Severity}
    for scan in scan_scheduler.list():
        for result in scan_scheduler.get_results(scan.scan_id) or []:
            analysis = result.get("analysis")
            if isinstance(analysis, AnalysisResult):
                for finding in analysis.findings:
                    counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return [{"name": level.value.title(), "value": counts[level.value]} for level in Severity]


@scan_lifecycle_router.get("/findings", response_model=list[Finding])
def list_findings(
    category: str | None = None,
    severity: Severity | None = None,
    status_filter: AnalysisStatus | None = Query(default=None, alias="status"),
) -> list[Finding]:
    all_findings: list[Finding] = []
    for scan in scan_scheduler.list():
        for result in scan_scheduler.get_results(scan.scan_id) or []:
            analysis = result.get("analysis")
            if isinstance(analysis, AnalysisResult):
                all_findings.extend(
                    finding.model_copy(update={"analysis_status": analysis.status})
                    for finding in analysis.findings
                    if (category is None or finding.category == category)
                    and (severity is None or finding.severity == severity)
                    and (status_filter is None or analysis.status == status_filter)
                )
    return all_findings


@scan_lifecycle_router.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: str) -> Finding:
    for scan in scan_scheduler.list():
        for result in scan_scheduler.get_results(scan.scan_id) or []:
            analysis = result.get("analysis")
            if isinstance(analysis, AnalysisResult):
                for finding in analysis.findings:
                    if finding.finding_id == finding_id:
                        return finding.model_copy(update={"analysis_status": analysis.status})
    raise HTTPException(status_code=404, detail="Finding not found")


@scan_lifecycle_router.get("/categories", response_model=list[str])
def list_scan_categories() -> list[str]:
    return sorted(set(attack_registry.list_categories()) | set(FUZZ_TEMPLATES))


@scan_lifecycle_router.get("/{scan_id}", response_model=ScanRecord)
def get_scan(scan_id: str) -> ScanRecord:
    scan = scan_scheduler.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

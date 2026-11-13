from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel

from app.analysis.models import AnalysisResult, AnalysisStatus, Finding, Severity
from app.execution.models import ExecutionResult
from app.fuzzing.orchestrator import fuzz_orchestrator
from app.attacks.registry import (
    PROMPT_INJECTION_BENCHMARK_CATEGORIES,
    PROMPT_INJECTION_BENCHMARK_ID,
    attack_registry,
)
from app.fuzzing.engine import FUZZ_TEMPLATES
from app.adapters.manager import target_manager
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanRecord, ScanStatus
from app.fuzzing.scheduler import scan_scheduler
from app.database.store import database
from app.rag.capabilities import category_supported_by_profile

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
    count: int = Query(default=4, ge=1, le=1000),
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
    target = target_manager.get(request.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not request.authorization_confirmed:
        raise HTTPException(
            status_code=403,
            detail="Explicit authorization confirmation is required to start a scan.",
        )
    supported_categories = set(attack_registry.list_all_categories()) | set(FUZZ_TEMPLATES)
    if request.benchmark_id is not None and request.benchmark_id != PROMPT_INJECTION_BENCHMARK_ID:
        raise HTTPException(status_code=422, detail="Unsupported benchmark.")
    requested_categories = (
        list(PROMPT_INJECTION_BENCHMARK_CATEGORIES)
        if request.benchmark_id == PROMPT_INJECTION_BENCHMARK_ID
        else request.categories or sorted(supported_categories)
    )
    if request.benchmark_id == PROMPT_INJECTION_BENCHMARK_ID and request.count != 180:
        raise HTTPException(status_code=422, detail="The complete benchmark requires count=180.")
    unsupported_categories = sorted(set(requested_categories) - supported_categories)
    if unsupported_categories:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported test categories: {', '.join(unsupported_categories)}",
        )
    not_applicable_categories = [
        category
        for category in requested_categories
        if not category_supported_by_profile(
            category,
            target.capability_profile,
            target.target_scope,
        )
    ]
    effective_request = request.model_copy(update={"categories": requested_categories})
    return scan_scheduler.start(
        effective_request,
        idempotency_key=idempotency_key,
        target_scope=target.target_scope,
        capability_profile=target.capability_profile,
        requested_categories=requested_categories,
        not_applicable_categories=not_applicable_categories,
    )


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


@scan_lifecycle_router.post("/{scan_id}/retry-errors", response_model=ScanRecord, status_code=status.HTTP_202_ACCEPTED)
def retry_scan_errors(scan_id: str) -> ScanRecord:
    original = scan_scheduler.get(scan_id)
    results = scan_scheduler.get_results(scan_id)
    if original is None or results is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = target_manager.get(original.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    errored = [
        result for result in results
        if isinstance(result.get("case"), FuzzCase)
        and getattr(result.get("execution"), "status", "") != "completed"
    ]
    if not errored:
        raise HTTPException(status_code=409, detail="This scan has no errored cases eligible for retry.")
    parent_request = scan_scheduler.get_request(scan_id)
    retry_case_ids = [result["case"].case_id for result in errored]
    categories = sorted({result["case"].category for result in errored})
    request = ScanCreateRequest(
        target_id=original.target_id,
        authorization_confirmed=True,
        count=len(retry_case_ids),
        categories=categories,
        benchmark_id=parent_request.benchmark_id if parent_request else None,
        retry_of_scan_id=scan_id,
        retry_case_ids=retry_case_ids,
        timeout_seconds=parent_request.timeout_seconds if parent_request else 30.0,
        max_retries=4,
        concurrency=1,
        delay_seconds=1.0,
    )
    return scan_scheduler.start(
        request,
        target_scope=target.target_scope,
        capability_profile=target.capability_profile,
        requested_categories=categories,
    )


@scan_lifecycle_router.post("/{scan_id}/reevaluate")
def reevaluate_scan(scan_id: str) -> dict[str, object]:
    if scan_scheduler.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "reevaluated_completed_cases": scan_scheduler.reevaluate_completed(scan_id),
        "provider_requests_sent": 0,
        "storage": "immutable_analysis_history",
    }


@scan_lifecycle_router.get("/{scan_id}/analysis-history")
def get_analysis_history(scan_id: str) -> list[dict[str, object]]:
    if scan_scheduler.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [item.model_dump(mode="json") for item in database.get_analysis_history(scan_id)]


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
    return sorted(set(attack_registry.list_all_categories()) | set(FUZZ_TEMPLATES))


@scan_lifecycle_router.get("/{scan_id}", response_model=ScanRecord)
def get_scan(scan_id: str) -> ScanRecord:
    scan = scan_scheduler.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

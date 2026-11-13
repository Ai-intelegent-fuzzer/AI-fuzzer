from datetime import datetime, timezone
import re
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.adapters.manager import target_manager
from app.analysis.models import (
    AnalysisResult,
    AnalysisStatus,
    EvidenceProvenance,
    Finding,
    FindingVerificationStatus,
    Severity,
)
from app.database.store import database
from app.attacks.registry import attack_registry
from app.fuzzing.engine import FUZZ_TEMPLATES
from app.fuzzing.models import ScanRecord, ScanStatus
from app.fuzzing.scheduler import scan_scheduler

router = APIRouter(prefix="/reports", tags=["Reports"])


class ReportFinding(BaseModel):
    id: str
    type: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str
    category: str = "unknown"
    confidence: str = "unknown"
    risk_score: int = 0
    provider: str | None = None
    model: str | None = None
    test_case_id: str | None = None
    attack_id: str | None = None
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    reproduction_steps: list[str] = Field(default_factory=list)
    impact: str = "Observed model behavior; external impact was not verified."
    response_excerpt: str | None = None
    verification_status: FindingVerificationStatus = FindingVerificationStatus.POTENTIAL
    evidence_provenance: list[EvidenceProvenance] = Field(default_factory=list)
    reproduction_reference: str | None = None


class ScanReport(BaseModel):
    report_revision: int = 3
    report_id: str
    title: str
    generated_at: datetime
    format: str = "JSON"
    status: str = "Ready"
    findings_count: int
    summary: str
    scan_id: str
    target_id: str
    target_name: str
    highest_severity: Severity | None
    executive_summary: str
    target_information: str
    scan_configuration: str
    tests_executed: int
    severity_distribution: list[dict[str, int | str]]
    detailed_findings: list[ReportFinding]
    evidence_references: list[str]
    recommended_remediation: list[str]
    project_name: str = "AI-Fuzzer"
    assessment_scope: str = ""
    authorization_statement: str = "The operator confirmed authorization before the assessment."
    methodology: str = "Category-scoped, controlled prompt tests were executed against the configured target; results are heuristic and require human review."
    categories_executed: list[str] = Field(default_factory=list)
    categories_requested: list[str] = Field(default_factory=list)
    categories_generated: list[str] = Field(default_factory=list)
    category_coverage_percent: float = 0.0
    inconclusive_analyses: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    coverage_warning: str | None = None
    conclusion: str = ""
    limitations: list[str] = Field(default_factory=lambda: [
        "Results reflect only the executed test cases and target responses.",
        "A finding is heuristic response evidence, not proof of external impact.",
        "No finding does not prove that the target is secure.",
    ])
    target_provider: str | None = None
    target_model: str | None = None
    requested_cases: int = 0
    generated_cases: int = 0
    failed_executions: int = 0
    scan_status: str = "unknown"
    target_scope: str | None = None
    capability_profile: dict[str, Any] | None = None
    categories_applicable: list[str] = Field(default_factory=list)
    categories_not_applicable: list[str] = Field(default_factory=list)
    evidence_provenance_references: list[str] = Field(default_factory=list)
    findings_by_verification_status: dict[str, int] = Field(default_factory=dict)


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


def _sanitize_evidence(value: str, api_key: str | None) -> str:
    sanitized = value
    if api_key:
        sanitized = sanitized.replace(api_key, "[REDACTED]")
    patterns = (
        r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*",
        r"(?i)((?:api[_ -]?key|access[_ -]?token|client[_ -]?secret|password)\s*[:=]\s*)[^\s,;]+",
        r"\b(?:sk-[A-Za-z0-9_-]{12,}|gsk_[A-Za-z0-9_-]{12,}|AIza[A-Za-z0-9_-]{20,})\b",
        r"\bSYNTHETIC-CANARY-[A-Z0-9-]+\b",
        r"\[SYNTHETIC_(?:SECRET|SYSTEM_PROMPT|USER_DATA|CANARY)(?:_[A-Z0-9]+)*\]",
    )
    for pattern in patterns:
        sanitized = re.sub(pattern, r"\1[REDACTED]" if "bearer" in pattern.lower() else "[REDACTED]", sanitized)
    return sanitized[:4000]


def _conclusion(
    *,
    finding_count: int,
    requested_cases: int,
    generated_cases: int,
    executed_cases: int,
    failed_executions: int,
    inconclusive_analyses: int,
    category_coverage_percent: float,
    scan_status: ScanStatus,
    confirmed_findings: int,
    likely_findings: int,
    potential_findings: int,
) -> str:
    incomplete = (
        failed_executions > 0
        or inconclusive_analyses > 0
        or generated_cases < requested_cases
        or executed_cases < generated_cases
        or category_coverage_percent < 100
        or scan_status != ScanStatus.COMPLETED
    )
    if incomplete:
        return (
            f"Assessment is inconclusive: {finding_count} finding(s) were identified, "
            f"{requested_cases} case(s) requested, {generated_cases} generated, and "
            f"{executed_cases} executed; {failed_executions} execution(s) failed, "
            f"{inconclusive_analyses} analysis result(s) were inconclusive, and "
            f"category coverage was {category_coverage_percent:g}%. Results do not "
            "establish that the target is secure."
        )
    if finding_count:
        return (
            f"The assessment identified {finding_count} finding(s): "
            f"{confirmed_findings} confirmed through controlled evidence, "
            f"{likely_findings} likely response-behavior indicator(s), and "
            f"{potential_findings} potential indicator(s). Model-response findings "
            "do not establish external impact and require human review."
        )
    return (
        "No category-specific vulnerability indicator was observed in the completed "
        "tests. This is not a security verdict and does not prove that the target is secure."
    )


def _report_for(scan: ScanRecord) -> ScanReport:
    results = scan_scheduler.get_results(scan.scan_id)
    if results is None or scan.status in {
        ScanStatus.CREATED,
        ScanStatus.QUEUED,
        ScanStatus.RUNNING,
        ScanStatus.PAUSED,
    }:
        raise HTTPException(status_code=404, detail="Report is not available for this scan")

    target = target_manager.get(scan.target_id)
    findings: list[Finding] = []
    for result in results:
        analysis = result.get("analysis")
        if isinstance(analysis, AnalysisResult):
            findings.extend(analysis.findings)

    severity_counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        severity_counts[finding.severity.value] += 1

    highest_severity = min(
        (finding.severity for finding in findings),
        key=lambda severity: _SEVERITY_ORDER[severity],
        default=None,
    )
    target_name = target.name if target is not None else scan.target_id
    persisted_generated_cases = database.get_generated_cases(scan.scan_id) or []
    categories = sorted({
        result["case"].category
        for result in results
        if hasattr(result.get("case"), "category")
    })
    request = scan_scheduler.get_request(scan.scan_id)
    requested_categories = list(
        scan.requested_categories
        or (
            request.categories
            if request and request.categories is not None
            else sorted(set(attack_registry.list_all_categories()) | set(FUZZ_TEMPLATES))
        )
    )
    applicable_categories = list(
        scan.applicable_categories
        if scan.capability_profile is not None or scan.not_applicable_categories
        else requested_categories
    )
    not_applicable_categories = list(scan.not_applicable_categories)
    generated_categories = sorted(
        set(scan.generated_categories)
        | {case.category for case in persisted_generated_cases}
        | set(categories)
    )
    generated_case_count = max(
        scan.generated_case_count,
        len(persisted_generated_cases),
        len(results),
    )
    category_coverage_percent = (
        round(
            len(set(applicable_categories).intersection(categories))
            / len(applicable_categories)
            * 100,
            2,
        )
        if applicable_categories
        else 100.0
    )
    inconclusive_analyses = sum(
        isinstance(result.get("analysis"), AnalysisResult)
        and result["analysis"].status == AnalysisStatus.INCONCLUSIVE
        for result in results
    )
    failed_executions = sum(
        getattr(result.get("execution"), "status", None) != "completed"
        for result in results
    )
    execution_by_case = {
        execution.case_id: execution
        for result in results
        if (execution := result.get("execution")) is not None
        and hasattr(execution, "case_id")
    }
    evidence_provenance = [
        provenance
        for result in results
        if isinstance(result.get("analysis"), AnalysisResult)
        for provenance in result["analysis"].evidence_provenance
    ]
    verification_counts = {
        status.value: sum(
            finding.verification_status == status for finding in findings
        )
        for status in FindingVerificationStatus
    }
    api_key = target.api_key.get_secret_value() if target and target.api_key else None
    summary = (
        f"{len(findings)} findings across {len(results)} executed tests; "
        f"{verification_counts[FindingVerificationStatus.CONFIRMED.value]} confirmed, "
        f"{verification_counts[FindingVerificationStatus.LIKELY.value]} likely, "
        f"{verification_counts[FindingVerificationStatus.POTENTIAL.value]} potential; "
        f"{failed_executions} failed executions and "
        f"{inconclusive_analyses} inconclusive analyses."
    )
    configuration = (
        f"Requested cases: {request.count}; categories: "
        f"{', '.join(request.categories or []) or 'all supported categories'}; "
        f"timeout: {request.timeout_seconds:g}s; concurrency: {request.concurrency}."
        if request is not None
        else "Scan configuration is unavailable."
    )

    report = ScanReport(
        report_id=scan.scan_id,
        title=f"Security assessment - {target_name}",
        generated_at=datetime.now(timezone.utc),
        findings_count=len(findings),
        summary=summary,
        scan_id=scan.scan_id,
        target_id=scan.target_id,
        target_name=target_name,
        highest_severity=highest_severity,
        executive_summary=summary,
        target_information=(
            f"Target ID: {scan.target_id}; scope: "
            f"{scan.target_scope.value if scan.target_scope is not None else 'unknown'}."
        ),
        scan_configuration=configuration,
        tests_executed=len(results),
        severity_distribution=[
            {"name": severity.value.title(), "value": severity_counts[severity.value]}
            for severity in Severity
        ],
        detailed_findings=[
            ReportFinding(
                id=finding.finding_id,
                type=_sanitize_evidence(finding.title, api_key),
                severity=finding.severity,
                description=_sanitize_evidence(
                    finding.description or finding.detection_rationale or finding.category,
                    api_key,
                ),
                evidence=_sanitize_evidence(finding.evidence, api_key),
                recommendation=_sanitize_evidence(finding.recommendation, api_key),
                category=finding.category,
                confidence=finding.confidence.value,
                risk_score=finding.risk_score,
                provider=getattr(execution_by_case.get(finding.case_id), "provider", None),
                model=getattr(execution_by_case.get(finding.case_id), "model", None),
                test_case_id=finding.case_id,
                attack_id=finding.attack_id,
                expected_behavior=(
                    _sanitize_evidence(finding.expected_behavior, api_key)
                    if finding.expected_behavior else None
                ),
                observed_behavior=(
                    _sanitize_evidence(finding.observed_behavior, api_key)
                    if finding.observed_behavior else None
                ),
                reproduction_steps=[
                    "Open the source scan and locate the referenced test case.",
                    "Re-run only against the same explicitly authorized target.",
                ],
                response_excerpt=(
                    _sanitize_evidence(
                        execution_by_case[finding.case_id].response_body,
                        api_key,
                    )
                    if (
                        finding.case_id in execution_by_case
                        and execution_by_case[finding.case_id].response_body
                    )
                    else None
                ),
                impact=(
                    "A synthetic canary was disclosed from a verified protected context."
                    if finding.verification_status == FindingVerificationStatus.CONFIRMED
                    else "Observed model behavior; external impact was not verified."
                ),
                verification_status=finding.verification_status,
                evidence_provenance=finding.evidence_provenance,
                reproduction_reference=finding.reproduction_reference,
            )
            for finding in findings
        ],
        evidence_references=[finding.finding_id for finding in findings],
        recommended_remediation=sorted({finding.recommendation for finding in findings}),
        assessment_scope=(
            f"Target {target_name}; provider {target.provider.value}; model {target.model or 'not recorded'}."
            if target is not None
            else f"Target ID {scan.target_id}; target configuration is no longer available."
        ),
        categories_executed=categories,
        categories_requested=requested_categories,
        categories_generated=generated_categories,
        category_coverage_percent=category_coverage_percent,
        inconclusive_analyses=inconclusive_analyses,
        findings_by_severity={
            severity.value: severity_counts[severity.value]
            for severity in Severity
        },
        coverage_warning=scan.coverage_warning,
        target_provider=target.provider.value if target is not None else None,
        target_model=target.model if target is not None else None,
        requested_cases=scan.requested_case_count,
        generated_cases=generated_case_count,
        failed_executions=failed_executions,
        scan_status=scan.status.value,
        target_scope=scan.target_scope.value if scan.target_scope is not None else None,
        capability_profile=(
            scan.capability_profile.model_dump(mode="json")
            if scan.capability_profile is not None
            else None
        ),
        categories_applicable=applicable_categories,
        categories_not_applicable=not_applicable_categories,
        evidence_provenance_references=sorted({
            item.provenance_id for item in evidence_provenance
        }),
        findings_by_verification_status=verification_counts,
        conclusion=_conclusion(
            finding_count=len(findings),
            requested_cases=scan.requested_case_count,
            generated_cases=generated_case_count,
            executed_cases=len(results),
            failed_executions=failed_executions,
            inconclusive_analyses=inconclusive_analyses,
            category_coverage_percent=category_coverage_percent,
            scan_status=scan.status,
            confirmed_findings=verification_counts[
                FindingVerificationStatus.CONFIRMED.value
            ],
            likely_findings=verification_counts[
                FindingVerificationStatus.LIKELY.value
            ],
            potential_findings=verification_counts[
                FindingVerificationStatus.POTENTIAL.value
            ],
        ),
    )
    database.save_report(
        report.report_id,
        report.scan_id,
        report.generated_at,
        report.model_dump(mode="json"),
    )
    return report


@router.get("", response_model=list[ScanReport])
def list_reports() -> list[ScanReport]:
    persisted: dict[str, ScanReport] = {}
    for data in database.list_reports():
        report_id = data.get("report_id")
        if not isinstance(report_id, str):
            continue
        if data.get("report_revision") != 3:
            scan = scan_scheduler.get(report_id)
            if scan is not None and scan.status in {
                ScanStatus.COMPLETED,
                ScanStatus.FAILED,
                ScanStatus.CANCELLED,
            }:
                persisted[report_id] = _report_for(scan)
                continue
        persisted[report_id] = ScanReport.model_validate(data)
    for scan in scan_scheduler.list():
        if (
            scan.scan_id not in persisted
            and scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
        ):
            persisted[scan.scan_id] = _report_for(scan)
    return sorted(persisted.values(), key=lambda report: report.generated_at, reverse=True)


@router.post("/{scan_id}/generate", response_model=ScanReport)
def generate_report(scan_id: str) -> ScanReport:
    scan = scan_scheduler.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _report_for(scan)


@router.get("/{report_id}", response_model=ScanReport)
def get_report(report_id: str) -> ScanReport:
    persisted = database.get_report(report_id)
    if persisted is not None:
        if persisted.get("report_revision") != 3:
            scan = scan_scheduler.get(report_id)
            if scan is not None and scan.status in {
                ScanStatus.COMPLETED,
                ScanStatus.FAILED,
                ScanStatus.CANCELLED,
            }:
                return _report_for(scan)
        return ScanReport.model_validate(persisted)
    scan = scan_scheduler.get(report_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return _report_for(scan)

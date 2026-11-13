from enum import Enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AnalysisStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class AnalysisOutcome(str, Enum):
    VULNERABILITY_DETECTED = "vulnerability_detected"
    REFUSED_OR_BLOCKED = "refused_or_blocked"
    NO_ISSUE_OBSERVED = "no_issue_observed"
    INCONCLUSIVE = "inconclusive"
    EXECUTION_FAILED = "execution_failed"
    NOT_APPLICABLE = "not_applicable"


class DetectionClassification(str, Enum):
    """Evidence-based result classification independent of legacy PASS/FAIL fields."""

    CONFIRMED_ATTACK = "confirmed_attack"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    EXECUTION_ERROR = "execution_error"


class FindingVerificationStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POTENTIAL = "potential"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    NO_ISSUE_OBSERVED = "no_issue_observed"
    EXECUTION_FAILURE = "execution_failure"


class IndicatorType(str, Enum):
    INSTRUCTION_FOLLOWED = "instruction_followed"
    TRUSTED_INSTRUCTION_IGNORED = "trusted_instruction_ignored"
    POLICY_BYPASS = "policy_bypass"
    UNTRUSTED_CONTEXT_TRUSTED = "untrusted_context_trusted"
    RETRIEVED_INSTRUCTION_FOLLOWED = "retrieved_instruction_followed"
    INDIRECT_INSTRUCTION_FOLLOWED = "indirect_instruction_followed"
    CONTROLLED_DATA_DISCLOSURE = "controlled_data_disclosure"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    UNAUTHORIZED_ACTION = "unauthorized_action"
    ROLE_AUTHORITY_CONFUSION = "role_authority_confusion"


class BehavioralIndicator(BaseModel):
    indicator_type: IndicatorType
    description: str
    evidence: str
    confidence: Confidence
    category: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceProvenance(BaseModel):
    provenance_id: str
    scan_id: str | None = None
    test_case_id: str
    target_id: str
    canary_identifier: str | None = None
    canary_present_in_protected_context: bool = False
    canary_present_in_test_input: bool = False
    canary_present_in_response: bool = False
    protected_context_verified: bool = False
    disclosure_verified: bool = False
    verification_level: str
    evidence_type: str
    analyzer_rule_id: str | None = None
    analyzer_rule_version: str | None = None
    identity_id: str | None = None
    tenant_id: str | None = None
    retrieval_reference: str | None = None
    tool_reference: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnalysisAssessment(BaseModel):
    vulnerable: bool
    status: AnalysisStatus = AnalysisStatus.INCONCLUSIVE
    outcome: AnalysisOutcome = AnalysisOutcome.INCONCLUSIVE
    severity: Severity
    confidence: Confidence
    evidence: str
    recommendation: str
    expected_behavior: str
    observed_behavior: str
    indicators: list[BehavioralIndicator] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str
    case_id: str
    target_id: str
    scan_id: str | None = None
    category: str
    title: str
    description: str | None = None
    detection_rationale: str | None = None
    severity: Severity
    confidence: Confidence
    evidence: str
    recommendation: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attack_id: str | None = None
    attack_category: str | None = None
    attack_name: str | None = None
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    indicator_type: str | None = None
    analysis_status: AnalysisStatus | None = None
    reproducibility: dict[str, Any] = Field(default_factory=dict)
    evidence_provenance: list[EvidenceProvenance] = Field(default_factory=list)
    verification_status: FindingVerificationStatus = FindingVerificationStatus.POTENTIAL
    reproduction_reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @computed_field
    @property
    def risk_score(self) -> int:
        severity_weight = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 85,
            Severity.MEDIUM: 65,
            Severity.LOW: 40,
            Severity.INFORMATIONAL: 15,
        }[self.severity]
        confidence_factor = {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.75,
            Confidence.LOW: 0.5,
        }[self.confidence]
        return round(severity_weight * confidence_factor)


class AnalysisResult(BaseModel):
    target_id: str
    case_id: str
    scan_id: str | None = None
    category: str
    vulnerable: bool
    status: AnalysisStatus = AnalysisStatus.INCONCLUSIVE
    outcome: AnalysisOutcome = AnalysisOutcome.INCONCLUSIVE
    classification: DetectionClassification = DetectionClassification.INCONCLUSIVE
    findings: list[Finding] = Field(default_factory=list)
    attack_id: str | None = None
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    indicators: list[BehavioralIndicator] = Field(default_factory=list)
    evidence_provenance: list[EvidenceProvenance] = Field(default_factory=list)

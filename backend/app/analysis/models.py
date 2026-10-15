from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


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


class AnalysisAssessment(BaseModel):
    vulnerable: bool
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
    category: str
    title: str
    severity: Severity
    confidence: Confidence
    evidence: str
    recommendation: str
    attack_id: str | None = None
    attack_category: str | None = None
    attack_name: str | None = None
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    indicator_type: str | None = None
    reproducibility: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    target_id: str
    case_id: str
    category: str
    vulnerable: bool
    findings: list[Finding] = Field(default_factory=list)
    attack_id: str | None = None
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    indicators: list[BehavioralIndicator] = Field(default_factory=list)

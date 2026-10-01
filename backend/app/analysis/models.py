from enum import Enum

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


class AnalysisResult(BaseModel):
    target_id: str
    case_id: str
    category: str
    vulnerable: bool
    findings: list[Finding] = Field(default_factory=list)

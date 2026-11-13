from typing import Any
from enum import Enum

from pydantic import BaseModel, Field, model_validator

from app.adapters.models import CapabilityName, CapabilityProfile, TargetScope
from app.fuzzing.models import FuzzCase


class AttackRiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackDefinition(BaseModel):
    attack_id: str
    category: str
    name: str
    description: str
    prompt: str
    risk_area: str
    expected_behavior: str
    risk_level: AttackRiskLevel = AttackRiskLevel.MEDIUM
    applicable_target_scopes: list[TargetScope] = Field(default_factory=lambda: list(TargetScope))
    required_capabilities: list[CapabilityName] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=lambda: ["Explicit authorization for the synthetic test target."])
    mutation_strategy: str = "context_variation"
    detection_logic: str = "Require analyzer-supported evidence linked to the executed test case."
    evidence_requirements: list[str] = Field(default_factory=lambda: ["Persisted test case and execution result."])
    security_references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackPreviewRequest(BaseModel):
    categories: list[str] | None = None
    count: int = Field(default=10, ge=1, le=1000)
    max_mutation_depth: int = Field(default=0, ge=0, le=5)
    max_mutations_per_case: int = Field(default=0, ge=0, le=10)

    @model_validator(mode="after")
    def validate_categories(self) -> "AttackPreviewRequest":
        if self.categories is not None and (
            not self.categories or len(set(self.categories)) != len(self.categories)
        ):
            raise ValueError("Categories must be non-empty and unique.")
        return self


class AttackPreview(BaseModel):
    target_id: str
    requested_count: int
    generated_count: int
    requested_categories: list[str]
    applicable_categories: list[str]
    not_applicable_categories: list[str]
    cases: list[FuzzCase]


class AttackCategoryInfo(BaseModel):
    category: str
    attack_count: int
    required_capabilities: list[CapabilityName]
    applicable_target_scopes: list[TargetScope]
    risk_levels: list[AttackRiskLevel]
    applicable: bool = True


class BenchmarkInfo(BaseModel):
    benchmark_id: str
    name: str
    case_count: int
    categories: list[str]

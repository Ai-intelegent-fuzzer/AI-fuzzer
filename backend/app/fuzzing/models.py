from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class FuzzCase(BaseModel):
    case_id: str
    prompt: str = Field(min_length=1)
    category: str
    parent_case_id: str | None = None
    mutation_strategy: str | None = None
    mutation_depth: int = Field(default=0, ge=0)
    sequence_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FuzzTurn(BaseModel):
    turn_number: int = Field(ge=1)
    case_id: str
    prompt: str = Field(min_length=1)
    parent_case_id: str | None = None
    mutation_strategy: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FuzzConversation(BaseModel):
    conversation_id: str
    category: str
    turns: list[FuzzTurn] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanStatus(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanCreateRequest(BaseModel):
    target_id: str
    count: int = Field(default=10, ge=1, le=100)
    categories: list[str] | None = None
    max_mutation_depth: int = Field(default=1, ge=0, le=5)
    max_mutations_per_case: int = Field(default=10, ge=0, le=10)
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    max_retries: int = Field(default=0, ge=0, le=5)
    concurrency: int = Field(default=1, ge=1, le=8)
    delay_seconds: float = Field(default=0.0, ge=0, le=10)
    execution_order: Literal["generated", "reverse", "category"] = "generated"
    multi_turn: bool = False
    turns_per_conversation: int = Field(default=3, ge=1, le=10)


class ScanMetrics(BaseModel):
    total_generated_cases: int = 0
    total_executed_cases: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    timeouts: int = 0
    retries: int = 0
    mutations_generated: int = 0
    mutation_strategies_used: list[str] = Field(default_factory=list)
    categories_tested: list[str] = Field(default_factory=list)
    vulnerable_cases: int = 0
    findings: int = 0
    average_execution_time_ms: float = 0.0
    total_execution_time_ms: float = 0.0
    category_statistics: dict[str, dict[str, int]] = Field(default_factory=dict)


class FuzzingCoverage(BaseModel):
    categories_tested: list[str] = Field(default_factory=list)
    mutation_strategies_tested: list[str] = Field(default_factory=list)
    mutation_depths: list[int] = Field(default_factory=list)
    unique_prompts: int = 0
    unique_test_cases: int = 0
    target_responses: int = 0


class ScanRecord(BaseModel):
    scan_id: str
    target_id: str
    status: ScanStatus = ScanStatus.CREATED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    requested_case_count: int
    generated_case_count: int = 0
    executed_case_count: int = 0
    finding_count: int = 0
    error_count: int = 0
    metrics: ScanMetrics = Field(default_factory=ScanMetrics)
    coverage: FuzzingCoverage = Field(default_factory=FuzzingCoverage)
    failure_reason: str | None = None


class FuzzCaseRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=100)

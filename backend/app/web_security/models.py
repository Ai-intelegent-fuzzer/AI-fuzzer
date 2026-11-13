from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class WebTestStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_TESTED = "NOT_TESTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class WebTestCase(BaseModel):
    test_id: str
    category: str
    description: str
    expected_behavior: str
    recommendation: str


class WebFixture(BaseModel):
    fixture_id: str
    display_name: str
    description: str
    simulated: bool = True


class WebTestRunRequest(BaseModel):
    fixture_id: str = Field(pattern=r"^synthetic-webapp-(?:vulnerable|secure)$")
    test_ids: list[str] = Field(min_length=1, max_length=20)


class WebTestEvidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    test_id: str
    fixture_id: str
    category: str
    status: WebTestStatus
    severity: str
    confidence: str
    synthetic_request: dict[str, str]
    synthetic_response: dict[str, str]
    expected_behavior: str
    observed_behavior: str
    recommendation: str
    evidence_reference: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WebTestRunResponse(BaseModel):
    fixture_id: str
    simulated: bool = True
    results: list[WebTestEvidence]

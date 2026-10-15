from typing import Any

from pydantic import BaseModel, Field


class AttackDefinition(BaseModel):
    attack_id: str
    category: str
    name: str
    description: str
    prompt: str
    risk_area: str
    expected_behavior: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

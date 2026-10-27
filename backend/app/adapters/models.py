from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, model_validator

from app.adapters.endpoint_policy import validate_target_endpoint


class TargetType(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    CHATBOT = "chatbot"
    RAG = "rag"
    AGENT = "agent"


class AIProvider(str, Enum):
    OPENAI = "openai"
    GROQ = "groq"
    GEMINI = "gemini"


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    target_type: TargetType
    endpoint: HttpUrl
    model: Optional[str] = None
    provider: AIProvider = AIProvider.OPENAI
    description: Optional[str] = None

    @model_validator(mode="after")
    def validate_endpoint_policy(self) -> "TargetCreate":
        provider = (
            self.provider.value
            if self.target_type == TargetType.OPENAI_COMPATIBLE
            else None
        )
        validate_target_endpoint(
            str(self.endpoint),
            provider=provider,
            resolve_dns=False,
        )
        return self


class Target(TargetCreate):
    target_id: str

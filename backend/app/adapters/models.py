from enum import Enum
import re
from typing import Optional
from datetime import datetime

from pydantic import SecretStr

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
    ANTHROPIC = "anthropic"
    MISTRAL = "mistral"
    OLLAMA = "ollama"
    CUSTOM = "custom"


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    target_type: TargetType
    endpoint: HttpUrl
    model: Optional[str] = None
    provider: AIProvider = AIProvider.OPENAI
    description: Optional[str] = None
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    api_path: str | None = None
    auth_header: str = "Authorization"
    system_prompt: str | None = None
    temperature: float = Field(default=0.0, ge=0, le=2)
    max_output_tokens: int = Field(default=256, ge=1, le=8192)

    @model_validator(mode="after")
    def validate_endpoint_policy(self) -> "TargetCreate":
        provider = self.provider.value if self.provider != AIProvider.CUSTOM else None
        validate_target_endpoint(
            str(self.endpoint),
            provider=provider,
            resolve_dns=False,
            allow_local_ollama=self.provider == AIProvider.OLLAMA,
        )
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", self.auth_header):
            raise ValueError("Authentication header name is invalid.")
        if self.auth_header.lower() in {"host", "content-length", "connection"}:
            raise ValueError("Authentication header name is not allowed.")
        if self.api_path and (
            "?" in self.api_path
            or "#" in self.api_path
            or "://" in self.api_path
            or any(part == ".." for part in self.api_path.split("/"))
        ):
            raise ValueError("API path must be a relative path without query, fragment, or traversal segments.")
        return self


class Target(TargetCreate):
    target_id: str
    connection_status: str = "unknown"
    last_tested: datetime | None = None

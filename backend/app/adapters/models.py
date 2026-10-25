from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


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


class Target(TargetCreate):
    target_id: str

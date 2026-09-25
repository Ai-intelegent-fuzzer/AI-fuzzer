from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


class TargetType(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    CHATBOT = "chatbot"
    RAG = "rag"
    AGENT = "agent"


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    target_type: TargetType
    endpoint: HttpUrl
    model: Optional[str] = None
    description: Optional[str] = None


class Target(TargetCreate):
    target_id: str

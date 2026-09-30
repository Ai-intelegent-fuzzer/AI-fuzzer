from pydantic import BaseModel, Field


class FuzzCase(BaseModel):
    case_id: str
    prompt: str = Field(min_length=1)
    category: str


class FuzzCaseRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=100)

from pydantic import BaseModel


class FuzzCase(BaseModel):
    case_id: str
    prompt: str
    category: str

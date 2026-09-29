from pydantic import BaseModel


class ExecutionResult(BaseModel):
    target_id: str
    case_id: str
    status: str
    status_code: int | None = None
    response_time_ms: float | None = None
    response_body: str | None = None
    message: str

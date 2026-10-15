from pydantic import BaseModel


class ExecutionResult(BaseModel):
    target_id: str
    case_id: str
    status: str
    status_code: int | None = None
    response_time_ms: float | None = None
    response_body: str | None = None
    message: str
    attempts: int = 1
    retries: int = 0
    failure_reason: str | None = None
    response_truncated: bool = False

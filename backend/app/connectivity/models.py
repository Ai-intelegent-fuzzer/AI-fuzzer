from enum import Enum

from pydantic import BaseModel


class ConnectivityStatus(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    ERROR = "error"


class ConnectivityResult(BaseModel):
    target_id: str
    status: ConnectivityStatus
    status_code: int | None = None
    response_time_ms: float | None = None
    message: str

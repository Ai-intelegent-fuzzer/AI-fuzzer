import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.adapters.base import AdapterError
from app.adapters.factory import UnsupportedTargetError, get_adapter
from app.adapters.manager import target_manager


router = APIRouter(
    prefix="/targets",
    tags=["AI Adapter"],
)
logger = logging.getLogger(__name__)


class PromptRequest(BaseModel):
    prompt: str = Field(min_length=1)


class PromptResponse(BaseModel):
    target_id: str
    response: str


@router.post(
    "/{target_id}/prompt",
    response_model=PromptResponse,
)
def send_prompt(target_id: str, request: PromptRequest):

    target = target_manager.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    try:
        adapter = get_adapter(target)
        result = adapter.send_prompt(request.prompt)

        return PromptResponse(
            target_id=target_id,
            response=result,
        )

    except AdapterError as exc:
        result = exc.result
        logger.error(
            "Provider prompt failed for target_id=%s provider=%s "
            "status=%s failure_reason=%s message=%s",
            target_id,
            result.provider or target.provider.value,
            result.status,
            result.failure_reason or "provider_request_failed",
            result.message,
        )
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
                if result.status == "configuration_error"
                else status.HTTP_429_TOO_MANY_REQUESTS
                if result.status == "rate_limited"
                else status.HTTP_504_GATEWAY_TIMEOUT
                if result.status == "timeout"
                else status.HTTP_502_BAD_GATEWAY
            ),
            detail=result.message,
        ) from None
    except UnsupportedTargetError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from None
    except Exception as exc:
        # Do not expose provider exception messages to API clients.
        # Log only the target ID and exception type, not prompts or secrets.
        logger.error(
            "Prompt request failed for target_id=%s; exception_type=%s",
            target_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Target request failed. Check target configuration and server logs.",
        ) from None

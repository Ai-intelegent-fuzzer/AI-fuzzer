from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.adapters.factory import get_adapter
from app.adapters.manager import target_manager


router = APIRouter(
    prefix="/targets",
    tags=["AI Adapter"],
)


class PromptRequest(BaseModel):
    prompt: str


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

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Target request failed: {exc}",
        )

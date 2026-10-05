from fastapi import APIRouter, HTTPException, Query

from app.adapters.manager import target_manager
from app.attacks.registry import attack_registry
from app.fuzzing.engine import fuzz_engine
from app.fuzzing.models import FuzzCase


router = APIRouter(
    prefix="/targets",
    tags=["Fuzzing"],
)


@router.post(
    "/{target_id}/fuzz-cases",
    response_model=list[FuzzCase],
)
def generate_fuzz_cases(
    target_id: str,
    count: int = Query(default=4, ge=1, le=100),
):
    target = target_manager.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    return fuzz_engine.generate(count)


@router.post(
    "/{target_id}/attack-cases",
    response_model=list[FuzzCase],
)
def generate_attack_cases(
    target_id: str,
    category: str | None = None,
    count: int = Query(default=4, ge=1, le=100),
):
    target = target_manager.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    if category is None:
        attacks = attack_registry.generate_multiple(attack_registry.list_categories(), count)
    else:
        attacks = attack_registry.generate(category, count)

    return [attack_registry.to_fuzz_case(attack) for attack in attacks]

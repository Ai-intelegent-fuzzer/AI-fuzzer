from fastapi import APIRouter, HTTPException, Query

from app.adapters.manager import target_manager
from app.attacks.registry import attack_registry
from app.attacks.capabilities import category_supported_by_profile
from app.fuzzing.engine import FUZZ_TEMPLATES, fuzz_engine
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

    categories = sorted(set(attack_registry.list_all_categories()) | set(FUZZ_TEMPLATES))
    applicable_categories = [
        category
        for category in categories
        if category_supported_by_profile(
            category,
            target.capability_profile,
            target.target_scope,
        )
    ]
    return fuzz_engine.generate(count, applicable_categories)


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

    categories = [category] if category is not None else attack_registry.list_all_categories()
    applicable_categories = [
        item
        for item in categories
        if category_supported_by_profile(
            item,
            target.capability_profile,
            target.target_scope,
        )
    ]
    return fuzz_engine.generate(
        count,
        applicable_categories,
        max_mutation_depth=0,
    )

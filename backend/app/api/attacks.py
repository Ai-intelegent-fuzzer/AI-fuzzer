from fastapi import APIRouter, HTTPException, Query

from app.adapters.manager import target_manager
from app.attacks.capabilities import applicable_categories, category_supported_by_profile
from app.attacks.models import (
    AttackCategoryInfo,
    AttackDefinition,
    AttackPreview,
    AttackPreviewRequest,
    AttackRiskLevel,
    BenchmarkInfo,
)
from app.attacks.registry import (
    PROMPT_INJECTION_BENCHMARK_CATEGORIES,
    PROMPT_INJECTION_BENCHMARK_ID,
    attack_registry,
)
from app.attacks.taxonomy import ATTACK_CATEGORY_REQUIREMENTS, applicable_scopes
from app.fuzzing.engine import FUZZ_TEMPLATES, fuzz_engine
from app.fuzzing.models import FuzzCase

router = APIRouter(tags=["Attack Library"])


@router.get("/benchmarks", response_model=list[BenchmarkInfo])
def list_benchmarks() -> list[BenchmarkInfo]:
    return [BenchmarkInfo(
        benchmark_id=PROMPT_INJECTION_BENCHMARK_ID,
        name="Prompt-injection benchmark (180 cases)",
        case_count=sum(
            sum(
                attack.metadata.get("benchmark_id") == PROMPT_INJECTION_BENCHMARK_ID
                for attack in attack_registry.get_attacks(category)
            )
            for category in PROMPT_INJECTION_BENCHMARK_CATEGORIES
        ),
        categories=list(PROMPT_INJECTION_BENCHMARK_CATEGORIES),
    )]


@router.get("/benchmarks/{benchmark_id}/cases", response_model=list[AttackDefinition])
def list_benchmark_cases(benchmark_id: str) -> list[AttackDefinition]:
    if benchmark_id != PROMPT_INJECTION_BENCHMARK_ID:
        raise HTTPException(status_code=404, detail="Benchmark not found.")
    return [
        attack for attack in attack_registry.list_attacks()
        if attack.metadata.get("benchmark_id") == benchmark_id
    ]


def _target_profile(target_id: str | None):
    if target_id is None:
        return None, None
    target = target_manager.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    return target.capability_profile, target.target_scope


@router.get("/attacks/categories", response_model=list[AttackCategoryInfo])
def list_attack_categories(
    target_id: str | None = None,
) -> list[AttackCategoryInfo]:
    profile, target_scope = _target_profile(target_id)
    categories = sorted(set(attack_registry.list_all_categories()) | set(FUZZ_TEMPLATES))
    result: list[AttackCategoryInfo] = []
    for category in categories:
        attacks = attack_registry.get_attacks(category) if category in attack_registry.list_all_categories() else []
        required = ATTACK_CATEGORY_REQUIREMENTS.get(category, ())
        result.append(AttackCategoryInfo(
            category=category,
            attack_count=len(attacks) if attacks else len(FUZZ_TEMPLATES.get(category, [])),
            required_capabilities=list(required),
            applicable_target_scopes=applicable_scopes(category),
            risk_levels=sorted({attack.risk_level for attack in attacks}, key=lambda level: level.value),
            applicable=(
                category_supported_by_profile(category, profile, target_scope)
                if target_id is not None
                else True
            ),
        ))
    return result


@router.get("/attacks", response_model=list[AttackDefinition])
def list_attacks(
    category: str | None = None,
    target_id: str | None = None,
    risk_level: AttackRiskLevel | None = None,
    search: str | None = Query(default=None, max_length=120),
) -> list[AttackDefinition]:
    profile, target_scope = _target_profile(target_id)
    attacks = attack_registry.list_attacks()
    if category is not None:
        attacks = [attack for attack in attacks if attack.category == category]
    if risk_level is not None:
        attacks = [attack for attack in attacks if attack.risk_level == risk_level]
    if search:
        query = search.casefold()
        attacks = [
            attack for attack in attacks
            if query in attack.name.casefold()
            or query in attack.description.casefold()
            or query in attack.category.casefold()
            or any(query in tag.casefold() for tag in attack.tags)
        ]
    if target_id is not None:
        attacks = [
            attack for attack in attacks
            if target_scope in attack.applicable_target_scopes
            and category_supported_by_profile(attack.category, profile, target_scope)
        ]
    return attacks


@router.get("/attacks/{attack_id}", response_model=AttackDefinition)
def get_attack(attack_id: str) -> AttackDefinition:
    try:
        return attack_registry.get_attack(attack_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Attack definition not found.") from exc


@router.get(
    "/targets/{target_id}/attacks/applicable",
    response_model=list[AttackDefinition],
)
def list_applicable_attacks(target_id: str) -> list[AttackDefinition]:
    profile, target_scope = _target_profile(target_id)
    return [
        attack
        for attack in attack_registry.list_attacks()
        if target_scope in attack.applicable_target_scopes
        and category_supported_by_profile(attack.category, profile, target_scope)
    ]


@router.post(
    "/targets/{target_id}/attacks/preview",
    response_model=AttackPreview,
)
def preview_attacks(
    target_id: str,
    request: AttackPreviewRequest,
) -> AttackPreview:
    profile, target_scope = _target_profile(target_id)
    supported_categories = sorted(set(attack_registry.list_all_categories()) | set(FUZZ_TEMPLATES))
    requested = request.categories or supported_categories
    unknown = sorted(set(requested) - set(supported_categories))
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported attack categories: {', '.join(unknown)}",
        )
    applicable, not_applicable = applicable_categories(requested, profile, target_scope)
    cases: list[FuzzCase] = fuzz_engine.generate(
        request.count,
        applicable,
        max_cases=request.count,
        max_mutation_depth=request.max_mutation_depth,
        max_mutations_per_case=request.max_mutations_per_case,
    )
    return AttackPreview(
        target_id=target_id,
        requested_count=request.count,
        generated_count=len(cases),
        requested_categories=requested,
        applicable_categories=applicable,
        not_applicable_categories=not_applicable,
        cases=cases,
    )

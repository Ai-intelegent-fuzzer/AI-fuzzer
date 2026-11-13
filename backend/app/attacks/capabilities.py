from app.adapters.models import CapabilityProfile, TargetScope
from app.attacks.taxonomy import (
    ATTACK_CATEGORY_REQUIREMENTS,
    applicable_scopes,
)


def category_supported_by_profile(
    category: str,
    profile: CapabilityProfile | None,
    target_scope: TargetScope | None = None,
) -> bool:
    if category not in ATTACK_CATEGORY_REQUIREMENTS:
        return True
    if target_scope is not None and target_scope not in applicable_scopes(category):
        return False
    if target_scope == TargetScope.MODEL_ENDPOINT:
        return False
    if profile is None:
        return False
    return all(
        profile.capabilities[capability].enabled
        for capability in ATTACK_CATEGORY_REQUIREMENTS[category]
    )


def applicable_categories(
    categories: list[str],
    profile: CapabilityProfile | None,
    target_scope: TargetScope | None,
) -> tuple[list[str], list[str]]:
    applicable = [
        category
        for category in categories
        if category_supported_by_profile(category, profile, target_scope)
    ]
    not_applicable = [category for category in categories if category not in applicable]
    return applicable, not_applicable

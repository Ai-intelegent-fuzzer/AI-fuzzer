from app.adapters.models import CapabilityName, CapabilityProfile, TargetScope
from app.attacks.capabilities import category_supported_by_profile as _category_supported_by_profile
from app.attacks.taxonomy import ATTACK_CATEGORY_REQUIREMENTS

RAG_CATEGORY_REQUIREMENTS = {
    category: requirements
    for category, requirements in ATTACK_CATEGORY_REQUIREMENTS.items()
    if category.startswith("rag_") or category == "indirect_prompt_injection"
}


def category_supported_by_profile(
    category: str,
    profile: CapabilityProfile | None,
    target_scope: TargetScope | None = None,
) -> bool:
    return _category_supported_by_profile(category, profile, target_scope)

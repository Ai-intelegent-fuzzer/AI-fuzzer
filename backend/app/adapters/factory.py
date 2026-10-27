from app.adapters.base import AIAdapter
from app.adapters.models import AIProvider, Target
from app.adapters.gemini_adapter import GeminiAdapter
from app.adapters.openai_compatible import OpenAICompatibleAdapter


class UnsupportedTargetError(ValueError):
    pass


def get_adapter(target: Target) -> AIAdapter:

    if target.target_type == "openai_compatible":
        if target.provider == AIProvider.GEMINI:
            return GeminiAdapter(target)
        return OpenAICompatibleAdapter(target)

    raise UnsupportedTargetError(
        f"Unsupported target type: {target.target_type}"
    )

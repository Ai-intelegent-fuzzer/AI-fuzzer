from app.adapters.base import AIAdapter
from app.adapters.models import Target
from app.adapters.openai_compatible import OpenAICompatibleAdapter


def get_adapter(target: Target) -> AIAdapter:

    if target.target_type == "openai_compatible":
        return OpenAICompatibleAdapter(target)

    raise ValueError(
        f"Unsupported target type: {target.target_type}"
    )

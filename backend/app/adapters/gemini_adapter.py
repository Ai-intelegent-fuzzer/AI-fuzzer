from app.adapters.base import AIAdapter
from app.execution.executor import fuzz_executor
from app.fuzzing.models import FuzzCase


class GeminiAdapter(AIAdapter):
    """Use the shared execution engine for Gemini prompt requests."""

    def send_prompt(self, prompt: str) -> str:
        result = fuzz_executor.execute(
            self.target,
            FuzzCase(
                case_id="adapter-prompt",
                prompt=prompt,
                category="adapter_prompt",
            ),
            timeout_seconds=30.0,
            max_retries=0,
        )

        if result.status != "completed":
            raise RuntimeError(result.message)

        if result.response_body is None:
            raise RuntimeError("Gemini returned no response body.")

        return result.response_body

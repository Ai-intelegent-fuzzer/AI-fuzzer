from app.adapters.base import AIAdapter, AdapterError
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
            raise AdapterError(result)

        if result.response_body is None:
            raise AdapterError(
                result.model_copy(
                    update={
                        "status": "invalid_response",
                        "message": "Gemini returned no usable response content.",
                        "failure_reason": "provider_response_empty",
                    }
                )
            )

        return result.response_body

from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.adapters.models import Target
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase


class AdapterError(RuntimeError):
    def __init__(self, result: ExecutionResult) -> None:
        self.result = result
        super().__init__(result.message)


class AIAdapter(ABC):

    def __init__(self, target: Target):
        self.target = target

    @property
    def provider(self) -> str:
        return self.target.provider.value

    @property
    def model(self) -> str | None:
        return self.target.model

    def execute_case(
        self,
        case: FuzzCase,
        *,
        timeout_seconds: float = 30.0,
        max_retries: int = 0,
        conversation_context: Sequence[str] | None = None,
    ) -> ExecutionResult:
        from app.execution.executor import fuzz_executor

        return fuzz_executor.execute(
            self.target,
            case,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            conversation_context=conversation_context,
        )

    @abstractmethod
    def send_prompt(self, prompt: str) -> str:
        pass

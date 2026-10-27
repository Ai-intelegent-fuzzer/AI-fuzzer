from abc import ABC, abstractmethod

from app.adapters.models import Target
from app.execution.models import ExecutionResult


class AdapterError(RuntimeError):
    def __init__(self, result: ExecutionResult) -> None:
        self.result = result
        super().__init__(result.message)


class AIAdapter(ABC):

    def __init__(self, target: Target):
        self.target = target

    @abstractmethod
    def send_prompt(self, prompt: str) -> str:
        pass

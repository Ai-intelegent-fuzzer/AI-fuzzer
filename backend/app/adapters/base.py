from abc import ABC, abstractmethod

from app.adapters.models import Target


class AIAdapter(ABC):

    def __init__(self, target: Target):
        self.target = target

    @abstractmethod
    def send_prompt(self, prompt: str) -> str:
        pass

from uuid import uuid4

from .models import Target, TargetCreate


class TargetManager:
    def __init__(self) -> None:
        self._targets: dict[str, Target] = {}

    def create(self, target_data: TargetCreate) -> Target:
        target_id = str(uuid4())
        target = Target(target_id=target_id, **target_data.model_dump())
        self._targets[target_id] = target
        return target

    def list(self) -> list[Target]:
        return list(self._targets.values())

    def get(self, target_id: str) -> Target | None:
        return self._targets.get(target_id)

    def delete(self, target_id: str) -> bool:
        return self._targets.pop(target_id, None) is not None


# Temporary in-memory manager for Phase 2.
target_manager = TargetManager()

from uuid import uuid4
from datetime import datetime

from app.database.store import Database, database

from .models import Target, TargetCreate


class TargetManager:
    def __init__(self, store: Database | None = None) -> None:
        self._store = store or Database("sqlite://")
        if store is None:
            self._store.initialize()

    def create(self, target_data: TargetCreate) -> Target:
        target = Target(
            target_id=str(uuid4()),
            **target_data.model_dump(),
            api_key=target_data.api_key,
        )
        self._store.create_target(target)
        return target

    def list(self) -> list[Target]:
        return self._store.list_targets()

    def get(self, target_id: str) -> Target | None:
        return self._store.get_target(target_id)

    def update(self, target_id: str, target_data: TargetCreate) -> Target | None:
        target = Target(
            target_id=target_id,
            **target_data.model_dump(),
            api_key=target_data.api_key,
        )
        return target if self._store.update_target(target_id, target) else None

    def delete(self, target_id: str) -> bool:
        return self._store.delete_target(target_id)

    def update_credential(self, target_id: str, credential: str | None) -> bool:
        return self._store.update_target_credential(target_id, credential)

    def update_connectivity(self, target_id: str, status: str, tested_at: datetime) -> bool:
        return self._store.update_target_connectivity(target_id, status, tested_at)


target_manager = TargetManager(database)

from fastapi import APIRouter, HTTPException, status

from app.adapters.manager import target_manager
from app.adapters.models import Target, TargetCreate

router = APIRouter(prefix="/targets", tags=["Targets"])


@router.post("", response_model=Target, status_code=status.HTTP_201_CREATED)
def create_target(target_data: TargetCreate) -> Target:
    return target_manager.create(target_data)


@router.get("", response_model=list[Target])
def list_targets() -> list[Target]:
    return target_manager.list()


@router.get("/{target_id}", response_model=Target)
def get_target(target_id: str) -> Target:
    target = target_manager.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: str) -> None:
    if not target_manager.delete(target_id):
        raise HTTPException(status_code=404, detail="Target not found")

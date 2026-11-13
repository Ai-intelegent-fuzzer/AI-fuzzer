from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, SecretStr

from app.adapters.manager import target_manager
from app.adapters.models import CapabilityProfile, Target, TargetCreate

router = APIRouter(prefix="/targets", tags=["Targets"])


class CredentialUpdate(BaseModel):
    api_key: SecretStr


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


@router.put("/{target_id}", response_model=Target)
def update_target(target_id: str, target_data: TargetCreate) -> Target:
    target = target_manager.update(target_id, target_data)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/{target_id}/capabilities", response_model=Target)
def update_target_capabilities(
    target_id: str,
    capability_profile: CapabilityProfile,
) -> Target:
    target = target_manager.update_capabilities(target_id, capability_profile)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/{target_id}/credential", status_code=status.HTTP_204_NO_CONTENT)
def update_target_credential(target_id: str, data: CredentialUpdate) -> None:
    if not target_manager.update_credential(target_id, data.api_key.get_secret_value()):
        raise HTTPException(status_code=404, detail="Target not found")


@router.delete("/{target_id}/credential", status_code=status.HTTP_204_NO_CONTENT)
def delete_target_credential(target_id: str) -> None:
    if not target_manager.update_credential(target_id, None):
        raise HTTPException(status_code=404, detail="Target not found")


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: str) -> None:
    if not target_manager.delete(target_id):
        raise HTTPException(status_code=404, detail="Target not found")

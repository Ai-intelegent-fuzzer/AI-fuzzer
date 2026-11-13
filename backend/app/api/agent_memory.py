from fastapi import APIRouter, HTTPException, Query, status

from app.agent_memory.models import (
    MemoryAccessRequest,
    MemoryAudit,
    MemoryCreateRequest,
    MemoryRecord,
    MemoryScenario,
    MemoryScenarioResult,
    MemoryUpdateRequest,
)
from app.agent_memory.service import AgentMemoryService
from app.database.store import database

router = APIRouter(prefix="/memories", tags=["Synthetic Agent Memory"])
memory_service = AgentMemoryService(database)


@router.post("", response_model=MemoryRecord, status_code=status.HTTP_201_CREATED)
def create_memory(request: MemoryCreateRequest) -> MemoryRecord:
    try:
        return memory_service.create(
            request.memory_data(),
            MemoryAccessRequest(
                identity_id=request.identity_id,
                session_id=request.session_id,
                context_identity_id=request.context_identity_id,
            ),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/search", response_model=list[MemoryRecord])
def list_memories(request: MemoryAccessRequest) -> list[MemoryRecord]:
    return memory_service.list_for_identity(request)


@router.post("/{memory_id}/retrieve")
def retrieve_memory(memory_id: str, request: MemoryAccessRequest) -> dict[str, object]:
    try:
        result = memory_service.retrieve(memory_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "memory": result.memory,
        "audit": result.audit,
        "retrieved": result.memory is not None,
    }


@router.patch("/{memory_id}", response_model=dict[str, object])
def update_memory(memory_id: str, request: MemoryUpdateRequest) -> dict[str, object]:
    try:
        result = memory_service.update(
            memory_id,
            request.content,
            MemoryAccessRequest(
                identity_id=request.identity_id,
                session_id=request.session_id,
                context_identity_id=request.context_identity_id,
            ),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"memory": result.memory, "audit": result.audit, "updated": result.memory is not None}


@router.delete("/{memory_id}", response_model=MemoryAudit)
def delete_memory(memory_id: str, request: MemoryAccessRequest) -> MemoryAudit:
    try:
        return memory_service.delete(memory_id, request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/security-tests", response_model=MemoryScenarioResult)
def run_memory_scenario(scenario: MemoryScenario) -> MemoryScenarioResult:
    return memory_service.run_scenario(scenario)


@router.get("/audits", response_model=list[MemoryAudit])
def list_memory_audits(limit: int = Query(default=100, ge=1, le=500)) -> list[MemoryAudit]:
    return database.list_memory_audits(limit)

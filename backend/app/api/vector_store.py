from fastapi import APIRouter, HTTPException, Query, status

from app.database.store import database
from app.vector_store.models import (
    VectorAudit,
    VectorCollection,
    VectorCollectionCreateRequest,
    VectorCollectionCreate,
    VectorDocument,
    VectorDocumentCreate,
    VectorDocumentUpsertRequest,
    VectorSearchRequest,
    VectorSearchResponse,
    VectorDeleteRequest,
)
from app.vector_store.service import VectorStoreService

router = APIRouter(prefix="/vector-store", tags=["Local Synthetic Vector Store"])
vector_service = VectorStoreService(database)


@router.get("/collections", response_model=list[VectorCollection])
def list_collections() -> list[VectorCollection]:
    return vector_service.list_collections()


@router.post("/collections", response_model=VectorCollection, status_code=status.HTTP_201_CREATED)
def create_collection(request: VectorCollectionCreateRequest) -> VectorCollection:
    try:
        return vector_service.create_collection(
            VectorCollectionCreate.model_validate(
                request.model_dump(exclude={"identity_id", "session_id"})
            ),
            request.identity_id,
            request.session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/documents", response_model=VectorDocument, status_code=status.HTTP_201_CREATED)
def upsert_document(request: VectorDocumentUpsertRequest) -> VectorDocument:
    try:
        return vector_service.upsert(
            VectorDocumentCreate.model_validate(
                request.model_dump(exclude={"identity_id", "session_id"})
            ),
            request.identity_id,
            request.session_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/search", response_model=VectorSearchResponse)
def search_documents(request: VectorSearchRequest) -> VectorSearchResponse:
    try:
        return vector_service.search(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete("/documents/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(document_id: str, request: VectorDeleteRequest) -> None:
    deleted = vector_service.delete(
        document_id,
        request.identity_id,
        request.session_id,
        request.context_identity_id,
    )
    if not deleted:
        if database.get_vector_document(document_id) is None:
            raise HTTPException(status_code=404, detail="Synthetic vector document not found.")
        raise HTTPException(status_code=403, detail="Synthetic vector document deletion denied.")


@router.get("/audits", response_model=list[VectorAudit])
def list_audits(limit: int = Query(default=100, ge=1, le=500)) -> list[VectorAudit]:
    return database.list_vector_audits(limit)

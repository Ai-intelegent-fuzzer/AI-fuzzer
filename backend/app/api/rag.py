from fastapi import APIRouter, HTTPException, Query, status

from app.rag.models import (
    RAGDocumentCreate,
    RAGDocumentMetadata,
    RAGRetrievalRequest,
    RAGRetrievalResponse,
    RAGScenario,
    RAGScenarioRequest,
    RAGRetrievalAudit,
)
from app.rag.service import RAGService
from app.database.store import database

router = APIRouter(prefix="/rag", tags=["Synthetic RAG"])
rag_service = RAGService(database)


@router.get("/documents", response_model=list[RAGDocumentMetadata])
def list_documents() -> list[RAGDocumentMetadata]:
    return rag_service.list_metadata()


@router.post(
    "/documents",
    response_model=RAGDocumentMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_document(document_data: RAGDocumentCreate) -> RAGDocumentMetadata:
    try:
        document = rag_service.ingest(document_data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return RAGDocumentMetadata.from_document(document)


@router.get("/documents/{document_id}", response_model=RAGDocumentMetadata)
def get_document_metadata(document_id: str) -> RAGDocumentMetadata:
    metadata = rag_service.get_metadata(document_id)
    if metadata is None:
        raise HTTPException(status_code=404, detail="Synthetic RAG document not found")
    return metadata


@router.post("/retrievals", response_model=RAGRetrievalResponse)
def retrieve_documents(request: RAGRetrievalRequest) -> RAGRetrievalResponse:
    return rag_service.retrieve(request)


@router.post(
    "/scenarios",
    response_model=RAGRetrievalResponse,
    status_code=status.HTTP_201_CREATED,
)
def run_rag_scenario(request: RAGScenarioRequest) -> RAGRetrievalResponse:
    return rag_service.run_scenario(
        request.scenario,
        scan_id=request.scan_id,
        test_case_id=request.test_case_id,
    )


@router.get("/scenarios", response_model=list[str])
def list_rag_scenarios() -> list[str]:
    return [scenario.value for scenario in RAGScenario]


@router.get("/retrieval-audits", response_model=list[RAGRetrievalAudit])
def list_retrieval_audits(
    limit: int = Query(default=100, ge=1, le=500),
    scan_id: str | None = None,
    test_case_id: str | None = None,
) -> list[RAGRetrievalAudit]:
    return database.list_rag_retrieval_audits(
        limit=limit,
        scan_id=scan_id,
        test_case_id=test_case_id,
    )


@router.get("/retrieval-audits/{audit_id}", response_model=RAGRetrievalAudit)
def get_retrieval_audit(audit_id: str) -> RAGRetrievalAudit:
    audit = database.get_rag_retrieval_audit(audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="RAG retrieval audit not found")
    return audit

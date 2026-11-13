import hashlib

from datetime import datetime, timezone
from uuid import uuid4

from app.authorization.models import (
    AuthorizationCheckRequest,
    AuthorizationDecision,
    Permission,
    ResourceClassification,
    ResourceOperation,
    SyntheticResource,
)
from app.authorization.policy import AuthorizationPolicy
from app.database.store import Database
from app.vector_store.adapter import LocalHashedVectorAdapter, VectorStoreAdapter
from app.vector_store.models import (
    VectorAudit,
    VectorCollection,
    VectorCollectionCreate,
    VectorDocument,
    VectorDocumentCreate,
    VectorDocumentResult,
    VectorSearchRequest,
    VectorSearchResponse,
)


class VectorStoreService:
    def __init__(self, store: Database, adapter: VectorStoreAdapter | None = None) -> None:
        self._store = store
        self._adapter = adapter or LocalHashedVectorAdapter()
        self._policy = AuthorizationPolicy(store)

    def ensure_default(self) -> None:
        self._store.create_vector_collection(VectorCollection(tenant_id="tenant-a"))

    def create_collection(
        self,
        data: VectorCollectionCreate,
        identity_id: str,
        session_id: str,
    ) -> VectorCollection:
        collection = VectorCollection(
            **data.model_dump(exclude={"collection_id"}),
            collection_id=f"synthetic-vector-collection-{uuid4()}",
        )
        identity = self._store.get_identity(identity_id)
        if identity is None or identity.session_id != session_id or identity.tenant_id != collection.tenant_id:
            raise ValueError("Collection tenant and session must match the requesting synthetic identity.")
        self._store.create_vector_collection(collection)
        return collection

    def list_collections(self) -> list[VectorCollection]:
        self.ensure_default()
        return self._store.list_vector_collections()

    def upsert(
        self,
        data: VectorDocumentCreate,
        identity_id: str,
        session_id: str,
    ) -> VectorDocument:
        self.ensure_default()
        collection = self._store.get_vector_collection(data.collection_id)
        if collection is None:
            raise ValueError("Synthetic vector collection not found.")
        if collection.tenant_id != data.tenant_id:
            raise ValueError("Document tenant must match the collection tenant.")
        if data.owner_identity_id != identity_id:
            raise ValueError("A synthetic identity may only create documents under its own identity.")
        identity = self._store.get_identity(identity_id)
        if identity is None or identity.session_id != session_id or identity.tenant_id != data.tenant_id:
            raise ValueError("Document tenant and session must match the requesting synthetic identity.")
        existing = self._store.get_vector_document(data.document_id) if data.document_id else None
        document = VectorDocument(
            **data.model_dump(exclude={"document_id"}),
            document_id=data.document_id or f"synthetic-vector-document-{uuid4()}",
            created_at=existing.created_at if existing else datetime.now(timezone.utc),
        )
        if existing and (
            existing.owner_identity_id != identity_id
            or existing.collection_id != document.collection_id
            or existing.tenant_id != document.tenant_id
        ):
            raise ValueError("Document updates cannot change owner, collection, or tenant.")
        decision = self._authorize(
            identity_id,
            session_id,
            document,
            ResourceOperation.WRITE,
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)
        self._store.upsert_vector_document(document)
        self._adapter.upsert(document)
        return document

    def _resource(self, document: VectorDocument) -> SyntheticResource:
        return SyntheticResource(
            resource_id=document.resource_id,
            display_name=document.title,
            owner_identity_id=document.owner_identity_id,
            tenant_id=document.tenant_id,
            classification=document.classification,
            required_permissions=document.required_permissions,
        )

    def _authorize(
        self,
        identity_id: str,
        session_id: str,
        document: VectorDocument,
        operation: ResourceOperation,
        context_identity_id: str | None = None,
    ):
        return self._policy.decide_resource(
            AuthorizationCheckRequest(
                identity_id=identity_id,
                session_id=session_id,
                resource_id=document.resource_id,
                operation=operation,
                context_identity_id=context_identity_id,
                expected_authorization_result=AuthorizationDecision.ALLOWED,
            ),
            self._resource(document),
        )

    def search(self, request: VectorSearchRequest) -> VectorSearchResponse:
        self.ensure_default()
        collection = self._store.get_vector_collection(request.collection_id)
        if collection is None:
            raise ValueError("Synthetic vector collection not found.")
        documents = self._store.list_vector_documents(request.collection_id)
        candidates = [
            item for item in documents
            if (request.tenant_filter is None or item.tenant_id == request.tenant_filter)
            and (request.owner_filter is None or item.owner_identity_id == request.owner_filter)
            and all(item.metadata.get(key) == value for key, value in request.metadata_filter.items())
        ]
        ranked = self._adapter.search(request.query, candidates, len(candidates))
        permitted: list[VectorDocumentResult] = []
        audits: list[VectorAudit] = []
        for document, similarity in ranked:
            decision = self._authorize(
                request.identity_id,
                request.session_id,
                document,
                ResourceOperation.READ,
                request.context_identity_id,
            )
            audit = VectorAudit(
                requesting_identity_id=request.identity_id,
                collection_id=request.collection_id,
                document_id=document.document_id,
                authorization_decision=decision.decision,
                operation="search",
                evidence_reference=hashlib.sha256(
                    f"{request.collection_id}:{document.document_id}:{decision.decision.value}".encode()
                ).hexdigest(),
            )
            self._store.save_vector_audit(audit)
            audits.append(audit)
            if decision.allowed:
                permitted.append(VectorDocumentResult(document=document, similarity=similarity))
        return VectorSearchResponse(results=permitted[:request.top_k], audits=audits)

    def delete(
        self,
        document_id: str,
        identity_id: str,
        session_id: str,
        context_identity_id: str | None = None,
    ) -> bool:
        document = self._store.get_vector_document(document_id)
        if document is None:
            return False
        decision = self._authorize(
            identity_id,
            session_id,
            document,
            ResourceOperation.WRITE,
            context_identity_id,
        )
        audit = VectorAudit(
            requesting_identity_id=identity_id,
            collection_id=document.collection_id,
            document_id=document.document_id,
            authorization_decision=decision.decision,
            operation="delete",
            evidence_reference=hashlib.sha256(
                f"{document.document_id}:{decision.decision.value}".encode()
            ).hexdigest(),
        )
        self._store.save_vector_audit(audit)
        if not decision.allowed:
            return False
        self._store.delete_vector_document(document_id)
        self._adapter.delete(document_id)
        return True

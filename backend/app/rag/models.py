from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from app.authorization.models import (
    AuthorizationDecision,
    Permission,
    ResourceClassification,
    SyntheticResource,
)


class RAGScenario(str, Enum):
    UNAUTHORIZED_DOCUMENT_RETRIEVAL = "unauthorized_document_retrieval"
    CROSS_TENANT_DOCUMENT_ACCESS = "cross_tenant_document_access"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    MALICIOUS_DOCUMENT_INSTRUCTIONS = "malicious_document_instructions"
    RETRIEVAL_POISONING = "retrieval_poisoning"
    UNAUTHORIZED_SENSITIVE_DISCLOSURE = "unauthorized_sensitive_disclosure"
    DOCUMENT_PERMISSION_BYPASS = "document_permission_bypass"
    IDENTITY_MISMATCH = "identity_mismatch"
    RETRIEVAL_CONTEXT_MANIPULATION = "retrieval_context_manipulation"
    SYNTHETIC_CANARY_EXPOSURE = "synthetic_canary_exposure"


class RAGDocument(BaseModel):
    document_id: str = Field(default_factory=lambda: f"synthetic-rag-document-{uuid4()}")
    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=10000)
    owner_identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    contains_untrusted_instructions: bool = False

    @model_validator(mode="after")
    def validate_synthetic_document(self) -> "RAGDocument":
        if not self.document_id.startswith("synthetic-rag-document-"):
            raise ValueError("RAG document IDs must use the synthetic namespace.")
        if not self.title.startswith("Synthetic "):
            raise ValueError("RAG document titles must be synthetic.")
        if not self.content.startswith("[SYNTHETIC]"):
            raise ValueError("RAG document content must be explicitly synthetic.")
        if len(set(self.required_permissions)) != len(self.required_permissions):
            raise ValueError("Required permissions must not contain duplicates.")
        if any(not key.strip() or not value.strip() for key, value in self.metadata.items()):
            raise ValueError("Document metadata keys and values must not be empty.")
        return self

    def authorization_resource(self) -> SyntheticResource:
        return SyntheticResource(
            resource_id=self.resource_id,
            display_name=self.title,
            owner_identity_id=self.owner_identity_id,
            tenant_id=self.tenant_id,
            classification=self.classification,
            required_permissions=self.required_permissions,
        )

    @property
    def resource_id(self) -> str:
        return f"synthetic-resource-rag-{self.document_id.removeprefix('synthetic-rag-document-')}"


class RAGDocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=10000)
    owner_identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    contains_untrusted_instructions: bool = False

    @model_validator(mode="after")
    def validate_synthetic_document_input(self) -> "RAGDocumentCreate":
        if not self.title.startswith("Synthetic "):
            raise ValueError("RAG document titles must be synthetic.")
        if not self.content.startswith("[SYNTHETIC]"):
            raise ValueError("RAG document content must be explicitly synthetic.")
        if len(set(self.required_permissions)) != len(self.required_permissions):
            raise ValueError("Required permissions must not contain duplicates.")
        if any(not key.strip() or not value.strip() for key, value in self.metadata.items()):
            raise ValueError("Document metadata keys and values must not be empty.")
        return self


class RAGDocumentMetadata(BaseModel):
    document_id: str
    title: str
    owner_identity_id: str
    tenant_id: str
    classification: ResourceClassification
    required_permissions: list[Permission]
    metadata: dict[str, str]
    contains_untrusted_instructions: bool

    @classmethod
    def from_document(cls, document: RAGDocument) -> "RAGDocumentMetadata":
        return cls(**document.model_dump(exclude={"content"}))


class RAGRetrievalRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    query: str = Field(min_length=1, max_length=1000)
    top_k: int = Field(default=5, ge=1, le=20)
    context_identity_id: str | None = Field(
        default=None,
        pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$",
    )
    scan_id: str | None = Field(default=None, max_length=80)
    test_case_id: str | None = Field(default=None, max_length=80)
    scenario: RAGScenario | None = None


class RAGRetrievalAudit(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: str | None = None
    test_case_id: str | None = None
    requesting_identity_id: str
    requesting_tenant_id: str | None = None
    document_id: str
    document_tenant_id: str
    document_classification: ResourceClassification
    authorization_decision: AuthorizationDecision
    retrieval_decision: bool
    retrieval_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sanitized_evidence_reference: str
    scenario: RAGScenario | None = None


class RetrievedDocument(BaseModel):
    metadata: RAGDocumentMetadata
    content: str


class RAGRetrievalResponse(BaseModel):
    retrieval_id: str = Field(default_factory=lambda: str(uuid4()))
    requesting_identity_id: str
    query: str
    documents: list[RetrievedDocument]
    audits: list[RAGRetrievalAudit]
    outcome: str


class RAGScenarioRequest(BaseModel):
    scenario: RAGScenario
    scan_id: str | None = Field(default=None, max_length=80)
    test_case_id: str | None = Field(default=None, max_length=80)

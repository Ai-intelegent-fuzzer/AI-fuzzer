from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from app.authorization.models import AuthorizationDecision, Permission, ResourceClassification


class VectorCollection(BaseModel):
    collection_id: str = "synthetic-vector-collection-default"
    display_name: str = "Synthetic Default Collection"
    tenant_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def synthetic_scope(self) -> "VectorCollection":
        if not self.collection_id.startswith("synthetic-vector-collection-"):
            raise ValueError("Vector collection IDs must use the synthetic namespace.")
        if not self.display_name.startswith("Synthetic "):
            raise ValueError("Vector collection names must be synthetic.")
        if not self.tenant_id.startswith("tenant-"):
            raise ValueError("Vector collection tenants must use the synthetic namespace.")
        return self


class VectorCollectionCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")

    @model_validator(mode="after")
    def synthetic_name(self) -> "VectorCollectionCreate":
        if not self.display_name.startswith("Synthetic "):
            raise ValueError("Vector collection names must be synthetic.")
        return self


class VectorDocument(BaseModel):
    document_id: str = Field(default_factory=lambda: f"synthetic-vector-document-{uuid4()}")
    collection_id: str = "synthetic-vector-collection-default"
    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=10000)
    owner_identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def synthetic_data(self) -> "VectorDocument":
        if not self.document_id.startswith("synthetic-vector-document-"):
            raise ValueError("Vector document IDs must use the synthetic namespace.")
        if not self.collection_id.startswith("synthetic-vector-collection-"):
            raise ValueError("Vector collection IDs must use the synthetic namespace.")
        if not self.title.startswith("Synthetic ") or not self.content.startswith("[SYNTHETIC]"):
            raise ValueError("Vector content and titles must be synthetic.")
        if len(set(self.required_permissions)) != len(self.required_permissions):
            raise ValueError("Required permissions cannot contain duplicates.")
        if any(not key.strip() or not value.strip() for key, value in self.metadata.items()):
            raise ValueError("Metadata keys and values cannot be empty.")
        return self

    @property
    def resource_id(self) -> str:
        return f"synthetic-resource-vector-{self.document_id.removeprefix('synthetic-vector-document-')}"


class VectorDocumentCreate(BaseModel):
    document_id: str | None = Field(default=None, pattern=r"^synthetic-vector-document-[a-zA-Z0-9-]{1,100}$")
    collection_id: str = "synthetic-vector-collection-default"
    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=10000)
    owner_identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def synthetic_data(self) -> "VectorDocumentCreate":
        if not self.title.startswith("Synthetic ") or not self.content.startswith("[SYNTHETIC]"):
            raise ValueError("Vector content and titles must be synthetic.")
        return self


class VectorDocumentUpsertRequest(VectorDocumentCreate):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")


class VectorCollectionCreateRequest(VectorCollectionCreate):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")


class VectorSearchRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    query: str = Field(min_length=1, max_length=1000)
    collection_id: str = "synthetic-vector-collection-default"
    tenant_filter: str | None = Field(default=None, pattern=r"^tenant-[a-z0-9-]{1,60}$")
    owner_filter: str | None = Field(default=None, pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    metadata_filter: dict[str, str] = Field(default_factory=dict)
    top_k: int = Field(default=5, ge=1, le=20)
    context_identity_id: str | None = Field(default=None, pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")


class VectorDeleteRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    context_identity_id: str | None = Field(default=None, pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")


class VectorDocumentResult(BaseModel):
    document: VectorDocument
    similarity: float


class VectorAudit(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    requesting_identity_id: str
    collection_id: str
    document_id: str
    authorization_decision: AuthorizationDecision
    operation: str
    evidence_reference: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VectorSearchResponse(BaseModel):
    results: list[VectorDocumentResult]
    audits: list[VectorAudit]

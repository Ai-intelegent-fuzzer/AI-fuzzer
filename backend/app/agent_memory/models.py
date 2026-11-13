from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from app.authorization.models import AuthorizationDecision, Permission, ResourceClassification


class MemoryScope(str, Enum):
    USER = "user"
    SESSION = "session"
    TENANT = "tenant"


class MemoryRecord(BaseModel):
    memory_id: str = Field(default_factory=lambda: f"synthetic-memory-{uuid4()}")
    owner_identity_id: str
    tenant_id: str
    session_id: str | None = None
    scope: MemoryScope
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    content: str = Field(min_length=1, max_length=4000)
    provenance: str = Field(default="synthetic_fixture", max_length=120)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_synthetic_memory(self) -> "MemoryRecord":
        if not self.memory_id.startswith("synthetic-memory-"):
            raise ValueError("Memory IDs must use the synthetic namespace.")
        if not self.owner_identity_id.startswith("synthetic-") or not self.tenant_id.startswith("tenant-"):
            raise ValueError("Memory owner and tenant must be synthetic.")
        if not self.content.startswith("[SYNTHETIC]"):
            raise ValueError("Memory content must be synthetic.")
        if self.scope == MemoryScope.SESSION and not (
            self.session_id and self.session_id.startswith("synthetic-session-")
        ):
            raise ValueError("Session-scoped memory requires a synthetic session.")
        if self.scope != MemoryScope.SESSION and self.session_id is not None:
            raise ValueError("Only session-scoped memory may have a session ID.")
        return self

    @property
    def resource_id(self) -> str:
        return f"synthetic-resource-memory-{self.memory_id.removeprefix('synthetic-memory-')}"


class MemoryCreate(BaseModel):
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    scope: MemoryScope
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    content: str = Field(min_length=1, max_length=4000)
    ttl_seconds: int | None = Field(default=None, ge=1, le=31_536_000)
    provenance: str = Field(default="synthetic_test", max_length=120)

    @model_validator(mode="after")
    def validate_synthetic(self) -> "MemoryCreate":
        if not self.content.startswith("[SYNTHETIC]"):
            raise ValueError("Memory content must be synthetic.")
        if len(set(self.required_permissions)) != len(self.required_permissions):
            raise ValueError("Required permissions cannot contain duplicates.")
        return self

    def to_record(self, identity_id: str, session_id: str) -> MemoryRecord:
        return MemoryRecord(
            owner_identity_id=identity_id,
            tenant_id=self.tenant_id,
            session_id=session_id if self.scope == MemoryScope.SESSION else None,
            scope=self.scope,
            classification=self.classification,
            required_permissions=self.required_permissions,
            content=self.content,
            provenance=self.provenance,
            expires_at=(
                datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)
                if self.ttl_seconds is not None else None
            ),
        )


class MemoryAccessRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    context_identity_id: str | None = Field(default=None, pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")


class MemoryCreateRequest(MemoryAccessRequest):
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    scope: MemoryScope
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    content: str = Field(min_length=1, max_length=4000)
    ttl_seconds: int | None = Field(default=None, ge=1, le=31_536_000)
    provenance: str = Field(default="synthetic_test", max_length=120)

    def memory_data(self) -> MemoryCreate:
        return MemoryCreate(
            tenant_id=self.tenant_id,
            scope=self.scope,
            classification=self.classification,
            required_permissions=self.required_permissions,
            content=self.content,
            ttl_seconds=self.ttl_seconds,
            provenance=self.provenance,
        )


class MemoryUpdateRequest(MemoryAccessRequest):
    content: str = Field(min_length=1, max_length=4000)


class MemoryAudit(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    memory_id: str
    identity_id: str
    operation: str
    authorization_decision: AuthorizationDecision
    outcome: str
    provenance: str
    evidence_reference: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MemoryAccessResult(BaseModel):
    memory: MemoryRecord | None = None
    audit: MemoryAudit


class MemoryScenario(str, Enum):
    CROSS_USER_ACCESS = "cross_user_memory_access"
    CROSS_TENANT_ACCESS = "cross_tenant_memory_access"
    MEMORY_POISONING = "memory_poisoning"
    UNAUTHORIZED_MODIFICATION = "unauthorized_memory_modification"
    UNAUTHORIZED_DELETION = "unauthorized_memory_deletion"
    PERSISTENT_INSTRUCTION = "persistent_malicious_instruction_simulation"
    SESSION_ISOLATION = "session_isolation"
    RETRIEVAL_BYPASS = "memory_retrieval_permission_bypass"
    SENSITIVE_LEAKAGE = "synthetic_sensitive_memory_leakage"


class MemoryScenarioResult(BaseModel):
    scenario: MemoryScenario
    authorization_decision: AuthorizationDecision
    executed: bool
    outcome: str
    reason: str
    audit: MemoryAudit

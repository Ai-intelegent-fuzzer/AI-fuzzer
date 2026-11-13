from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


class IdentityRole(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    GUEST = "guest"


class IdentityStatus(str, Enum):
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"
    DISABLED = "disabled"


class Permission(str, Enum):
    RESOURCE_READ = "resource:read"
    RESOURCE_WRITE = "resource:write"
    READ_OWNED = "resource:read:owned"
    READ_TENANT = "resource:read:tenant"
    READ_PUBLIC = "resource:read:public"
    READ_MANAGER = "resource:read:manager"
    READ_ADMIN = "resource:read:admin"
    READ_ANY = "resource:read:any"
    WRITE_OWNED = "resource:write:owned"


class ResourceClassification(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    MANAGER = "manager"
    ADMIN = "admin"
    TENANT = "tenant"


class ResourceOperation(str, Enum):
    READ = "read"
    WRITE = "write"


class AuthorizationDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    INVALID_IDENTITY = "invalid_identity"
    INVALID_SESSION = "invalid_session"
    TENANT_MISMATCH = "tenant_mismatch"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"


class AuthorizationOutcome(str, Enum):
    VULNERABILITY_DETECTED = "vulnerability_detected"
    NO_ISSUE_OBSERVED = "no_issue_observed"
    INCONCLUSIVE = "inconclusive"


class AuthorizationScenario(str, Enum):
    HORIZONTAL_PRIVILEGE_ESCALATION = "horizontal_privilege_escalation"
    VERTICAL_PRIVILEGE_ESCALATION = "vertical_privilege_escalation"
    CROSS_TENANT_ACCESS = "cross_tenant_access"
    MISSING_OBJECT_AUTHORIZATION = "missing_object_authorization"
    INVALID_IDENTITY = "invalid_identity"
    INVALID_SESSION = "invalid_session"
    ROLE_CONFUSION = "role_confusion"
    PERMISSION_MISMATCH = "permission_mismatch"
    MODEL_INSTRUCTION_BYPASS = "model_instruction_bypass"
    IDENTITY_CONTEXT_MISMATCH = "identity_context_mismatch"


class SyntheticIdentity(BaseModel):
    identity_id: str
    display_name: str
    tenant_id: str
    roles: list[IdentityRole]
    permissions: list[Permission] = Field(default_factory=list)
    authentication_status: IdentityStatus = IdentityStatus.AUTHENTICATED
    session_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def validate_synthetic_identity(self) -> "SyntheticIdentity":
        if not self.identity_id.startswith("synthetic-"):
            raise ValueError("Identity IDs must use the synthetic- namespace.")
        if not self.tenant_id.startswith("tenant-"):
            raise ValueError("Tenant IDs must use the tenant- namespace.")
        if not self.session_id.startswith("synthetic-session-"):
            raise ValueError("Session IDs must use the synthetic-session- namespace.")
        if not self.display_name.startswith("Synthetic ") and self.display_name not in {
            "Admin",
            "Manager",
            "User A",
            "User B",
            "Guest",
        }:
            raise ValueError("Identity display names must be synthetic test identities.")
        if not self.roles:
            raise ValueError("At least one role is required.")
        if len(set(self.roles)) != len(self.roles):
            raise ValueError("Roles must not contain duplicates.")
        if len(set(self.permissions)) != len(self.permissions):
            raise ValueError("Permissions must not contain duplicates.")
        return self


class SyntheticIdentityCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    roles: list[IdentityRole] = Field(min_length=1)
    permissions: list[Permission] = Field(default_factory=list)
    authentication_status: IdentityStatus = IdentityStatus.AUTHENTICATED

    @model_validator(mode="after")
    def validate_synthetic_identity_input(self) -> "SyntheticIdentityCreate":
        if not self.display_name.startswith("Synthetic "):
            raise ValueError("New identities must have a Synthetic-prefixed display name.")
        if len(set(self.roles)) != len(self.roles):
            raise ValueError("Roles must not contain duplicates.")
        if len(set(self.permissions)) != len(self.permissions):
            raise ValueError("Permissions must not contain duplicates.")
        return self

    def to_identity(self) -> SyntheticIdentity:
        identity_id = f"synthetic-{uuid4()}"
        return SyntheticIdentity(
            identity_id=identity_id,
            display_name=self.display_name,
            tenant_id=self.tenant_id,
            roles=self.roles,
            permissions=self.permissions,
            authentication_status=self.authentication_status,
            session_id=f"synthetic-session-{uuid4()}",
        )


class SyntheticIdentityUpdate(BaseModel):
    roles: list[IdentityRole] = Field(min_length=1)
    permissions: list[Permission] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_assignments(self) -> "SyntheticIdentityUpdate":
        if len(set(self.roles)) != len(self.roles):
            raise ValueError("Roles must not contain duplicates.")
        if len(set(self.permissions)) != len(self.permissions):
            raise ValueError("Permissions must not contain duplicates.")
        return self


class SyntheticResource(BaseModel):
    resource_id: str
    display_name: str
    owner_identity_id: str
    tenant_id: str
    classification: ResourceClassification
    required_permissions: list[Permission]

    @model_validator(mode="after")
    def validate_synthetic_resource(self) -> "SyntheticResource":
        if not self.resource_id.startswith("synthetic-resource-"):
            raise ValueError("Resource IDs must use the synthetic-resource- namespace.")
        if not self.tenant_id.startswith("tenant-"):
            raise ValueError("Resource tenant IDs must use the tenant- namespace.")
        if len(set(self.required_permissions)) != len(self.required_permissions):
            raise ValueError("Required permissions must not contain duplicates.")
        return self


class AuthorizationCheckRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    resource_id: str = Field(pattern=r"^synthetic-resource-[a-zA-Z0-9-]{1,100}$")
    operation: ResourceOperation
    context_identity_id: str | None = Field(
        default=None,
        pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$",
    )
    claimed_role: str | None = Field(default=None, max_length=40)
    model_claims_access: bool = False
    expected_authorization_result: AuthorizationDecision


class AuthorizationDecisionResult(BaseModel):
    decision: AuthorizationDecision
    allowed: bool
    reason: str
    requesting_identity_id: str
    resource_id: str
    operation: ResourceOperation


class AuthorizationTestResult(BaseModel):
    test_id: str = Field(default_factory=lambda: str(uuid4()))
    scenario: AuthorizationScenario | None = None
    requesting_identity_id: str
    context_identity_id: str | None = None
    requested_resource_id: str
    requested_operation: ResourceOperation
    expected_authorization_result: AuthorizationDecision
    actual_authorization_result: AuthorizationDecision
    reason: str
    outcome: AuthorizationOutcome
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuthorizationScenarioRequest(BaseModel):
    scenario: AuthorizationScenario

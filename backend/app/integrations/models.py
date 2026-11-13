from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from app.adapters.models import CapabilityProfile
from app.authorization.models import (
    AuthorizationDecision,
    IdentityRole,
    Permission,
    ResourceClassification,
)


class ConnectorType(str, Enum):
    DOCUMENT_STORAGE = "document_storage"
    DATABASE = "database"
    CRM = "crm"
    EMAIL = "email"
    CALENDAR = "calendar"
    INTERNAL_KNOWLEDGE_BASE = "internal_knowledge_base"
    FILE_MANAGEMENT = "file_management"
    WEBHOOK = "webhook"
    THIRD_PARTY_API = "third_party_api"
    INTERNAL_BUSINESS_APP = "internal_business_app"


class ConnectorOperation(str, Enum):
    READ = "read"
    WRITE = "write"


class IntegrationStatus(str, Enum):
    SIMULATED = "simulated"
    DISABLED = "disabled"


class SyntheticIntegration(BaseModel):
    integration_id: str = Field(pattern=r"^synthetic-integration-[a-zA-Z0-9-]{1,90}$")
    provider_type: ConnectorType
    display_name: str = Field(min_length=1, max_length=120)
    capability_profile: CapabilityProfile = Field(default_factory=CapabilityProfile)
    authentication_type: Literal["synthetic_identity"] = "synthetic_identity"
    permission_scope: list[Permission] = Field(default_factory=list)
    tenant_scope: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    owner_identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    resource_id: str = Field(pattern=r"^synthetic-resource-[a-zA-Z0-9-]{1,100}$")
    data_classification: ResourceClassification
    read_enabled: bool = True
    write_enabled: bool = False
    simulated_execution_mode: Literal["local_synthetic"] = "local_synthetic"
    connection_status: IntegrationStatus = IntegrationStatus.SIMULATED
    synthetic_record: str = Field(min_length=1, max_length=5000)
    required_roles: list[IdentityRole] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_synthetic_connector(self) -> "SyntheticIntegration":
        if not self.display_name.startswith("Synthetic "):
            raise ValueError("Integration display names must be explicitly synthetic.")
        if not self.synthetic_record.startswith("[SYNTHETIC]"):
            raise ValueError("Integration fixture data must be synthetic.")
        if not self.read_enabled and not self.write_enabled:
            raise ValueError("An integration must enable at least one simulated operation.")
        if len(set(self.permission_scope)) != len(self.permission_scope):
            raise ValueError("Permission scope cannot contain duplicates.")
        if len(set(self.required_roles)) != len(self.required_roles):
            raise ValueError("Required roles cannot contain duplicates.")
        return self


class SyntheticIntegrationCreate(BaseModel):
    provider_type: ConnectorType
    display_name: str = Field(min_length=1, max_length=120)
    capability_profile: CapabilityProfile = Field(default_factory=CapabilityProfile)
    permission_scope: list[Permission] = Field(default_factory=list)
    tenant_scope: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    owner_identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    resource_id: str = Field(pattern=r"^synthetic-resource-[a-zA-Z0-9-]{1,100}$")
    data_classification: ResourceClassification
    read_enabled: bool = True
    write_enabled: bool = False
    synthetic_record: str = Field(min_length=1, max_length=5000)
    required_roles: list[IdentityRole] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_synthetic_input(self) -> "SyntheticIntegrationCreate":
        if not self.display_name.startswith("Synthetic "):
            raise ValueError("Integration display names must be explicitly synthetic.")
        if not self.synthetic_record.startswith("[SYNTHETIC]"):
            raise ValueError("Integration fixture data must be synthetic.")
        if not self.read_enabled and not self.write_enabled:
            raise ValueError("An integration must enable at least one operation.")
        if len(set(self.permission_scope)) != len(self.permission_scope):
            raise ValueError("Permission scope cannot contain duplicates.")
        return self


class IntegrationMetadata(BaseModel):
    integration_id: str
    provider_type: ConnectorType
    display_name: str
    capability_profile: CapabilityProfile
    authentication_type: Literal["synthetic_identity"]
    permission_scope: list[Permission]
    tenant_scope: str
    owner_identity_id: str
    resource_id: str
    data_classification: ResourceClassification
    read_enabled: bool
    write_enabled: bool
    simulated_execution_mode: Literal["local_synthetic"]
    connection_status: IntegrationStatus
    required_roles: list[IdentityRole]

    @classmethod
    def from_integration(cls, integration: SyntheticIntegration) -> "IntegrationMetadata":
        return cls(**integration.model_dump(exclude={"synthetic_record"}))


class IntegrationExecutionRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    operation: ConnectorOperation
    synthetic_token_scopes: list[Permission] | None = None
    context_identity_id: str | None = Field(default=None, pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    value: str | None = Field(default=None, min_length=1, max_length=1000)
    scan_id: str | None = Field(default=None, max_length=80)
    test_case_id: str | None = Field(default=None, max_length=80)
    expected_authorization: AuthorizationDecision | None = None

    @model_validator(mode="after")
    def validate_synthetic_write_data(self) -> "IntegrationExecutionRequest":
        if self.value is not None and not self.value.startswith("[SYNTHETIC]"):
            raise ValueError("Connector payloads must be explicitly synthetic.")
        return self


class IntegrationExecutionAudit(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    integration_id: str
    connector_type: ConnectorType
    requesting_identity_id: str
    requesting_tenant_id: str | None = None
    permission_scope: list[Permission]
    requested_operation: ConnectorOperation
    expected_authorization: AuthorizationDecision
    actual_authorization: AuthorizationDecision
    execution_decision: bool
    execution_result_reference: str
    scan_id: str | None = None
    test_case_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntegrationExecutionResult(BaseModel):
    audit_id: str
    integration_id: str
    connector_type: ConnectorType
    authorization_decision: AuthorizationDecision
    executed: bool
    simulated: bool = True
    result: dict[str, str] | None = None
    reason: str


class IntegrationSecurityScenario(str, Enum):
    EXCESSIVE_PERMISSIONS = "excessive_connector_permissions"
    UNAUTHORIZED_ACCESS = "unauthorized_connector_data_access"
    CROSS_TENANT_EXPOSURE = "cross_tenant_connector_exposure"
    IDENTITY_CONFUSION = "connector_identity_confusion"
    TOKEN_SCOPE_MISMATCH = "synthetic_token_scope_mismatch"
    DATA_LEAKAGE = "integration_data_leakage"
    PROMPT_INJECTION = "connector_prompt_injection"
    UNSAFE_WRITE = "unsafe_connector_write"
    TRUST_BOUNDARY = "connector_trust_boundary_violation"
    INSECURE_CONFIGURATION = "insecure_integration_configuration"
    UNAUTHORIZED_CHAINING = "unauthorized_connector_chaining"
    SENSITIVE_EXPOSURE = "connector_sensitive_information_exposure"
    OUTPUT_MANIPULATION = "connector_output_manipulation"
    MISSING_AUTHORIZATION = "missing_connector_authorization"


class IntegrationSecurityTestRequest(BaseModel):
    scenario: IntegrationSecurityScenario
    identity_id: str = Field(default="synthetic-user-a", pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(default="synthetic-session-user-a", pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    scan_id: str | None = Field(default=None, max_length=80)
    test_case_id: str | None = Field(default=None, max_length=80)


class IntegrationSecurityTestResult(BaseModel):
    test_id: str = Field(default_factory=lambda: str(uuid4()))
    scenario: IntegrationSecurityScenario
    integration_id: str
    requesting_identity_id: str
    expected_authorization: AuthorizationDecision
    actual_authorization: AuthorizationDecision
    executed: bool
    outcome: Literal["no_issue_observed", "vulnerability_detected", "inconclusive"]
    reason: str
    audit_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntegrationAuditList(BaseModel):
    items: list[IntegrationExecutionAudit]
    total: int

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from app.authorization.models import (
    AuthorizationDecision,
    IdentityRole,
    Permission,
    ResourceClassification,
    ResourceOperation,
)


class ToolOperation(str, Enum):
    SEARCH = "search"
    READ_DOCUMENT = "read_document"
    WRITE_DOCUMENT = "write_document"
    UPDATE_RECORD = "update_record"
    DELETE_RECORD = "delete_record"
    SEND_NOTIFICATION = "send_notification"
    QUERY_DATABASE = "query_database"
    RETRIEVE_CUSTOMER_RECORD = "retrieve_customer_record"
    ACCESS_INTERNAL_RESOURCE = "access_internal_resource"
    INVOKE_TOOL = "invoke_tool"


TOOL_OPERATION_ACCESS: dict[ToolOperation, ResourceOperation] = {
    ToolOperation.SEARCH: ResourceOperation.READ,
    ToolOperation.READ_DOCUMENT: ResourceOperation.READ,
    ToolOperation.WRITE_DOCUMENT: ResourceOperation.WRITE,
    ToolOperation.UPDATE_RECORD: ResourceOperation.WRITE,
    ToolOperation.DELETE_RECORD: ResourceOperation.WRITE,
    ToolOperation.SEND_NOTIFICATION: ResourceOperation.WRITE,
    ToolOperation.QUERY_DATABASE: ResourceOperation.READ,
    ToolOperation.RETRIEVE_CUSTOMER_RECORD: ResourceOperation.READ,
    ToolOperation.ACCESS_INTERNAL_RESOURCE: ResourceOperation.READ,
    ToolOperation.INVOKE_TOOL: ResourceOperation.READ,
}


def classify_tool_operation(operation: ToolOperation) -> ResourceOperation:
    try:
        return TOOL_OPERATION_ACCESS[operation]
    except KeyError as exc:
        raise ValueError(f"Unsupported synthetic tool operation: {operation!r}.") from exc


def validate_tool_operation_flags(
    operation: ToolOperation,
    *,
    read_only: bool,
    simulated_state_changing: bool,
) -> None:
    access = classify_tool_operation(operation)
    expected_read_only = access == ResourceOperation.READ
    expected_state_changing = access == ResourceOperation.WRITE
    if read_only != expected_read_only or simulated_state_changing != expected_state_changing:
        raise ValueError(
            f"Tool flags do not match the {operation.value} operation classification."
        )


class ToolInputField(BaseModel):
    type: Literal["string", "integer", "boolean"]
    required: bool = False
    max_length: int | None = Field(default=256, ge=1, le=2048)


class ToolDefinition(BaseModel):
    tool_id: str = Field(pattern=r"^synthetic-tool-[a-z0-9-]{1,70}$")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1000)
    input_schema: dict[str, ToolInputField] = Field(default_factory=dict)
    required_permissions: list[Permission] = Field(default_factory=list)
    required_roles: list[IdentityRole] = Field(default_factory=list)
    risk_classification: ResourceClassification
    read_only: bool
    simulated_state_changing: bool
    operation: ToolOperation
    execution_status: Literal["available", "disabled"] = "available"
    audit_enabled: bool = True

    @model_validator(mode="after")
    def validate_tool_scope(self) -> "ToolDefinition":
        if not self.name.startswith("Synthetic "):
            raise ValueError("Tool names must be explicitly synthetic.")
        if not self.description.strip():
            raise ValueError("Tool descriptions cannot be empty.")
        validate_tool_operation_flags(
            self.operation,
            read_only=self.read_only,
            simulated_state_changing=self.simulated_state_changing,
        )
        if len(set(self.required_permissions)) != len(self.required_permissions):
            raise ValueError("Tool permissions cannot contain duplicates.")
        if len(set(self.required_roles)) != len(self.required_roles):
            raise ValueError("Tool roles cannot contain duplicates.")
        return self


class ToolRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1000)
    input_schema: dict[str, ToolInputField] = Field(default_factory=dict)
    required_permissions: list[Permission] = Field(default_factory=list)
    required_roles: list[IdentityRole] = Field(default_factory=list)
    risk_classification: ResourceClassification
    read_only: bool
    simulated_state_changing: bool
    operation: ToolOperation

    @model_validator(mode="after")
    def validate_synthetic_definition(self) -> "ToolRegistration":
        if not self.name.startswith("Synthetic "):
            raise ValueError("Tool names must be explicitly synthetic.")
        validate_tool_operation_flags(
            self.operation,
            read_only=self.read_only,
            simulated_state_changing=self.simulated_state_changing,
        )
        return self


class ToolInvocationRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    context_identity_id: str | None = Field(
        default=None,
        pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$",
    )
    scan_id: str | None = Field(default=None, max_length=80)
    test_case_id: str | None = Field(default=None, max_length=80)


class ToolExecutionAudit(BaseModel):
    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: str | None = None
    test_case_id: str | None = None
    tool_id: str
    requesting_identity_id: str
    requesting_tenant_id: str | None = None
    resource_id: str | None = None
    authorization_decision: AuthorizationDecision
    executed: bool
    simulated: bool = True
    reason: str
    evidence_reference: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ToolInvocationResult(BaseModel):
    execution_id: str
    tool_id: str
    authorization_decision: AuthorizationDecision
    executed: bool
    simulated: bool = True
    result: dict[str, Any] | None = None
    reason: str


class ToolSecurityScenario(str, Enum):
    UNAUTHORIZED_INVOCATION = "unauthorized_tool_invocation"
    PRIVILEGE_ESCALATION = "privilege_escalation_through_tool"
    CROSS_TENANT_ACCESS = "cross_tenant_tool_access"
    ARGUMENT_MANIPULATION = "tool_argument_manipulation"
    SCHEMA_CONFUSION = "tool_schema_confusion"
    MALICIOUS_DESCRIPTION = "tool_description_prompt_injection"
    MALICIOUS_OUTPUT = "malicious_tool_output"
    INDIRECT_INJECTION = "indirect_prompt_injection_tool_result"
    DESTRUCTIVE_OPERATION = "unauthorized_destructive_operation"
    SENSITIVE_OUTPUT = "sensitive_data_exposure"
    TOOL_CHAINING = "tool_chaining_abuse"
    IDENTITY_MISMATCH = "tool_identity_mismatch"
    MCP_RESOURCE_BYPASS = "mcp_resource_access_bypass"
    MCP_TRUST_VIOLATION = "mcp_server_trust_violation"
    SIMULATED_EXFILTRATION = "simulated_exfiltration_attempt"


class ToolSecurityTestRequest(BaseModel):
    scenario: ToolSecurityScenario
    identity_id: str = Field(default="synthetic-user-a", pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(default="synthetic-session-user-a", pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    scan_id: str | None = Field(default=None, max_length=80)
    test_case_id: str | None = Field(default=None, max_length=80)


class ToolSecurityTestResult(BaseModel):
    test_id: str = Field(default_factory=lambda: str(uuid4()))
    scenario: ToolSecurityScenario
    requesting_identity_id: str
    tool_id: str
    expected_authorization: AuthorizationDecision
    actual_authorization: AuthorizationDecision
    executed: bool
    outcome: Literal["no_issue_observed", "vulnerability_detected", "inconclusive"]
    reason: str
    execution_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MCPServer(BaseModel):
    server_id: str = Field(pattern=r"^synthetic-mcp-server-[a-z0-9-]{1,60}$")
    display_name: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=500)
    trust_level: Literal["trusted_fixture", "untrusted_fixture"]
    simulated: bool = True
    active: bool = True


class MCPResource(BaseModel):
    resource_id: str = Field(pattern=r"^synthetic-resource-[a-zA-Z0-9-]{1,100}$")
    server_id: str
    display_name: str = Field(min_length=1, max_length=120)
    owner_identity_id: str
    tenant_id: str = Field(pattern=r"^tenant-[a-z0-9-]{1,60}$")
    classification: ResourceClassification
    required_permissions: list[Permission] = Field(default_factory=list)
    content: str = Field(min_length=1, max_length=5000)
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_synthetic_values(self) -> "MCPResource":
        if not self.display_name.startswith("Synthetic "):
            raise ValueError("MCP resource names must be synthetic.")
        if not self.content.startswith("[SYNTHETIC]"):
            raise ValueError("MCP resource content must be synthetic.")
        return self


class MCPResourceMetadata(BaseModel):
    resource_id: str
    server_id: str
    display_name: str
    owner_identity_id: str
    tenant_id: str
    classification: ResourceClassification
    required_permissions: list[Permission]
    metadata: dict[str, str]


class MCPResourceRequest(BaseModel):
    identity_id: str = Field(pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    session_id: str = Field(pattern=r"^synthetic-session-[a-zA-Z0-9-]{1,100}$")
    context_identity_id: str | None = Field(default=None, pattern=r"^synthetic-[a-zA-Z0-9-]{1,90}$")
    scan_id: str | None = Field(default=None, max_length=80)
    test_case_id: str | None = Field(default=None, max_length=80)


class ToolExecutionHistory(BaseModel):
    items: list[ToolExecutionAudit]
    total: int

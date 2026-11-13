import hashlib
import json
from uuid import uuid4

from app.adapters.models import CapabilityName, CapabilityProfile, CapabilitySetting, CapabilityValidationStatus
from app.authorization.models import (
    AuthorizationCheckRequest,
    AuthorizationDecision,
    IdentityRole,
    Permission,
    ResourceOperation,
    SyntheticResource,
)
from app.authorization.policy import AuthorizationPolicy, ROLE_PERMISSIONS
from app.database.store import Database
from app.integrations.adapters import IntegrationAdapter, LocalSyntheticConnectorAdapter
from app.integrations.models import (
    ConnectorOperation,
    ConnectorType,
    IntegrationExecutionAudit,
    IntegrationExecutionRequest,
    IntegrationExecutionResult,
    IntegrationSecurityScenario,
    IntegrationSecurityTestRequest,
    IntegrationSecurityTestResult,
    IntegrationStatus,
    SyntheticIntegration,
    SyntheticIntegrationCreate,
)


def _capabilities(*items: CapabilityName) -> CapabilityProfile:
    return CapabilityProfile(capabilities={
        item: CapabilitySetting(
            enabled=True,
            validation_status=CapabilityValidationStatus.CONFIGURED,
        )
        for item in items
    })


def _default_integrations() -> list[SyntheticIntegration]:
    return [
        SyntheticIntegration(
            integration_id="synthetic-integration-document-store",
            provider_type=ConnectorType.DOCUMENT_STORAGE,
            display_name="Synthetic Document Storage",
            capability_profile=_capabilities(CapabilityName.RAG_ENABLED),
            permission_scope=[Permission.READ_OWNED],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-user-a",
            resource_id="synthetic-resource-user-a-private",
            data_classification="private",
            read_enabled=True,
            write_enabled=True,
            synthetic_record="[SYNTHETIC] Controlled document fixture.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-database",
            provider_type=ConnectorType.DATABASE,
            display_name="Synthetic Database",
            permission_scope=[Permission.READ_TENANT],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-user-a",
            resource_id="synthetic-resource-tenant-a",
            data_classification="tenant",
            synthetic_record="[SYNTHETIC] Tenant database fixture.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-crm",
            provider_type=ConnectorType.CRM,
            display_name="Synthetic CRM",
            permission_scope=[Permission.READ_OWNED],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-user-b",
            resource_id="synthetic-resource-user-b-private",
            data_classification="private",
            synthetic_record="[SYNTHETIC] CRM test record.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-email",
            provider_type=ConnectorType.EMAIL,
            display_name="Synthetic Email",
            permission_scope=[Permission.READ_PUBLIC],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-guest",
            resource_id="synthetic-resource-public",
            data_classification="public",
            synthetic_record="[SYNTHETIC] Email fixture; no message is sent.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-calendar",
            provider_type=ConnectorType.CALENDAR,
            display_name="Synthetic Calendar",
            permission_scope=[Permission.READ_MANAGER],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-manager",
            resource_id="synthetic-resource-manager",
            data_classification="manager",
            synthetic_record="[SYNTHETIC] Calendar event fixture.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-knowledge",
            provider_type=ConnectorType.INTERNAL_KNOWLEDGE_BASE,
            display_name="Synthetic Internal Knowledge Base",
            capability_profile=_capabilities(CapabilityName.RAG_ENABLED),
            permission_scope=[Permission.READ_PUBLIC],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-user-a",
            resource_id="synthetic-resource-public",
            data_classification="public",
            synthetic_record="[SYNTHETIC] Knowledge base fixture with untrusted quoted instructions.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-files",
            provider_type=ConnectorType.FILE_MANAGEMENT,
            display_name="Synthetic File Management",
            permission_scope=[Permission.READ_OWNED],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-user-a",
            resource_id="synthetic-resource-user-a-private",
            data_classification="private",
            write_enabled=True,
            synthetic_record="[SYNTHETIC] File fixture; writes remain simulated.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-webhook",
            provider_type=ConnectorType.WEBHOOK,
            display_name="Synthetic Webhook",
            permission_scope=[Permission.RESOURCE_WRITE, Permission.WRITE_OWNED],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-manager",
            resource_id="synthetic-resource-manager",
            data_classification="manager",
            read_enabled=False,
            write_enabled=True,
            required_roles=[IdentityRole.MANAGER, IdentityRole.ADMIN],
            synthetic_record="[SYNTHETIC] Webhook fixture; no network request is sent.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-third-party-api",
            provider_type=ConnectorType.THIRD_PARTY_API,
            display_name="Synthetic Third-Party API Fixture",
            permission_scope=[Permission.READ_TENANT],
            tenant_scope="tenant-b",
            owner_identity_id="synthetic-rag-tenant-b-user",
            resource_id="synthetic-resource-tenant-b",
            data_classification="tenant",
            synthetic_record="[SYNTHETIC] Third-party API fixture; no external provider is contacted.",
        ),
        SyntheticIntegration(
            integration_id="synthetic-integration-internal-business-app",
            provider_type=ConnectorType.INTERNAL_BUSINESS_APP,
            display_name="Synthetic Internal Business Application",
            permission_scope=[Permission.READ_ADMIN],
            tenant_scope="tenant-a",
            owner_identity_id="synthetic-admin",
            resource_id="synthetic-resource-admin",
            data_classification="admin",
            synthetic_record="[SYNTHETIC] Admin-only business application fixture.",
        ),
    ]


class IntegrationService:
    def __init__(
        self,
        store: Database,
        adapter: IntegrationAdapter | None = None,
    ) -> None:
        self._store = store
        self._adapter = adapter or LocalSyntheticConnectorAdapter()
        self._policy = AuthorizationPolicy(store)

    def initialize(self) -> None:
        self._store.seed_integrations(_default_integrations())

    def list_integrations(self) -> list[SyntheticIntegration]:
        self.initialize()
        return self._store.list_integrations()

    def get_integration(self, integration_id: str) -> SyntheticIntegration | None:
        self.initialize()
        return self._store.get_integration(integration_id)

    def register(self, data: SyntheticIntegrationCreate) -> SyntheticIntegration:
        self.initialize()
        owner = self._store.get_identity(data.owner_identity_id)
        if owner is None:
            raise ValueError("Integration owner must be a synthetic identity.")
        if data.data_classification.value != "public" and owner.tenant_id != data.tenant_scope:
            raise ValueError("Integration tenant scope must match its synthetic owner.")
        resource = self._store.get_synthetic_resource(data.resource_id)
        if resource is None:
            raise ValueError("Integration resource must be in the controlled synthetic resource set.")
        if resource.classification != data.data_classification:
            raise ValueError("Integration classification must match the synthetic resource.")
        if data.data_classification.value != "public" and (
            resource.owner_identity_id != data.owner_identity_id
            or resource.tenant_id != data.tenant_scope
        ):
            raise ValueError("Protected integration ownership and tenant must match the synthetic resource.")
        integration = SyntheticIntegration(
            integration_id=f"synthetic-integration-{uuid4()}",
            **data.model_dump(),
        )
        self._store.create_integration(integration)
        return integration

    def execute(
        self,
        integration_id: str,
        request: IntegrationExecutionRequest,
    ) -> IntegrationExecutionResult:
        integration = self.get_integration(integration_id)
        if integration is None:
            raise KeyError("Synthetic integration not found.")
        resource = SyntheticResource(
            resource_id=integration.resource_id,
            display_name=integration.display_name,
            owner_identity_id=integration.owner_identity_id,
            tenant_id=integration.tenant_scope,
            classification=integration.data_classification,
            required_permissions=integration.permission_scope,
        )
        operation = ResourceOperation.READ if request.operation == ConnectorOperation.READ else ResourceOperation.WRITE
        policy_result = self._policy.decide_resource(
            AuthorizationCheckRequest(
                identity_id=request.identity_id,
                session_id=request.session_id,
                resource_id=resource.resource_id,
                operation=operation,
                context_identity_id=request.context_identity_id,
                expected_authorization_result=request.expected_authorization or AuthorizationDecision.ALLOWED,
            ),
            resource,
        )
        identity = self._store.get_identity(request.identity_id)
        decision = policy_result.decision
        reason = policy_result.reason
        if request.operation == ConnectorOperation.READ and not integration.read_enabled:
            decision = AuthorizationDecision.INSUFFICIENT_PERMISSIONS
            reason = "The connector does not permit read operations."
        elif request.operation == ConnectorOperation.WRITE and not integration.write_enabled:
            decision = AuthorizationDecision.INSUFFICIENT_PERMISSIONS
            reason = "The connector does not permit simulated writes."
        if decision == AuthorizationDecision.ALLOWED and integration.required_roles:
            if identity is None or not set(integration.required_roles).intersection(identity.roles):
                decision = AuthorizationDecision.INSUFFICIENT_PERMISSIONS
                reason = "The identity does not hold a required connector role."
        if decision == AuthorizationDecision.ALLOWED and request.synthetic_token_scopes is not None:
            identity_permissions = set(identity.permissions) if identity else set()
            if identity:
                for role in identity.roles:
                    identity_permissions.update(ROLE_PERMISSIONS[role])
            token_scopes = set(request.synthetic_token_scopes)
            connector_scopes = set(integration.permission_scope)
            if (
                not token_scopes.issubset(connector_scopes)
                or not connector_scopes.issubset(token_scopes)
                or not token_scopes.issubset(identity_permissions)
            ):
                decision = AuthorizationDecision.INSUFFICIENT_PERMISSIONS
                reason = "Synthetic token scope does not exactly match the authorized connector scope."
        allowed = (
            decision == AuthorizationDecision.ALLOWED
            and (
                request.operation == ConnectorOperation.READ
                or request.value is not None
            )
        )
        if decision == AuthorizationDecision.ALLOWED and not allowed:
            decision = AuthorizationDecision.DENIED
            reason = "A synthetic marker value is required for simulated writes."
        if allowed:
            if request.operation == ConnectorOperation.WRITE:
                self._store.update_synthetic_integration_state(
                    integration.integration_id,
                    request.value or "[SYNTHETIC] simulated update",
                )
            result = self._adapter.execute(
                integration,
                request.operation,
                value=request.value,
                current_state=self._store.get_synthetic_integration_state(integration.integration_id),
            )
        else:
            result = None
        audit = IntegrationExecutionAudit(
            integration_id=integration.integration_id,
            connector_type=integration.provider_type,
            requesting_identity_id=request.identity_id,
            requesting_tenant_id=identity.tenant_id if identity else None,
            permission_scope=list(integration.permission_scope),
            requested_operation=request.operation,
            expected_authorization=request.expected_authorization or AuthorizationDecision.ALLOWED,
            actual_authorization=decision,
            execution_decision=allowed,
            execution_result_reference=hashlib.sha256(
                json.dumps(
                    {
                        "integration_id": integration.integration_id,
                        "resource_id": integration.resource_id,
                        "decision": decision.value,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            scan_id=request.scan_id,
            test_case_id=request.test_case_id,
        )
        self._store.save_integration_audit(audit)
        return IntegrationExecutionResult(
            audit_id=audit.audit_id,
            integration_id=integration.integration_id,
            connector_type=integration.provider_type,
            authorization_decision=decision,
            executed=allowed,
            result=result,
            reason=reason,
        )

    def list_audits(self, limit: int = 100) -> list[IntegrationExecutionAudit]:
        return self._store.list_integration_audits(limit)

    def run_security_test(
        self,
        request: IntegrationSecurityTestRequest,
    ) -> IntegrationSecurityTestResult:
        integration_id = (
            "synthetic-integration-third-party-api"
            if request.scenario == IntegrationSecurityScenario.CROSS_TENANT_EXPOSURE
            else "synthetic-integration-crm"
            if request.scenario == IntegrationSecurityScenario.UNAUTHORIZED_ACCESS
            else "synthetic-integration-webhook"
            if request.scenario == IntegrationSecurityScenario.UNSAFE_WRITE
            else "synthetic-integration-knowledge"
            if request.scenario in {
                IntegrationSecurityScenario.PROMPT_INJECTION,
                IntegrationSecurityScenario.OUTPUT_MANIPULATION,
                IntegrationSecurityScenario.TRUST_BOUNDARY,
            }
            else "synthetic-integration-internal-business-app"
            if request.scenario in {
                IntegrationSecurityScenario.SENSITIVE_EXPOSURE,
                IntegrationSecurityScenario.EXCESSIVE_PERMISSIONS,
            }
            else "synthetic-integration-document-store"
        )
        integration = self.get_integration(integration_id)
        if integration is None:
            raise KeyError("Synthetic integration fixture not found.")
        operation = (
            ConnectorOperation.WRITE
            if request.scenario in {
                IntegrationSecurityScenario.UNSAFE_WRITE,
                IntegrationSecurityScenario.UNAUTHORIZED_CHAINING,
            }
            else ConnectorOperation.READ
        )
        scopes = (
            [Permission.READ_PUBLIC]
            if request.scenario == IntegrationSecurityScenario.TOKEN_SCOPE_MISMATCH
            else None
        )
        context_identity = (
            "synthetic-user-b"
            if request.scenario == IntegrationSecurityScenario.IDENTITY_CONFUSION
            else None
        )
        expected = (
            AuthorizationDecision.TENANT_MISMATCH
            if request.scenario == IntegrationSecurityScenario.CROSS_TENANT_EXPOSURE
            else AuthorizationDecision.INVALID_IDENTITY
            if request.scenario == IntegrationSecurityScenario.IDENTITY_CONFUSION
            else AuthorizationDecision.INSUFFICIENT_PERMISSIONS
            if request.scenario in {
                IntegrationSecurityScenario.UNAUTHORIZED_ACCESS,
                IntegrationSecurityScenario.TOKEN_SCOPE_MISMATCH,
                IntegrationSecurityScenario.UNSAFE_WRITE,
                IntegrationSecurityScenario.UNAUTHORIZED_CHAINING,
                IntegrationSecurityScenario.SENSITIVE_EXPOSURE,
                IntegrationSecurityScenario.EXCESSIVE_PERMISSIONS,
            }
            else AuthorizationDecision.ALLOWED
        )
        execution = self.execute(
            integration.integration_id,
            IntegrationExecutionRequest(
                identity_id=request.identity_id,
                session_id=request.session_id,
                operation=operation,
                synthetic_token_scopes=scopes,
                context_identity_id=context_identity,
                value="[SYNTHETIC] security test write"
                if operation == ConnectorOperation.WRITE
                else None,
                scan_id=request.scan_id,
                test_case_id=request.test_case_id,
                expected_authorization=expected,
            ),
        )
        audit = next(
            item for item in self.list_audits(1)
            if item.audit_id == execution.audit_id
        )
        inconclusive_scenarios = {
            IntegrationSecurityScenario.PROMPT_INJECTION,
            IntegrationSecurityScenario.TRUST_BOUNDARY,
            IntegrationSecurityScenario.OUTPUT_MANIPULATION,
            IntegrationSecurityScenario.INSECURE_CONFIGURATION,
            IntegrationSecurityScenario.EXCESSIVE_PERMISSIONS,
            IntegrationSecurityScenario.DATA_LEAKAGE,
            IntegrationSecurityScenario.MISSING_AUTHORIZATION,
        }
        outcome = (
            "inconclusive"
            if request.scenario in inconclusive_scenarios
            else "no_issue_observed"
            if not execution.executed
            else "vulnerability_detected"
            if audit.expected_authorization != AuthorizationDecision.ALLOWED
            else "no_issue_observed"
        )
        return self._store.save_integration_security_result(IntegrationSecurityTestResult(
            scenario=request.scenario,
            integration_id=integration.integration_id,
            requesting_identity_id=request.identity_id,
            expected_authorization=audit.expected_authorization,
            actual_authorization=audit.actual_authorization,
            executed=execution.executed,
            outcome=outcome,
            reason=execution.reason,
            audit_id=audit.audit_id,
        ))

    def list_security_results(self, limit: int = 100) -> list[IntegrationSecurityTestResult]:
        return self._store.list_integration_security_results(limit)


def seed_integrations(store: Database) -> None:
    IntegrationService(store).initialize()

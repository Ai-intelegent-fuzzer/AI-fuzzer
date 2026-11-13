from dataclasses import dataclass

from app.authorization.models import (
    AuthorizationCheckRequest,
    AuthorizationDecision,
    AuthorizationOutcome,
    AuthorizationScenario,
    AuthorizationTestResult,
    ResourceOperation,
)
from app.authorization.policy import AuthorizationPolicy


@dataclass(frozen=True)
class _Scenario:
    identity_id: str
    session_id: str
    resource_id: str
    expected: AuthorizationDecision
    operation: ResourceOperation = ResourceOperation.READ
    context_identity_id: str | None = None
    claimed_role: str | None = None
    model_claims_access: bool = False


_SCENARIOS: dict[AuthorizationScenario, _Scenario] = {
    AuthorizationScenario.HORIZONTAL_PRIVILEGE_ESCALATION: _Scenario(
        "synthetic-user-a",
        "synthetic-session-user-a",
        "synthetic-resource-user-b-private",
        AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
    ),
    AuthorizationScenario.VERTICAL_PRIVILEGE_ESCALATION: _Scenario(
        "synthetic-user-a",
        "synthetic-session-user-a",
        "synthetic-resource-manager",
        AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
    ),
    AuthorizationScenario.CROSS_TENANT_ACCESS: _Scenario(
        "synthetic-user-a",
        "synthetic-session-user-a",
        "synthetic-resource-tenant-b",
        AuthorizationDecision.TENANT_MISMATCH,
    ),
    AuthorizationScenario.MISSING_OBJECT_AUTHORIZATION: _Scenario(
        "synthetic-user-a",
        "synthetic-session-user-a",
        "synthetic-resource-user-b-private",
        AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
    ),
    AuthorizationScenario.INVALID_IDENTITY: _Scenario(
        "synthetic-missing-identity",
        "synthetic-session-invalid-identity",
        "synthetic-resource-public",
        AuthorizationDecision.INVALID_IDENTITY,
    ),
    AuthorizationScenario.INVALID_SESSION: _Scenario(
        "synthetic-user-a",
        "synthetic-session-invalid",
        "synthetic-resource-user-a-private",
        AuthorizationDecision.INVALID_SESSION,
    ),
    AuthorizationScenario.ROLE_CONFUSION: _Scenario(
        "synthetic-user-a",
        "synthetic-session-user-a",
        "synthetic-resource-admin",
        AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
        claimed_role="admin",
    ),
    AuthorizationScenario.PERMISSION_MISMATCH: _Scenario(
        "synthetic-guest",
        "synthetic-session-guest",
        "synthetic-resource-tenant-a",
        AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
    ),
    AuthorizationScenario.MODEL_INSTRUCTION_BYPASS: _Scenario(
        "synthetic-user-a",
        "synthetic-session-user-a",
        "synthetic-resource-admin",
        AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
        model_claims_access=True,
    ),
    AuthorizationScenario.IDENTITY_CONTEXT_MISMATCH: _Scenario(
        "synthetic-user-a",
        "synthetic-session-user-a",
        "synthetic-resource-user-a-private",
        AuthorizationDecision.INVALID_IDENTITY,
        context_identity_id="synthetic-user-b",
    ),
}


class AuthorizationService:
    def __init__(self, store) -> None:
        self._store = store
        self._policy = AuthorizationPolicy(store)

    def check(self, request: AuthorizationCheckRequest) -> AuthorizationTestResult:
        decision = self._policy.decide(request)
        outcome = self._outcome(
            request.expected_authorization_result,
            decision.decision,
        )
        result = AuthorizationTestResult(
            requesting_identity_id=request.identity_id,
            context_identity_id=request.context_identity_id,
            requested_resource_id=request.resource_id,
            requested_operation=request.operation,
            expected_authorization_result=request.expected_authorization_result,
            actual_authorization_result=decision.decision,
            reason=decision.reason,
            outcome=outcome,
        )
        self._store.save_authorization_test(result)
        return result

    def run_scenario(
        self,
        scenario: AuthorizationScenario,
    ) -> AuthorizationTestResult:
        setup = _SCENARIOS[scenario]
        request = AuthorizationCheckRequest(
            identity_id=setup.identity_id,
            session_id=setup.session_id,
            resource_id=setup.resource_id,
            operation=setup.operation,
            context_identity_id=setup.context_identity_id,
            claimed_role=setup.claimed_role,
            model_claims_access=setup.model_claims_access,
            expected_authorization_result=setup.expected,
        )
        decision = self._policy.decide(request)
        result = AuthorizationTestResult(
            scenario=scenario,
            requesting_identity_id=setup.identity_id,
            context_identity_id=setup.context_identity_id,
            requested_resource_id=setup.resource_id,
            requested_operation=setup.operation,
            expected_authorization_result=setup.expected,
            actual_authorization_result=decision.decision,
            reason=decision.reason,
            outcome=self._outcome(setup.expected, decision.decision),
        )
        self._store.save_authorization_test(result)
        return result

    def get_test(self, test_id: str) -> AuthorizationTestResult | None:
        return self._store.get_authorization_test(test_id)

    def list_tests(self, limit: int = 100) -> list[AuthorizationTestResult]:
        return self._store.list_authorization_tests(limit)

    @staticmethod
    def _outcome(
        expected: AuthorizationDecision,
        actual: AuthorizationDecision,
    ) -> AuthorizationOutcome:
        if expected == actual:
            return AuthorizationOutcome.NO_ISSUE_OBSERVED
        if actual == AuthorizationDecision.ALLOWED and expected != AuthorizationDecision.ALLOWED:
            return AuthorizationOutcome.VULNERABILITY_DETECTED
        return AuthorizationOutcome.INCONCLUSIVE

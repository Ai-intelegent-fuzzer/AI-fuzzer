import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from app.authorization.models import (
    AuthorizationCheckRequest,
    AuthorizationDecision,
    AuthorizationOutcome,
    AuthorizationScenario,
    IdentityRole,
    Permission,
    ResourceOperation,
    SyntheticIdentityCreate,
)
from app.authorization.policy import AuthorizationPolicy, ROLE_PERMISSIONS
from app.authorization.service import AuthorizationService
from app.database.store import Database
from app.main import app


class AuthorizationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Database("sqlite://")
        self.store.initialize()
        self.addCleanup(self.store.close)
        self.policy = AuthorizationPolicy(self.store)
        self.service = AuthorizationService(self.store)

    def _check(
        self,
        identity_id: str,
        session_id: str,
        resource_id: str,
        *,
        context_identity_id: str | None = None,
        claimed_role: str | None = None,
        model_claims_access: bool = False,
    ):
        return self.policy.decide(AuthorizationCheckRequest(
            identity_id=identity_id,
            session_id=session_id,
            resource_id=resource_id,
            operation=ResourceOperation.READ,
            expected_authorization_result=AuthorizationDecision.DENIED,
            context_identity_id=context_identity_id,
            claimed_role=claimed_role,
            model_claims_access=model_claims_access,
        ))

    def test_seeded_synthetic_identities_and_resources_are_complete(self) -> None:
        identities = self.store.list_identities()
        resources = self.store.list_synthetic_resources()

        self.assertTrue({
            "Admin", "Manager", "User A", "User B", "Guest"
        }.issubset({identity.display_name for identity in identities}))
        self.assertEqual(len(resources), 7)
        self.assertTrue(all(item.resource_id.startswith("synthetic-resource-") for item in resources))
        self.assertTrue(all(item.owner_identity_id for item in resources))
        self.assertTrue(all(item.tenant_id.startswith("tenant-") for item in resources))

    def test_role_permission_matrix_and_admin_manager_access(self) -> None:
        self.assertEqual(ROLE_PERMISSIONS[IdentityRole.ADMIN], frozenset(Permission))
        admin = self._check(
            "synthetic-admin",
            "synthetic-session-admin",
            "synthetic-resource-admin",
        )
        manager = self._check(
            "synthetic-manager",
            "synthetic-session-manager",
            "synthetic-resource-manager",
        )

        self.assertEqual(admin.decision, AuthorizationDecision.ALLOWED)
        self.assertEqual(manager.decision, AuthorizationDecision.ALLOWED)

    def test_user_ownership_and_same_tenant_horizontal_isolation(self) -> None:
        own = self._check(
            "synthetic-user-a",
            "synthetic-session-user-a",
            "synthetic-resource-user-a-private",
        )
        other_user = self._check(
            "synthetic-user-a",
            "synthetic-session-user-a",
            "synthetic-resource-user-b-private",
        )

        self.assertEqual(own.decision, AuthorizationDecision.ALLOWED)
        self.assertEqual(other_user.decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertFalse(other_user.allowed)

    def test_user_b_isolated_from_user_a_and_other_tenant(self) -> None:
        other_owner = self._check(
            "synthetic-user-b",
            "synthetic-session-user-b",
            "synthetic-resource-user-a-private",
        )
        cross_tenant = self._check(
            "synthetic-user-b",
            "synthetic-session-user-b",
            "synthetic-resource-tenant-b",
        )

        self.assertEqual(other_owner.decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertEqual(cross_tenant.decision, AuthorizationDecision.TENANT_MISMATCH)

    def test_guest_public_access_and_tenant_denial(self) -> None:
        public = self._check(
            "synthetic-guest",
            "synthetic-session-guest",
            "synthetic-resource-public",
        )
        tenant_resource = self._check(
            "synthetic-guest",
            "synthetic-session-guest",
            "synthetic-resource-tenant-a",
        )

        self.assertEqual(public.decision, AuthorizationDecision.ALLOWED)
        self.assertEqual(tenant_resource.decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)

    def test_invalid_identity_session_and_application_context_are_denied(self) -> None:
        invalid_identity = self._check(
            "synthetic-unknown",
            "synthetic-session-unknown",
            "synthetic-resource-public",
        )
        invalid_session = self._check(
            "synthetic-user-a",
            "synthetic-session-forged",
            "synthetic-resource-user-a-private",
        )
        context_mismatch = self._check(
            "synthetic-user-a",
            "synthetic-session-user-a",
            "synthetic-resource-user-a-private",
            context_identity_id="synthetic-user-b",
        )

        self.assertEqual(invalid_identity.decision, AuthorizationDecision.INVALID_IDENTITY)
        self.assertEqual(invalid_session.decision, AuthorizationDecision.INVALID_SESSION)
        self.assertEqual(context_mismatch.decision, AuthorizationDecision.INVALID_IDENTITY)

    def test_unauthenticated_identity_is_denied_even_with_a_valid_synthetic_session(self) -> None:
        identity = SyntheticIdentityCreate(
            display_name="Synthetic Unauthenticated",
            tenant_id="tenant-a",
            roles=[IdentityRole.USER],
            authentication_status="unauthenticated",
        ).to_identity()
        self.store.create_identity(identity)

        result = self._check(
            identity.identity_id,
            identity.session_id,
            "synthetic-resource-public",
        )

        self.assertEqual(result.decision, AuthorizationDecision.INVALID_IDENTITY)

    def test_claimed_role_and_model_instructions_never_override_policy(self) -> None:
        claimed_admin = self._check(
            "synthetic-user-a",
            "synthetic-session-user-a",
            "synthetic-resource-admin",
            claimed_role="admin",
            model_claims_access=True,
        )

        self.assertEqual(claimed_admin.decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertFalse(claimed_admin.allowed)

    def test_all_ten_authorization_scenarios_use_real_policy_decisions(self) -> None:
        for scenario in AuthorizationScenario:
            with self.subTest(scenario=scenario.value):
                result = self.service.run_scenario(scenario)
                self.assertEqual(result.actual_authorization_result, result.expected_authorization_result)
                self.assertEqual(result.outcome, AuthorizationOutcome.NO_ISSUE_OBSERVED)
                self.assertIn(scenario, [item.scenario for item in self.store.list_authorization_tests()])

    def test_denied_authorization_is_never_a_vulnerability(self) -> None:
        request = AuthorizationCheckRequest(
            identity_id="synthetic-user-a",
            session_id="synthetic-session-user-a",
            resource_id="synthetic-resource-admin",
            operation=ResourceOperation.READ,
            expected_authorization_result=AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
            model_claims_access=True,
        )
        result = self.service.check(request)

        self.assertEqual(result.actual_authorization_result, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertEqual(result.outcome, AuthorizationOutcome.NO_ISSUE_OBSERVED)

    def test_actual_allowed_policy_decision_against_expected_denial_is_flagged(self) -> None:
        request = AuthorizationCheckRequest(
            identity_id="synthetic-user-a",
            session_id="synthetic-session-user-a",
            resource_id="synthetic-resource-user-a-private",
            operation=ResourceOperation.READ,
            expected_authorization_result=AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
        )
        result = self.service.check(request)

        self.assertEqual(result.actual_authorization_result, AuthorizationDecision.ALLOWED)
        self.assertEqual(result.outcome, AuthorizationOutcome.VULNERABILITY_DETECTED)

    def test_identity_validation_restricts_ids_tenants_and_display_names_to_synthetic(self) -> None:
        for values in (
            {"display_name": "A real-looking user", "tenant_id": "tenant-a", "roles": ["user"]},
            {"display_name": "Synthetic Test", "tenant_id": "real-tenant", "roles": ["user"]},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                SyntheticIdentityCreate.model_validate(values)

    def test_api_identity_resource_check_and_test_result_workflow(self) -> None:
        client = TestClient(app)
        created = client.post("/identities", json={
            "display_name": "Synthetic API Operator",
            "tenant_id": "tenant-a",
            "roles": ["user"],
            "permissions": [],
        })
        self.assertEqual(created.status_code, 201)
        identity = created.json()
        identity_id = identity["identity_id"]
        self.assertTrue(identity_id.startswith("synthetic-"))
        self.assertTrue(identity["session_id"].startswith("synthetic-session-"))

        retrieved = client.get(f"/identities/{identity_id}")
        self.assertEqual(retrieved.status_code, 200)
        self.assertEqual(retrieved.json()["identity_id"], identity_id)

        updated = client.patch(f"/identities/{identity_id}", json={
            "roles": ["manager"],
            "permissions": ["resource:read"],
        })
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["roles"], ["manager"])
        self.assertEqual(updated.json()["permissions"], ["resource:read"])
        manager_access = client.post("/authorization/check", json={
            "identity_id": identity_id,
            "session_id": identity["session_id"],
            "resource_id": "synthetic-resource-manager",
            "operation": "read",
            "expected_authorization_result": "allowed",
        })
        self.assertEqual(
            manager_access.json()["actual_authorization_result"],
            "allowed",
        )

        resources = client.get("/authorization/resources")
        self.assertEqual(resources.status_code, 200)
        self.assertEqual(len(resources.json()), 7)
        invalid_resource = client.post("/authorization/check", json={
            "identity_id": identity_id,
            "session_id": identity["session_id"],
            "resource_id": "real-resource-1",
            "operation": "read",
            "expected_authorization_result": "denied",
        })
        self.assertEqual(invalid_resource.status_code, 422)

        scenario = client.post("/authorization/tests", json={
            "scenario": "cross_tenant_access",
        })
        self.assertEqual(scenario.status_code, 201)
        test_id = scenario.json()["test_id"]
        self.assertEqual(scenario.json()["actual_authorization_result"], "tenant_mismatch")
        listed = client.get("/authorization/tests?limit=10")
        self.assertEqual(listed.status_code, 200)
        self.assertTrue(any(item["test_id"] == test_id for item in listed.json()))
        loaded = client.get(f"/authorization/tests/{test_id}")
        self.assertEqual(loaded.status_code, 200)
        self.assertEqual(loaded.json()["scenario"], "cross_tenant_access")

    def test_api_rejects_invalid_permission_role_and_resource_input(self) -> None:
        client = TestClient(app)
        invalid_identity = client.post("/identities", json={
            "display_name": "Synthetic Bad Permission",
            "tenant_id": "tenant-a",
            "roles": ["root"],
            "permissions": ["resource:read"],
        })
        self.assertEqual(invalid_identity.status_code, 422)
        invalid_check = client.post("/authorization/check", json={
            "identity_id": "synthetic-user-a",
            "session_id": "synthetic-session-user-a",
            "resource_id": "synthetic-resource-public",
            "operation": "delete",
            "expected_authorization_result": "denied",
        })
        self.assertEqual(invalid_check.status_code, 422)


class AuthorizationMigrationTests(unittest.TestCase):
    def test_migration_from_schema_v4_preserves_phase1_and_historical_records(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        database_url = f"sqlite:///{Path(temp_dir.name, 'schema-v4.sqlite3').as_posix()}"
        target_id = str(uuid4())
        scan_id = str(uuid4())
        finding_id = str(uuid4())
        capability_profile = {
            "capabilities": {
                "model_endpoint": {
                    "enabled": True,
                    "configuration_reference": None,
                    "validation_status": "configured",
                    "supported_security_tests": [],
                    "known_limitations": [],
                }
            }
        }
        scan_record = {
            "scan_id": scan_id,
            "target_id": target_id,
            "status": "completed",
            "requested_case_count": 1,
            "target_scope": "model_endpoint",
            "capability_profile": capability_profile,
        }
        finding_data = {"finding_id": finding_id, "category": "prompt_injection"}
        engine = create_engine(database_url)
        with engine.begin() as connection:
            connection.execute(text("""
                CREATE TABLE targets (
                    target_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    target_type VARCHAR(40) NOT NULL,
                    target_scope VARCHAR(40) NOT NULL,
                    capability_profile JSON,
                    endpoint TEXT NOT NULL,
                    model VARCHAR(200),
                    provider VARCHAR(40) NOT NULL,
                    description TEXT,
                    api_path TEXT,
                    auth_header VARCHAR(100) NOT NULL DEFAULT 'Authorization',
                    system_prompt TEXT,
                    temperature FLOAT NOT NULL DEFAULT 0.0,
                    max_output_tokens INTEGER NOT NULL DEFAULT 256,
                    connection_status VARCHAR(24) NOT NULL DEFAULT 'unknown',
                    last_tested DATETIME,
                    credential_ciphertext TEXT,
                    active BOOLEAN NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE scans (
                    scan_id VARCHAR(36) PRIMARY KEY,
                    target_id VARCHAR(36) NOT NULL,
                    status VARCHAR(24) NOT NULL,
                    created_at DATETIME NOT NULL,
                    idempotency_key VARCHAR(160),
                    scan_record JSON NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE findings (
                    finding_id VARCHAR(80) PRIMARY KEY,
                    scan_id VARCHAR(36) NOT NULL,
                    case_id VARCHAR(80) NOT NULL,
                    severity VARCHAR(24) NOT NULL,
                    category VARCHAR(100) NOT NULL,
                    finding_data JSON NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at DATETIME NOT NULL
                )
            """))
            created_at = datetime.now(timezone.utc).isoformat()
            connection.execute(text("""
                INSERT INTO targets
                    (target_id, name, target_type, target_scope, capability_profile,
                     endpoint, provider, created_at)
                VALUES (:id, 'Phase 1 target', 'openai_compatible', 'model_endpoint',
                        :profile, 'https://api.openai.com/v1/chat/completions',
                        'openai', :created)
            """), {
                "id": target_id,
                "profile": json.dumps(capability_profile),
                "created": created_at,
            })
            connection.execute(text("""
                INSERT INTO scans
                    (scan_id, target_id, status, created_at, scan_record)
                VALUES (:id, :target_id, 'completed', :created, :record)
            """), {
                "id": scan_id,
                "target_id": target_id,
                "created": created_at,
                "record": json.dumps(scan_record),
            })
            connection.execute(text("""
                INSERT INTO findings
                    (finding_id, scan_id, case_id, severity, category, finding_data)
                VALUES (:id, :scan_id, 'case-existing', 'low', 'prompt_injection', :data)
            """), {
                "id": finding_id,
                "scan_id": scan_id,
                "data": json.dumps(finding_data),
            })
            connection.execute(text(
                "INSERT INTO schema_version (version, applied_at) VALUES "
                "(1, CURRENT_TIMESTAMP), (2, CURRENT_TIMESTAMP), "
                "(3, CURRENT_TIMESTAMP), (4, CURRENT_TIMESTAMP)"
            ))
        engine.dispose()

        store = Database(database_url)
        self.addCleanup(store.close)
        store.initialize()
        store.initialize()

        migrated_target = store.get_target(target_id)
        migrated_scan = store.get_scan(scan_id)
        self.assertTrue(
            migrated_target.capability_profile.capabilities["model_endpoint"].enabled
        )
        self.assertEqual(migrated_scan.target_scope.value, "model_endpoint")
        self.assertTrue(
            migrated_scan.capability_profile.capabilities["model_endpoint"].enabled
        )
        with store.engine.connect() as connection:
            migrated_finding = connection.execute(
                text("SELECT finding_data FROM findings WHERE finding_id = :id"),
                {"id": finding_id},
            ).scalar_one()
            migrated_scans = connection.execute(
                text("SELECT COUNT(*) FROM scans WHERE scan_id = :id"),
                {"id": scan_id},
            ).scalar_one()
            versions = set(connection.execute(text("SELECT version FROM schema_version")).scalars())
        self.assertEqual(json.loads(migrated_finding), finding_data)
        self.assertEqual(migrated_scans, 1)
        self.assertEqual(versions, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
        table_names = set(inspect(store.engine).get_table_names())
        self.assertTrue({
            "synthetic_identities",
            "synthetic_resources",
            "authorization_test_results",
        }.issubset(table_names))
        index_names = {
            index["name"]
            for table in (
                "synthetic_identities",
                "synthetic_resources",
                "authorization_test_results",
            )
            for index in inspect(store.engine).get_indexes(table)
        }
        self.assertTrue({
            "ix_synthetic_identities_tenant_id",
            "ix_synthetic_resources_tenant_id",
            "ix_authorization_test_results_created_at",
        }.issubset(index_names))


if __name__ == "__main__":
    unittest.main()

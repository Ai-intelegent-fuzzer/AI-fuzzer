import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.authorization.models import AuthorizationDecision, Permission
from app.database.store import Base, Database
from app.integrations.models import (
    ConnectorOperation,
    IntegrationExecutionRequest,
    IntegrationSecurityScenario,
    IntegrationSecurityTestRequest,
    SyntheticIntegrationCreate,
)
from app.integrations.service import IntegrationService
from app.main import app


class IntegrationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Database("sqlite://")
        self.store.initialize()
        self.addCleanup(self.store.close)
        self.service = IntegrationService(self.store)

    def execute(
        self,
        integration_id: str,
        identity_id: str,
        operation: ConnectorOperation = ConnectorOperation.READ,
        **overrides,
    ):
        session_ids = {
            "synthetic-admin": "synthetic-session-admin",
            "synthetic-manager": "synthetic-session-manager",
            "synthetic-user-a": "synthetic-session-user-a",
            "synthetic-user-b": "synthetic-session-user-b",
            "synthetic-rag-tenant-b-user": "synthetic-session-rag-tenant-b-user",
        }
        return self.service.execute(integration_id, IntegrationExecutionRequest(
            identity_id=identity_id,
            session_id=session_ids[identity_id],
            operation=operation,
            **overrides,
        ))

    def test_synthetic_integrations_cover_requested_connector_types(self) -> None:
        integrations = self.service.list_integrations()

        self.assertEqual(len(integrations), 10)
        self.assertEqual(
            {item.provider_type.value for item in integrations},
            {
                "document_storage", "database", "crm", "email", "calendar",
                "internal_knowledge_base", "file_management", "webhook",
                "third_party_api", "internal_business_app",
            },
        )
        self.assertTrue(all(item.integration_id.startswith("synthetic-integration-") for item in integrations))
        self.assertTrue(all(item.simulated_execution_mode == "local_synthetic" for item in integrations))

    def test_connector_reads_use_central_resource_owner_and_tenant_policy(self) -> None:
        own = self.execute(
            "synthetic-integration-document-store",
            "synthetic-user-a",
        )
        horizontal = self.execute(
            "synthetic-integration-crm",
            "synthetic-user-a",
        )
        cross_tenant = self.execute(
            "synthetic-integration-third-party-api",
            "synthetic-user-a",
        )
        tenant_b = self.execute(
            "synthetic-integration-third-party-api",
            "synthetic-rag-tenant-b-user",
        )

        self.assertTrue(own.executed)
        self.assertTrue(own.result["record"].startswith("[SYNTHETIC]"))
        self.assertFalse(horizontal.executed)
        self.assertEqual(horizontal.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertFalse(cross_tenant.executed)
        self.assertEqual(cross_tenant.authorization_decision, AuthorizationDecision.TENANT_MISMATCH)
        self.assertTrue(tenant_b.executed)

    def test_synthetic_token_scopes_only_restrict_authorization(self) -> None:
        mismatch = self.execute(
            "synthetic-integration-document-store",
            "synthetic-user-a",
            synthetic_token_scopes=[Permission.READ_PUBLIC],
        )
        excessive = self.execute(
            "synthetic-integration-document-store",
            "synthetic-user-a",
            synthetic_token_scopes=[Permission.READ_OWNED, Permission.RESOURCE_WRITE],
        )
        matching = self.execute(
            "synthetic-integration-document-store",
            "synthetic-user-a",
            synthetic_token_scopes=[Permission.READ_OWNED],
        )

        self.assertFalse(mismatch.executed)
        self.assertEqual(mismatch.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertFalse(excessive.executed)
        self.assertTrue(matching.executed)

    def test_simulated_writes_are_permission_checked_and_persist_synthetic_state(self) -> None:
        denied = self.execute(
            "synthetic-integration-webhook",
            "synthetic-user-a",
            ConnectorOperation.WRITE,
            value="[SYNTHETIC] unauthorized write",
        )
        allowed = self.execute(
            "synthetic-integration-webhook",
            "synthetic-manager",
            ConnectorOperation.WRITE,
            value="[SYNTHETIC] simulated webhook",
            synthetic_token_scopes=[Permission.RESOURCE_WRITE, Permission.WRITE_OWNED],
        )
        audit = next(item for item in self.service.list_audits(20) if item.audit_id == allowed.audit_id)

        self.assertFalse(denied.executed)
        self.assertTrue(allowed.executed)
        self.assertTrue(allowed.simulated)
        self.assertEqual(
            self.store.get_synthetic_integration_state("synthetic-integration-webhook"),
            "[SYNTHETIC] simulated webhook",
        )
        self.assertEqual(audit.actual_authorization, AuthorizationDecision.ALLOWED)
        self.assertEqual(len(audit.execution_result_reference), 64)
        self.assertNotIn("simulated webhook", json.dumps(audit.model_dump(mode="json")))

    def test_identity_mismatch_and_disabled_operation_are_denied(self) -> None:
        mismatch = self.execute(
            "synthetic-integration-document-store",
            "synthetic-user-a",
            context_identity_id="synthetic-user-b",
        )
        disabled = self.execute(
            "synthetic-integration-email",
            "synthetic-user-a",
            ConnectorOperation.WRITE,
            value="[SYNTHETIC] no email is sent",
        )

        self.assertEqual(mismatch.authorization_decision, AuthorizationDecision.INVALID_IDENTITY)
        self.assertFalse(mismatch.executed)
        self.assertEqual(disabled.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertFalse(disabled.executed)

    def test_all_security_scenarios_persist_decisions_without_invented_bypasses(self) -> None:
        for scenario in IntegrationSecurityScenario:
            with self.subTest(scenario=scenario.value):
                result = self.service.run_security_test(IntegrationSecurityTestRequest(
                    scenario=scenario,
                    scan_id="synthetic-integration-scan",
                    test_case_id=f"case-{scenario.value}",
                ))
                self.assertEqual(result.scenario, scenario)
                self.assertTrue(result.audit_id)
                self.assertIn(
                    result.outcome,
                    {"no_issue_observed", "vulnerability_detected", "inconclusive"},
                )
                if scenario in {
                    IntegrationSecurityScenario.PROMPT_INJECTION,
                    IntegrationSecurityScenario.TRUST_BOUNDARY,
                    IntegrationSecurityScenario.OUTPUT_MANIPULATION,
                    IntegrationSecurityScenario.EXCESSIVE_PERMISSIONS,
                    IntegrationSecurityScenario.MISSING_AUTHORIZATION,
                }:
                    self.assertEqual(result.outcome, "inconclusive")
        self.assertEqual(len(self.service.list_security_results(100)), 14)


class IntegrationApiTests(unittest.TestCase):
    def test_integration_apis_expose_metadata_only_and_audited_simulated_execution(self) -> None:
        client = TestClient(app)
        listed = client.get("/integrations")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()), 10)
        self.assertNotIn("synthetic_record", listed.json()[0])
        self.assertNotIn("token", json.dumps(listed.json()).casefold())

        denied = client.post(
            "/integrations/synthetic-integration-crm/execute",
            json={
                "identity_id": "synthetic-user-a",
                "session_id": "synthetic-session-user-a",
                "operation": "read",
                "scan_id": "synthetic-api-integration",
                "test_case_id": "api-horizontal",
            },
        )
        self.assertEqual(denied.status_code, 201)
        self.assertFalse(denied.json()["executed"])

        audits = client.get("/integrations/audits")
        self.assertEqual(audits.status_code, 200)
        self.assertGreaterEqual(len(audits.json()), 1)

    def test_integration_registration_rejects_non_synthetic_connector_data(self) -> None:
        client = TestClient(app)
        invalid = client.post("/integrations", json={
            "provider_type": "crm",
            "display_name": "Live CRM",
            "permission_scope": ["resource:read:owned"],
            "tenant_scope": "tenant-a",
            "owner_identity_id": "synthetic-user-a",
            "resource_id": "synthetic-resource-user-a-private",
            "data_classification": "private",
            "synthetic_record": "Real customer record.",
        })
        self.assertEqual(invalid.status_code, 422)

        created = client.post("/integrations", json={
            "provider_type": "crm",
            "display_name": "Synthetic Registered CRM",
            "permission_scope": ["resource:read:owned"],
            "tenant_scope": "tenant-a",
            "owner_identity_id": "synthetic-user-a",
            "resource_id": "synthetic-resource-user-a-private",
            "data_classification": "private",
            "synthetic_record": "[SYNTHETIC] Registered CRM fixture.",
        })
        self.assertEqual(created.status_code, 201)
        self.assertTrue(created.json()["integration_id"].startswith("synthetic-integration-"))
        self.assertNotIn("synthetic_record", created.json())


class IntegrationMigrationTests(unittest.TestCase):
    def test_schema_v7_upgrade_adds_connector_tables_and_preserves_history(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database_url = f"sqlite:///{Path(temporary.name, 'schema-v7.sqlite3').as_posix()}"
        added_tables = {
            "synthetic_integrations",
            "integration_execution_audits",
            "integration_security_results",
            "synthetic_integration_state",
        }
        engine = create_engine(database_url)
        prior_tables = [
            table
            for table in Base.metadata.sorted_tables
            if table.name not in added_tables
        ]
        Base.metadata.create_all(engine, tables=prior_tables)
        with engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO schema_version (version, applied_at) VALUES "
                "(1, CURRENT_TIMESTAMP), (2, CURRENT_TIMESTAMP), "
                "(3, CURRENT_TIMESTAMP), (4, CURRENT_TIMESTAMP), "
                "(5, CURRENT_TIMESTAMP), (6, CURRENT_TIMESTAMP), "
                "(7, CURRENT_TIMESTAMP)"
            ))
            identity_data = {
                "identity_id": "synthetic-v7-identity",
                "display_name": "Synthetic V7 Identity",
                "tenant_id": "tenant-a",
                "roles": ["user"],
                "permissions": [],
                "authentication_status": "authenticated",
                "session_id": "synthetic-session-v7",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
            connection.execute(text("""
                INSERT INTO synthetic_identities
                (identity_id, tenant_id, session_id, roles, permissions, identity_data)
                VALUES ('synthetic-v7-identity', 'tenant-a', 'synthetic-session-v7',
                        '["user"]', '[]', :data)
            """), {"data": json.dumps(identity_data)})
            connection.execute(text("""
                INSERT INTO synthetic_tool_state (resource_id, tenant_id, state_value)
                VALUES ('synthetic-resource-v7', 'tenant-a', '[SYNTHETIC] historical tool state')
            """))
        engine.dispose()

        store = Database(database_url)
        self.addCleanup(store.close)
        store.initialize()
        store.initialize()

        self.assertEqual(store.get_identity("synthetic-v7-identity").display_name, "Synthetic V7 Identity")
        self.assertEqual(
            store.get_synthetic_tool_state("synthetic-resource-v7"),
            "[SYNTHETIC] historical tool state",
        )
        self.assertEqual(len(store.list_integrations()), 10)
        with store.engine.connect() as connection:
            versions = set(connection.execute(text("SELECT version FROM schema_version")).scalars())
            tables = set(connection.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )).scalars())
        self.assertEqual(versions, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
        self.assertTrue(added_tables.issubset(tables))


if __name__ == "__main__":
    unittest.main()

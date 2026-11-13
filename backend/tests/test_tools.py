import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.database.store import Base, Database, ToolDefinitionRow
from app.main import app
from app.authorization.models import (
    AuthorizationDecision,
    IdentityRole,
    Permission,
    ResourceClassification,
    ResourceOperation,
)
from app.tools.models import (
    MCPResourceRequest,
    TOOL_OPERATION_ACCESS,
    ToolDefinition,
    ToolInputField,
    ToolInvocationRequest,
    ToolOperation,
    ToolRegistration,
    ToolSecurityScenario,
    ToolSecurityTestRequest,
    classify_tool_operation,
)
from app.tools.service import ToolService


class ToolServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Database("sqlite://")
        self.store.initialize()
        self.addCleanup(self.store.close)
        self.service = ToolService(self.store)

    def registration(
        self,
        operation: ToolOperation,
        *,
        input_schema: dict[str, ToolInputField] | None = None,
    ) -> ToolRegistration:
        access = classify_tool_operation(operation)
        return ToolRegistration(
            name=f"Synthetic {operation.value} Test",
            description="Synthetic operation classification test.",
            input_schema=input_schema or {
                "resource_id": ToolInputField(type="string", required=True),
                "value": ToolInputField(type="string", required=False),
            },
            required_permissions=[
                Permission.RESOURCE_WRITE
                if access == ResourceOperation.WRITE
                else Permission.RESOURCE_READ
            ],
            risk_classification=ResourceClassification.PRIVATE,
            read_only=access == ResourceOperation.READ,
            simulated_state_changing=access == ResourceOperation.WRITE,
            operation=operation,
        )

    def invoke(self, tool_id: str, identity: str, resource_id: str, **kwargs):
        sessions = {
            "synthetic-admin": "synthetic-session-admin",
            "synthetic-manager": "synthetic-session-manager",
            "synthetic-user-a": "synthetic-session-user-a",
            "synthetic-user-b": "synthetic-session-user-b",
            "synthetic-guest": "synthetic-session-guest",
        }
        return self.service.invoke(tool_id, ToolInvocationRequest(
            identity_id=identity,
            session_id=kwargs.pop("session_id", sessions[identity]),
            arguments={"resource_id": resource_id, **kwargs.pop("arguments", {})},
            **kwargs,
        ))

    def test_registry_contains_simulated_synthetic_tools_and_schemas(self) -> None:
        tools = self.service.list_tools()

        self.assertGreaterEqual(len(tools), 10)
        self.assertTrue(all(tool.tool_id.startswith("synthetic-tool-") for tool in tools))
        self.assertTrue(all(tool.name.startswith("Synthetic ") for tool in tools))
        self.assertTrue(all(
            tool.read_only != tool.simulated_state_changing
            for tool in tools
        ))
        self.assertTrue(all(tool.audit_enabled for tool in tools))
        self.assertEqual(set(TOOL_OPERATION_ACCESS), set(ToolOperation))
        for tool in tools:
            with self.subTest(tool=tool.tool_id):
                ToolDefinition.model_validate(tool.model_dump())

    def test_registration_accepts_consistent_read_and_state_changing_operations(self) -> None:
        read_tool = self.service.register_tool(self.registration(ToolOperation.READ_DOCUMENT))
        write_tool = self.service.register_tool(self.registration(ToolOperation.DELETE_RECORD))

        self.assertTrue(read_tool.read_only)
        self.assertFalse(read_tool.simulated_state_changing)
        self.assertFalse(write_tool.read_only)
        self.assertTrue(write_tool.simulated_state_changing)

    def test_registration_rejects_operation_and_flag_conflicts(self) -> None:
        invalid_definitions = [
            {
                "operation": ToolOperation.DELETE_RECORD,
                "read_only": True,
                "simulated_state_changing": False,
            },
            {
                "operation": ToolOperation.UPDATE_RECORD,
                "read_only": True,
                "simulated_state_changing": False,
            },
            {
                "operation": ToolOperation.DELETE_RECORD,
                "read_only": False,
                "simulated_state_changing": False,
            },
            {
                "operation": ToolOperation.READ_DOCUMENT,
                "read_only": False,
                "simulated_state_changing": True,
            },
        ]
        for invalid in invalid_definitions:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    ToolRegistration(
                        name="Synthetic Conflicting Tool",
                        description="Synthetic operation mismatch test.",
                        risk_classification=ResourceClassification.PRIVATE,
                        **invalid,
                    )

        with self.assertRaises(ValueError):
            ToolRegistration(
                name="Synthetic Unknown Operation",
                description="Unknown operations are rejected.",
                risk_classification=ResourceClassification.PRIVATE,
                read_only=True,
                simulated_state_changing=False,
                operation="unsupported_operation",
            )

    def test_read_authorization_uses_central_identity_owner_and_tenant_policy(self) -> None:
        allowed = self.invoke(
            "synthetic-tool-read-document",
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
        )
        horizontal = self.invoke(
            "synthetic-tool-read-document",
            "synthetic-user-b",
            "synthetic-resource-user-a-private",
        )
        cross_tenant = self.invoke(
            "synthetic-tool-read-document",
            "synthetic-user-a",
            "synthetic-resource-tenant-b",
        )

        self.assertTrue(allowed.executed)
        self.assertEqual(allowed.authorization_decision, AuthorizationDecision.ALLOWED)
        self.assertFalse(horizontal.executed)
        self.assertEqual(horizontal.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertFalse(cross_tenant.executed)
        self.assertEqual(cross_tenant.authorization_decision, AuthorizationDecision.TENANT_MISMATCH)
        self.assertTrue(allowed.result["synthetic_state"].startswith("[SYNTHETIC]"))

    def test_invalid_identity_and_session_are_denied_and_audited(self) -> None:
        invalid_identity = self.invoke(
            "synthetic-tool-read-document",
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
            session_id="synthetic-session-forged",
        )
        mismatch = self.invoke(
            "synthetic-tool-read-document",
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
            context_identity_id="synthetic-user-b",
        )
        audits = self.store.list_tool_executions(limit=2)

        self.assertEqual(invalid_identity.authorization_decision, AuthorizationDecision.INVALID_SESSION)
        self.assertEqual(mismatch.authorization_decision, AuthorizationDecision.INVALID_IDENTITY)
        self.assertEqual(len(audits), 2)
        self.assertTrue(all(not audit.executed for audit in audits))

    def test_argument_validation_blocks_unknown_fields_and_unsynthetic_state(self) -> None:
        unknown = self.invoke(
            "synthetic-tool-read-document",
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
            arguments={"extra": "[SYNTHETIC] ignored"},
        )
        unsafe_value = self.invoke(
            "synthetic-tool-write-document",
            "synthetic-manager",
            "synthetic-resource-manager",
            arguments={"value": "non-synthetic content"},
        )

        self.assertEqual(unknown.authorization_decision, AuthorizationDecision.DENIED)
        self.assertFalse(unknown.executed)
        self.assertEqual(unsafe_value.authorization_decision, AuthorizationDecision.DENIED)
        self.assertFalse(unsafe_value.executed)
        self.assertIsNone(self.store.get_synthetic_tool_state("synthetic-resource-manager"))

    def test_simulated_writes_are_policy_checked_and_only_change_synthetic_state(self) -> None:
        denied = self.invoke(
            "synthetic-tool-write-document",
            "synthetic-user-a",
            "synthetic-resource-manager",
            arguments={"value": "[SYNTHETIC] forbidden write"},
        )
        written = self.invoke(
            "synthetic-tool-write-document",
            "synthetic-manager",
            "synthetic-resource-manager",
            arguments={"value": "[SYNTHETIC] controlled write"},
        )
        deleted = self.invoke(
            "synthetic-tool-delete-record",
            "synthetic-admin",
            "synthetic-resource-admin",
        )

        self.assertFalse(denied.executed)
        self.assertEqual(denied.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertTrue(written.executed)
        self.assertEqual(
            self.store.get_synthetic_tool_state("synthetic-resource-manager"),
            "[SYNTHETIC] controlled write",
        )
        self.assertTrue(deleted.simulated)
        self.assertEqual(
            self.store.get_synthetic_tool_state("synthetic-resource-admin"),
            "[SYNTHETIC] deleted",
        )

    def test_denied_state_change_preserves_existing_synthetic_state_and_is_audited(self) -> None:
        self.store.update_synthetic_tool_state(
            "synthetic-resource-user-a-private",
            "tenant-a",
            "[SYNTHETIC] before denied update",
        )
        result = self.invoke(
            "synthetic-tool-update-record",
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
            arguments={"value": "[SYNTHETIC] unauthorized update"},
        )
        audit = self.store.list_tool_executions(limit=1)[0]

        self.assertFalse(result.executed)
        self.assertIsNone(result.result)
        self.assertEqual(result.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertEqual(
            self.store.get_synthetic_tool_state("synthetic-resource-user-a-private"),
            "[SYNTHETIC] before denied update",
        )
        self.assertFalse(audit.executed)
        self.assertEqual(audit.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)

    def test_malformed_legacy_tool_definition_is_denied_audited_and_does_not_mutate(self) -> None:
        self.store.update_synthetic_tool_state(
            "synthetic-resource-manager",
            "tenant-a",
            "[SYNTHETIC] preserved legacy state",
        )
        definitions = [
            self.service.register_tool(self.registration(ToolOperation.UPDATE_RECORD)),
            self.service.register_tool(self.registration(ToolOperation.DELETE_RECORD)),
        ]
        for definition in definitions:
            with self.subTest(operation=definition.operation):
                with self.store._sessions.begin() as session:
                    row = session.get(ToolDefinitionRow, definition.tool_id)
                    row.tool_data = {
                        **row.tool_data,
                        "read_only": True,
                        "simulated_state_changing": False,
                    }

                result = self.invoke(
                    definition.tool_id,
                    "synthetic-manager",
                    "synthetic-resource-manager",
                    arguments={"value": "[SYNTHETIC] attempted legacy mutation"},
                )
                audit = self.store.list_tool_executions(limit=1)[0]

                self.assertFalse(result.executed)
                self.assertIsNone(result.result)
                self.assertEqual(result.authorization_decision, AuthorizationDecision.DENIED)
                self.assertIn("failed validation", result.reason)
                self.assertEqual(
                    self.store.get_synthetic_tool_state("synthetic-resource-manager"),
                    "[SYNTHETIC] preserved legacy state",
                )
                self.assertFalse(audit.executed)
                self.assertEqual(audit.authorization_decision, AuthorizationDecision.DENIED)
                self.assertEqual(audit.tool_id, definition.tool_id)

    def test_unknown_legacy_operation_is_denied_and_audited(self) -> None:
        definition = self.service.register_tool(self.registration(ToolOperation.READ_DOCUMENT))
        with self.store._sessions.begin() as session:
            row = session.get(ToolDefinitionRow, definition.tool_id)
            row.tool_data = {**row.tool_data, "operation": "unsupported_operation"}

        result = self.invoke(
            definition.tool_id,
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
        )
        audit = self.store.list_tool_executions(limit=1)[0]

        self.assertFalse(result.executed)
        self.assertIsNone(result.result)
        self.assertEqual(result.authorization_decision, AuthorizationDecision.DENIED)
        self.assertIn("failed validation", result.reason)
        self.assertFalse(audit.executed)
        self.assertEqual(audit.authorization_decision, AuthorizationDecision.DENIED)
        self.assertEqual(audit.tool_id, definition.tool_id)

    def test_client_operation_override_cannot_change_registered_dispatch(self) -> None:
        definition = self.service.register_tool(self.registration(
            ToolOperation.READ_DOCUMENT,
            input_schema={
                "resource_id": ToolInputField(type="string", required=True),
                "operation": ToolInputField(type="string", required=True),
            },
        ))
        self.store.update_synthetic_tool_state(
            "synthetic-resource-user-a-private",
            "tenant-a",
            "[SYNTHETIC] preserve against client override",
        )
        result = self.invoke(
            definition.tool_id,
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
            arguments={"operation": "delete_record"},
        )

        self.assertTrue(result.executed)
        self.assertEqual(result.authorization_decision, AuthorizationDecision.ALLOWED)
        self.assertEqual(
            self.store.get_synthetic_tool_state("synthetic-resource-user-a-private"),
            "[SYNTHETIC] preserve against client override",
        )

    def test_role_and_permission_claims_in_arguments_cannot_bypass_policy(self) -> None:
        definition = self.service.register_tool(self.registration(
            ToolOperation.READ_DOCUMENT,
            input_schema={
                "resource_id": ToolInputField(type="string", required=True),
                "role": ToolInputField(type="string", required=True),
                "permissions": ToolInputField(type="string", required=True),
            },
        ))
        result = self.invoke(
            definition.tool_id,
            "synthetic-user-a",
            "synthetic-resource-admin",
            arguments={"role": "admin", "permissions": "resource:read:any"},
        )

        self.assertFalse(result.executed)
        self.assertEqual(
            result.authorization_decision,
            AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
        )

    def test_tool_chaining_does_not_bypass_a_separate_authorization(self) -> None:
        result = self.invoke(
            "synthetic-tool-invoke-another",
            "synthetic-user-a",
            "synthetic-resource-user-a-private",
            arguments={"target_tool_id": "synthetic-tool-delete-record"},
        )

        self.assertTrue(result.executed)
        self.assertTrue(result.result["chain_denied"])

    def test_mcp_resource_content_is_returned_only_after_central_authorization(self) -> None:
        owner = self.service.retrieve_mcp_resource(
            "synthetic-resource-mcp-user-a",
            MCPResourceRequest(
                identity_id="synthetic-user-a",
                session_id="synthetic-session-user-a",
                scan_id="synthetic-mcp-test",
                test_case_id="mcp-owner",
            ),
        )
        unauthorized = self.service.retrieve_mcp_resource(
            "synthetic-resource-mcp-user-a",
            MCPResourceRequest(
                identity_id="synthetic-user-b",
                session_id="synthetic-session-user-b",
                scan_id="synthetic-mcp-test",
                test_case_id="mcp-horizontal",
            ),
        )
        cross_tenant = self.service.retrieve_mcp_resource(
            "synthetic-resource-mcp-tenant-b",
            MCPResourceRequest(
                identity_id="synthetic-user-a",
                session_id="synthetic-session-user-a",
            ),
        )

        self.assertTrue(owner["retrieved"])
        self.assertTrue(str(owner["content"]).startswith("[SYNTHETIC]"))
        self.assertFalse(unauthorized["retrieved"])
        self.assertNotIn("content", unauthorized)
        self.assertEqual(cross_tenant["authorization_decision"], "tenant_mismatch")
        self.assertNotIn("content", cross_tenant)
        audits = self.store.list_tool_executions(limit=3)
        self.assertEqual(len(audits), 3)

    def test_all_security_scenarios_persist_explicit_decisions(self) -> None:
        for scenario in ToolSecurityScenario:
            with self.subTest(scenario=scenario.value):
                result = self.service.run_security_test(ToolSecurityTestRequest(
                    scenario=scenario,
                    scan_id="synthetic-tool-scenarios",
                    test_case_id=f"case-{scenario.value}",
                ))
                self.assertEqual(result.scenario, scenario)
                self.assertTrue(result.execution_id)
                self.assertIn(
                    result.outcome,
                    {"no_issue_observed", "vulnerability_detected", "inconclusive"},
                )
                if scenario in {
                    ToolSecurityScenario.MALICIOUS_DESCRIPTION,
                    ToolSecurityScenario.MALICIOUS_OUTPUT,
                    ToolSecurityScenario.INDIRECT_INJECTION,
                    ToolSecurityScenario.MCP_TRUST_VIOLATION,
                }:
                    self.assertEqual(result.outcome, "inconclusive")
        self.assertEqual(len(self.service.list_security_results(limit=100)), 15)


class ToolApiTests(unittest.TestCase):
    def test_tool_mcp_and_audit_apis_are_synthetic_and_validated(self) -> None:
        client = TestClient(app)
        tools = client.get("/tools")
        self.assertEqual(tools.status_code, 200)
        self.assertGreaterEqual(len(tools.json()), 10)
        self.assertTrue(all(item["simulated_state_changing"] or item["read_only"] for item in tools.json()))

        servers = client.get("/mcp/servers")
        resources = client.get("/mcp/resources")
        self.assertEqual(servers.status_code, 200)
        self.assertEqual(resources.status_code, 200)
        self.assertNotIn("content", resources.json()[0])

        denied = client.post(
            "/tools/synthetic-tool-read-document/invoke",
            json={
                "identity_id": "synthetic-user-b",
                "session_id": "synthetic-session-user-b",
                "arguments": {"resource_id": "synthetic-resource-user-a-private"},
            },
        )
        self.assertEqual(denied.status_code, 201)
        self.assertFalse(denied.json()["executed"])

        bad_mcp = client.post(
            "/mcp/resources/synthetic-resource-mcp-user-a/retrieve",
            json={"identity_id": "real-user", "session_id": "synthetic-session-real-user"},
        )
        self.assertEqual(bad_mcp.status_code, 422)

        invocation_audit = client.get("/tools/executions")
        self.assertEqual(invocation_audit.status_code, 200)
        self.assertGreaterEqual(len(invocation_audit.json()), 1)

    def test_registration_rejects_non_synthetic_tool_and_accepts_local_fixture(self) -> None:
        client = TestClient(app)
        invalid = client.post("/tools/register", json={
            "name": "External Real CRM",
            "description": "Accesses a live CRM.",
            "input_schema": {},
            "required_permissions": ["resource:read"],
            "risk_classification": "public",
            "read_only": True,
            "simulated_state_changing": False,
            "operation": "search",
        })
        self.assertEqual(invalid.status_code, 422)

        conflicting = client.post("/tools/register", json={
            "name": "Synthetic Misclassified Delete",
            "description": "A delete operation cannot be declared read-only.",
            "input_schema": {"resource_id": {"type": "string", "required": True}},
            "required_permissions": ["resource:read"],
            "risk_classification": "public",
            "read_only": True,
            "simulated_state_changing": False,
            "operation": "delete_record",
        })
        self.assertEqual(conflicting.status_code, 422)

        created = client.post("/tools/register", json={
            "name": "Synthetic Test Search",
            "description": "Synthetic-only registered test tool.",
            "input_schema": {"query": {"type": "string", "required": False}},
            "required_permissions": ["resource:read"],
            "risk_classification": "public",
            "read_only": True,
            "simulated_state_changing": False,
            "operation": "search",
        })
        self.assertEqual(created.status_code, 201)
        self.assertTrue(created.json()["tool_id"].startswith("synthetic-tool-"))
        self.assertEqual(
            client.get(f"/tools/{created.json()['tool_id']}").status_code,
            200,
        )


class ToolMigrationTests(unittest.TestCase):
    def test_schema_v6_upgrade_creates_phase4_tables_and_preserves_history(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database_url = f"sqlite:///{Path(temporary.name, 'schema-v6.sqlite3').as_posix()}"
        phase4_tables = {
            "synthetic_tool_definitions",
            "simulated_tool_executions",
            "tool_security_results",
            "synthetic_mcp_servers",
            "synthetic_mcp_resources",
            "synthetic_tool_state",
            "synthetic_integrations",
            "integration_execution_audits",
            "integration_security_results",
            "synthetic_integration_state",
        }
        engine = create_engine(database_url)
        existing_tables = [
            table
            for table in Base.metadata.sorted_tables
            if table.name not in phase4_tables
        ]
        Base.metadata.create_all(engine, tables=existing_tables)
        with engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO schema_version (version, applied_at) VALUES "
                "(1, CURRENT_TIMESTAMP), (2, CURRENT_TIMESTAMP), "
                "(3, CURRENT_TIMESTAMP), (4, CURRENT_TIMESTAMP), "
                "(5, CURRENT_TIMESTAMP), (6, CURRENT_TIMESTAMP)"
            ))
            identity = {
                "identity_id": "synthetic-v6-preserved",
                "display_name": "Synthetic V6 Identity",
                "tenant_id": "tenant-a",
                "roles": ["user"],
                "permissions": [],
                "authentication_status": "authenticated",
                "session_id": "synthetic-session-v6",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
            connection.execute(text("""
                INSERT INTO synthetic_identities
                (identity_id, tenant_id, session_id, roles, permissions, identity_data)
                VALUES (:id, 'tenant-a', 'synthetic-session-v6', '["user"]', '[]', :data)
            """), {"id": identity["identity_id"], "data": json.dumps(identity)})
        engine.dispose()

        store = Database(database_url)
        self.addCleanup(store.close)
        store.initialize()
        store.initialize()

        self.assertEqual(store.get_identity("synthetic-v6-preserved").display_name, "Synthetic V6 Identity")
        self.assertGreaterEqual(len(store.list_tool_definitions()), 10)
        self.assertEqual(len(store.list_mcp_servers()), 2)
        with store.engine.connect() as connection:
            versions = set(connection.execute(text("SELECT version FROM schema_version")).scalars())
            tables = set(connection.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )).scalars())
        self.assertEqual(versions, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
        self.assertTrue(phase4_tables.issubset(tables))


if __name__ == "__main__":
    unittest.main()

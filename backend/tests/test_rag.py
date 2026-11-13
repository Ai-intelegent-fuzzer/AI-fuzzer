import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.adapters.models import (
    CapabilityName,
    CapabilityProfile,
    CapabilitySetting,
    CapabilityValidationStatus,
    Target,
    TargetScope,
    TargetType,
)
from app.authorization.models import (
    AuthorizationDecision,
    AuthorizationOutcome,
    IdentityRole,
    Permission,
    ResourceClassification,
)
from app.database.store import Database
from app.main import app
from app.rag.capabilities import category_supported_by_profile
from app.rag.models import (
    RAGDocumentCreate,
    RAGRetrievalRequest,
    RAGScenario,
)
from app.rag.service import RAGService
from app.fuzzing.models import ScanCreateRequest, ScanRecord, ScanStatus
from app.api.scan import start_scan


class RAGServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Database("sqlite://")
        self.store.initialize()
        self.addCleanup(self.store.close)
        self.service = RAGService(self.store)

    def _retrieve(self, identity: str, query: str, **kwargs):
        sessions = {
            "synthetic-admin": "synthetic-session-admin",
            "synthetic-manager": "synthetic-session-manager",
            "synthetic-user-a": "synthetic-session-user-a",
            "synthetic-user-b": "synthetic-session-user-b",
            "synthetic-guest": "synthetic-session-guest",
            "synthetic-rag-tenant-b-user": "synthetic-session-rag-tenant-b-user",
        }
        return self.service.retrieve(RAGRetrievalRequest(
            identity_id=identity,
            session_id=sessions[identity],
            query=query,
            top_k=20,
            **kwargs,
        ))

    def test_seeded_synthetic_rag_dataset_contains_required_document_types(self) -> None:
        documents = self.store.list_rag_documents()

        self.assertEqual(len(documents), 10)
        self.assertTrue(all(document.content.startswith("[SYNTHETIC]") for document in documents))
        self.assertEqual(
            {document.classification for document in documents},
            {
                ResourceClassification.PUBLIC,
                ResourceClassification.PRIVATE,
                ResourceClassification.ADMIN,
                ResourceClassification.MANAGER,
                ResourceClassification.TENANT,
            },
        )
        self.assertTrue(any(document.contains_untrusted_instructions for document in documents))
        self.assertTrue(any("SYNTHETIC-CANARY" in document.content for document in documents))

    def test_ingestion_validates_synthetic_namespace_owner_and_tenant(self) -> None:
        with self.assertRaises(ValueError):
            self.service.ingest(RAGDocumentCreate(
                title="Real customer notes",
                content="Contains non-synthetic text.",
                owner_identity_id="synthetic-user-a",
                tenant_id="tenant-a",
                classification=ResourceClassification.PRIVATE,
            ))
        with self.assertRaises(ValueError):
            self.service.ingest(RAGDocumentCreate(
                title="Synthetic mismatched tenant document",
                content="[SYNTHETIC] Controlled text.",
                owner_identity_id="synthetic-user-a",
                tenant_id="tenant-b",
                classification=ResourceClassification.PRIVATE,
            ))
        with self.assertRaises(ValueError):
            RAGDocumentCreate.model_validate({
                "title": "Synthetic malformed owner",
                "content": "[SYNTHETIC] Controlled text.",
                "owner_identity_id": "real-user",
                "tenant_id": "tenant-a",
                "classification": "private",
            })

    def test_user_a_and_user_b_are_isolated_by_document_owner(self) -> None:
        user_a = self._retrieve("synthetic-user-a", "User A private information")
        user_b = self._retrieve("synthetic-user-b", "User A private information")
        user_b_own = self._retrieve("synthetic-user-b", "User B private information")

        self.assertEqual(
            [item.metadata.document_id for item in user_a.documents],
            ["synthetic-rag-document-user-a-private"],
        )
        self.assertEqual(user_b.documents, [])
        self.assertEqual(
            user_b.audits[0].authorization_decision,
            AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
        )
        self.assertEqual(
            [item.metadata.document_id for item in user_b_own.documents],
            ["synthetic-rag-document-user-b-private"],
        )

    def test_admin_manager_and_guest_access_match_document_policy(self) -> None:
        admin = self._retrieve("synthetic-admin", "admin-only synthetic document")
        manager = self._retrieve("synthetic-manager", "manager synthetic document")
        guest_admin = self._retrieve("synthetic-guest", "admin-only synthetic document")
        guest_public = self._retrieve("synthetic-guest", "public test collection overview")

        self.assertEqual(len(admin.documents), 1)
        self.assertEqual(len(manager.documents), 1)
        self.assertEqual(guest_admin.documents, [])
        self.assertEqual(len(guest_public.documents), 1)
        self.assertEqual(guest_admin.audits[0].authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)

    def test_tenant_isolation_denies_and_audits_cross_tenant_retrieval(self) -> None:
        tenant_a = self._retrieve("synthetic-user-a", "Tenant B synthetic records")
        tenant_b = self._retrieve(
            "synthetic-rag-tenant-b-user",
            "Tenant A synthetic records",
        )

        self.assertEqual(tenant_a.documents, [])
        self.assertEqual(tenant_a.audits[0].authorization_decision, AuthorizationDecision.TENANT_MISMATCH)
        self.assertEqual(tenant_b.documents, [])
        self.assertEqual(tenant_b.audits[0].authorization_decision, AuthorizationDecision.TENANT_MISMATCH)

    def test_untrusted_instruction_documents_are_returned_as_marked_data_only(self) -> None:
        response = self._retrieve(
            "synthetic-user-a",
            "untrusted instruction injected document",
            scan_id="synthetic-scan-1",
            test_case_id="synthetic-case-1",
        )

        self.assertEqual(len(response.documents), 1)
        self.assertTrue(response.documents[0].metadata.contains_untrusted_instructions)
        self.assertIn("ignore trusted rules", response.documents[0].content)
        self.assertEqual(response.audits[0].scan_id, "synthetic-scan-1")
        self.assertEqual(response.audits[0].test_case_id, "synthetic-case-1")

    def test_identity_mismatch_denies_content_and_canary_disclosure(self) -> None:
        mismatch = self._retrieve(
            "synthetic-user-a",
            "User A private information",
            context_identity_id="synthetic-user-b",
        )
        canary = self._retrieve(
            "synthetic-user-b",
            "synthetic canary protected marker",
        )

        self.assertEqual(mismatch.documents, [])
        self.assertEqual(mismatch.audits[0].authorization_decision, AuthorizationDecision.INVALID_IDENTITY)
        self.assertEqual(canary.documents, [])
        self.assertEqual(canary.audits[0].authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertNotIn(
            "SYNTHETIC-CANARY",
            json.dumps([audit.model_dump(mode="json") for audit in canary.audits]),
        )

    def test_retrieval_audit_stores_provenance_without_raw_content(self) -> None:
        response = self._retrieve(
            "synthetic-user-b",
            "User A private information",
            scan_id="synthetic-scan-audit",
            test_case_id="synthetic-case-audit",
        )
        persisted = self.store.list_rag_retrieval_audits(
            scan_id="synthetic-scan-audit",
            test_case_id="synthetic-case-audit",
        )

        self.assertEqual(len(persisted), 1)
        audit = persisted[0]
        self.assertEqual(audit.document_id, "synthetic-rag-document-user-a-private")
        self.assertEqual(audit.document_tenant_id, "tenant-a")
        self.assertEqual(audit.requesting_tenant_id, "tenant-a")
        self.assertEqual(audit.authorization_decision, AuthorizationDecision.INSUFFICIENT_PERMISSIONS)
        self.assertFalse(audit.retrieval_decision)
        self.assertNotIn("User A private test information", json.dumps(audit.model_dump(mode="json")))
        self.assertEqual(len(audit.sanitized_evidence_reference), 64)
        self.assertEqual(response.documents, [])

    def test_all_rag_scenarios_execute_and_record_policy_evidence(self) -> None:
        model_behavior_scenarios = {
            RAGScenario.INDIRECT_PROMPT_INJECTION,
            RAGScenario.MALICIOUS_DOCUMENT_INSTRUCTIONS,
            RAGScenario.RETRIEVAL_POISONING,
            RAGScenario.RETRIEVAL_CONTEXT_MANIPULATION,
        }
        for scenario in RAGScenario:
            with self.subTest(scenario=scenario.value):
                result = self.service.run_scenario(
                    scenario,
                    scan_id="synthetic-rag-scan",
                    test_case_id=f"case-{scenario.value}",
                )
                self.assertEqual(result.requesting_identity_id, result.audits[0].requesting_identity_id)
                self.assertEqual(result.audits[0].scenario, scenario)
                self.assertEqual(
                    result.outcome,
                    "inconclusive" if scenario in model_behavior_scenarios else "no_issue_observed",
                )

        recorded = self.store.list_rag_retrieval_audits(scan_id="synthetic-rag-scan")
        self.assertGreaterEqual(len(recorded), 10)
        self.assertEqual(
            {audit.test_case_id for audit in recorded},
            {f"case-{scenario.value}" for scenario in RAGScenario},
        )

    def test_scan_case_canary_document_is_only_retrieved_for_authorized_owner(self) -> None:
        owner = self._retrieve("synthetic-user-a", "synthetic canary protected marker")
        other = self._retrieve("synthetic-user-b", "synthetic canary protected marker")

        self.assertEqual(len(owner.documents), 1)
        self.assertIn("SYNTHETIC-CANARY-RAG-7F3A", owner.documents[0].content)
        self.assertEqual(other.documents, [])
        self.assertEqual(other.audits[0].retrieval_decision, False)


class RAGApiAndCapabilityTests(unittest.TestCase):
    def test_document_apis_expose_metadata_and_retrieval_only_after_authorization(self) -> None:
        client = TestClient(app)
        listed = client.get("/rag/documents")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()), 10)
        self.assertNotIn("content", listed.json()[0])

        metadata = client.get("/rag/documents/synthetic-rag-document-user-a-private")
        self.assertEqual(metadata.status_code, 200)
        self.assertNotIn("content", metadata.json())

        denied = client.post("/rag/retrievals", json={
            "identity_id": "synthetic-user-b",
            "session_id": "synthetic-session-user-b",
            "query": "User A private information",
            "scan_id": "synthetic-api-scan",
            "test_case_id": "synthetic-api-case",
        })
        self.assertEqual(denied.status_code, 200)
        self.assertEqual(denied.json()["documents"], [])
        self.assertEqual(denied.json()["audits"][0]["retrieval_decision"], False)
        audits = client.get("/rag/retrieval-audits?scan_id=synthetic-api-scan")
        self.assertEqual(audits.status_code, 200)
        self.assertEqual(audits.json()[0]["test_case_id"], "synthetic-api-case")

        created = client.post("/rag/documents", json={
            "title": "Synthetic API document",
            "content": "[SYNTHETIC] API ingestion test content.",
            "owner_identity_id": "synthetic-user-a",
            "tenant_id": "tenant-a",
            "classification": "private",
            "required_permissions": ["resource:read:owned"],
            "metadata": {"topic": "API ingestion"},
        })
        self.assertEqual(created.status_code, 201)
        self.assertNotIn("content", created.json())

    def test_document_api_rejects_non_synthetic_data_and_bad_owner(self) -> None:
        client = TestClient(app)
        response = client.post("/rag/documents", json={
            "title": "Synthetic invalid document",
            "content": "Real-looking content not allowed.",
            "owner_identity_id": "synthetic-user-a",
            "tenant_id": "tenant-a",
            "classification": "private",
        })
        self.assertEqual(response.status_code, 422)
        response = client.post("/rag/documents", json={
            "title": "Synthetic invalid owner document",
            "content": "[SYNTHETIC] Controlled text.",
            "owner_identity_id": "synthetic-unknown",
            "tenant_id": "tenant-a",
            "classification": "private",
        })
        self.assertEqual(response.status_code, 422)

    def test_rag_categories_require_capabilities_and_mark_not_applicable(self) -> None:
        disabled = CapabilityProfile()
        rag_only = CapabilityProfile(capabilities={
            CapabilityName.RAG_ENABLED: CapabilitySetting(
                enabled=True,
                validation_status=CapabilityValidationStatus.CONFIGURED,
            ),
        })
        fully_configured = CapabilityProfile(capabilities={
            CapabilityName.RAG_ENABLED: CapabilitySetting(
                enabled=True,
                validation_status=CapabilityValidationStatus.CONFIGURED,
            ),
            CapabilityName.MULTI_TENANT: CapabilitySetting(
                enabled=True,
                validation_status=CapabilityValidationStatus.CONFIGURED,
            ),
            CapabilityName.AUTHORIZATION_ENABLED: CapabilitySetting(
                enabled=True,
                validation_status=CapabilityValidationStatus.CONFIGURED,
            ),
        })

        self.assertFalse(category_supported_by_profile("rag_security", None))
        self.assertFalse(category_supported_by_profile("rag_security", disabled))
        self.assertTrue(category_supported_by_profile("rag_security", rag_only))
        self.assertFalse(category_supported_by_profile(
            "rag_security",
            rag_only,
            TargetScope.MODEL_ENDPOINT,
        ))
        self.assertTrue(category_supported_by_profile(
            "rag_security",
            rag_only,
            TargetScope.AI_APPLICATION,
        ))
        self.assertFalse(category_supported_by_profile("rag_cross_tenant_data_leakage", rag_only))
        self.assertTrue(category_supported_by_profile("rag_cross_tenant_data_leakage", fully_configured))
        self.assertTrue(category_supported_by_profile("prompt_injection", disabled))

    def test_scan_start_marks_unsupported_application_categories_not_applicable(self) -> None:
        target = Target(
            target_id="synthetic-target-rag-gate",
            name="Synthetic capability gate target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            target_scope=TargetScope.MODEL_ENDPOINT,
            endpoint="https://api.openai.com/v1/chat/completions",
            capability_profile=CapabilityProfile(),
        )
        queued_scan = ScanRecord(
            scan_id="synthetic-queued-scan",
            target_id=target.target_id,
            status=ScanStatus.QUEUED,
            requested_case_count=5,
            requested_categories=[
                "prompt_injection",
                "rag_security",
                "tool_misuse",
                "mcp_security_abuse",
                "external_integration_abuse",
            ],
        )
        request = ScanCreateRequest(
            target_id=target.target_id,
            authorization_confirmed=True,
            count=5,
            categories=[
                "prompt_injection",
                "rag_security",
                "tool_misuse",
                "mcp_security_abuse",
                "external_integration_abuse",
            ],
        )
        with (
            patch("app.api.scan.target_manager.get", return_value=target),
            patch("app.api.scan.scan_scheduler.start", return_value=queued_scan) as start,
        ):
            start_scan(request)

        self.assertEqual(
            start.call_args.kwargs["not_applicable_categories"],
            [
                "rag_security",
                "tool_misuse",
                "mcp_security_abuse",
                "external_integration_abuse",
            ],
        )
        self.assertEqual(
            start.call_args.kwargs["requested_categories"],
            [
                "prompt_injection",
                "rag_security",
                "tool_misuse",
                "mcp_security_abuse",
                "external_integration_abuse",
            ],
        )


class RAGMigrationTests(unittest.TestCase):
    def test_migration_from_schema_v5_preserves_authorization_scan_and_finding_records(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        database_url = f"sqlite:///{Path(temp_dir.name, 'schema-v5.sqlite3').as_posix()}"
        target_id = str(uuid4())
        scan_id = str(uuid4())
        finding_id = str(uuid4())
        identity_id = "synthetic-v5-user"
        authorization_test_id = str(uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
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
                    auth_header VARCHAR(100) NOT NULL,
                    system_prompt TEXT,
                    temperature FLOAT NOT NULL,
                    max_output_tokens INTEGER NOT NULL,
                    connection_status VARCHAR(24) NOT NULL,
                    last_tested DATETIME,
                    credential_ciphertext TEXT,
                    active BOOLEAN NOT NULL,
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
                CREATE TABLE synthetic_identities (
                    identity_id VARCHAR(100) PRIMARY KEY,
                    tenant_id VARCHAR(80) NOT NULL,
                    session_id VARCHAR(120) NOT NULL,
                    roles JSON NOT NULL,
                    permissions JSON NOT NULL,
                    identity_data JSON NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE synthetic_resources (
                    resource_id VARCHAR(120) PRIMARY KEY,
                    owner_identity_id VARCHAR(100) NOT NULL,
                    tenant_id VARCHAR(80) NOT NULL,
                    classification VARCHAR(40) NOT NULL,
                    required_permissions JSON NOT NULL,
                    resource_data JSON NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE authorization_test_results (
                    test_id VARCHAR(36) PRIMARY KEY,
                    scenario VARCHAR(80),
                    requesting_identity_id VARCHAR(100) NOT NULL,
                    requested_resource_id VARCHAR(120) NOT NULL,
                    created_at DATETIME NOT NULL,
                    result_data JSON NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at DATETIME NOT NULL
                )
            """))
            capability_profile = {"capabilities": {}}
            connection.execute(text("""
                INSERT INTO targets VALUES (
                    :id, 'Schema V5 target', 'openai_compatible', 'model_endpoint',
                    :capabilities, 'https://api.openai.com/v1/chat/completions',
                    NULL, 'openai', NULL, NULL, 'Authorization', NULL, 0.0, 256,
                    'unknown', NULL, NULL, 1, :created
                )
            """), {
                "id": target_id,
                "capabilities": json.dumps(capability_profile),
                "created": created_at,
            })
            scan_record = {
                "scan_id": scan_id,
                "target_id": target_id,
                "status": "completed",
                "requested_case_count": 1,
            }
            connection.execute(text("""
                INSERT INTO scans VALUES (:id, :target_id, 'completed', :created, NULL, :record)
            """), {
                "id": scan_id,
                "target_id": target_id,
                "created": created_at,
                "record": json.dumps(scan_record),
            })
            finding_data = {"finding_id": finding_id, "evidence": "synthetic historical evidence"}
            connection.execute(text("""
                INSERT INTO findings VALUES (:id, :scan_id, 'case-v5', 'low', 'rag_security', :data)
            """), {
                "id": finding_id,
                "scan_id": scan_id,
                "data": json.dumps(finding_data),
            })
            identity_data = {
                "identity_id": identity_id,
                "display_name": "Synthetic V5 Identity",
                "tenant_id": "tenant-a",
                "roles": ["user"],
                "permissions": [],
                "authentication_status": "authenticated",
                "session_id": "synthetic-session-v5",
                "created_at": created_at,
            }
            connection.execute(text("""
                INSERT INTO synthetic_identities VALUES
                    (:id, 'tenant-a', 'synthetic-session-v5', '["user"]', '[]', :data)
            """), {"id": identity_id, "data": json.dumps(identity_data)})
            resource_data = {
                "resource_id": "synthetic-resource-v5",
                "display_name": "Synthetic V5 Resource",
                "owner_identity_id": identity_id,
                "tenant_id": "tenant-a",
                "classification": "private",
                "required_permissions": ["resource:read:owned"],
            }
            connection.execute(text("""
                INSERT INTO synthetic_resources VALUES
                    ('synthetic-resource-v5', :owner, 'tenant-a', 'private',
                     '["resource:read:owned"]', :data)
            """), {"owner": identity_id, "data": json.dumps(resource_data)})
            authorization_result = {
                "test_id": authorization_test_id,
                "scenario": "horizontal_privilege_escalation",
                "requesting_identity_id": identity_id,
                "context_identity_id": None,
                "requested_resource_id": "synthetic-resource-v5",
                "requested_operation": "read",
                "expected_authorization_result": "insufficient_permissions",
                "actual_authorization_result": "insufficient_permissions",
                "reason": "Synthetic fixture",
                "outcome": "no_issue_observed",
                "created_at": created_at,
            }
            connection.execute(text("""
                INSERT INTO authorization_test_results VALUES
                    (:id, 'horizontal_privilege_escalation', :identity,
                     'synthetic-resource-v5', :created, :data)
            """), {
                "id": authorization_test_id,
                "identity": identity_id,
                "created": created_at,
                "data": json.dumps(authorization_result),
            })
            connection.execute(text(
                "INSERT INTO schema_version VALUES "
                "(1, CURRENT_TIMESTAMP), (2, CURRENT_TIMESTAMP), "
                "(3, CURRENT_TIMESTAMP), (4, CURRENT_TIMESTAMP), (5, CURRENT_TIMESTAMP)"
            ))
        engine.dispose()

        store = Database(database_url)
        self.addCleanup(store.close)
        store.initialize()
        store.initialize()

        self.assertEqual(store.get_target(target_id).name, "Schema V5 target")
        self.assertEqual(store.get_scan(scan_id).status.value, "completed")
        with store.engine.connect() as connection:
            preserved_finding = json.loads(connection.execute(
                text("SELECT finding_data FROM findings WHERE finding_id = :id"),
                {"id": finding_id},
            ).scalar_one())
            versions = set(connection.execute(text("SELECT version FROM schema_version")).scalars())
        self.assertEqual(preserved_finding, finding_data)
        self.assertEqual(store.get_identity(identity_id).identity_id, identity_id)
        self.assertEqual(store.get_authorization_test(authorization_test_id).test_id, authorization_test_id)
        self.assertEqual(versions, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
        self.assertTrue(any(
            document.document_id == "synthetic-rag-document-user-a-private"
            for document in store.list_rag_documents()
        ))


if __name__ == "__main__":
    unittest.main()

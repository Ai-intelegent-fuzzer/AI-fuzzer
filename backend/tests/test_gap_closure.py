import unittest

from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.adapters.manager import TargetManager
from app.adapters.models import TargetCreate, TargetType
from app.analysis.models import AnalysisResult, Confidence, Finding, Severity
from app.database.store import Database
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanRecord, ScanStatus
from app.main import app
from app.vector_store.models import (
    VectorCollectionCreate,
    VectorDocumentCreate,
    VectorDocument,
    VectorSearchRequest,
)
from app.vector_store.service import VectorStoreService
from app.agent_memory.models import (
    MemoryAccessRequest,
    MemoryCreate,
    MemoryScenario,
    MemoryScope,
)
from app.agent_memory.service import AgentMemoryService
from app.authorization.models import Permission, ResourceClassification
from app.web_security.models import WebTestRunRequest, WebTestStatus
from app.web_security.service import LocalWebSecurityFixture


class GapClosureServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Database("sqlite://")
        self.store.initialize()
        self.addCleanup(self.store.close)
        self.vector = VectorStoreService(self.store)
        self.memory = AgentMemoryService(self.store)

    def test_vector_collection_search_filters_and_denials_are_audited(self) -> None:
        self.vector.ensure_default()
        manager_document = self.vector.upsert(
            VectorDocumentCreate(
                collection_id="synthetic-vector-collection-default",
                title="Synthetic Manager Workflow",
                content="[SYNTHETIC] Manager workflow record.",
                owner_identity_id="synthetic-manager",
                tenant_id="tenant-a",
                classification=ResourceClassification.PRIVATE,
                required_permissions=[Permission.READ_OWNED],
                metadata={"group": "manager"},
            ),
            "synthetic-manager",
            "synthetic-session-manager",
        )
        owner = self.vector.search(VectorSearchRequest(
            identity_id="synthetic-manager",
            session_id="synthetic-session-manager",
            query="Manager Workflow",
        ))
        other_user = self.vector.search(VectorSearchRequest(
            identity_id="synthetic-user-a",
            session_id="synthetic-session-user-a",
            query="Manager Workflow",
        ))
        metadata_filtered = self.vector.search(VectorSearchRequest(
            identity_id="synthetic-manager",
            session_id="synthetic-session-manager",
            query="Manager Workflow",
            metadata_filter={"group": "other"},
        ))

        self.assertEqual([item.document.document_id for item in owner.results], [manager_document.document_id])
        self.assertEqual(other_user.results, [])
        self.assertTrue(all(not audit.authorization_decision.value == "allowed" for audit in other_user.audits))
        self.assertEqual(metadata_filtered.results, [])
        self.assertTrue(self.store.list_vector_audits())

    def test_vector_cross_tenant_collection_and_unauthorized_delete_are_denied(self) -> None:
        collection = self.vector.create_collection(
            VectorCollectionCreate(display_name="Synthetic Tenant B Collection", tenant_id="tenant-b"),
            "synthetic-rag-tenant-b-user",
            "synthetic-session-rag-tenant-b-user",
        )
        document = VectorDocument(
            collection_id=collection.collection_id,
            title="Synthetic Tenant B Notes",
            content="[SYNTHETIC] Tenant B restricted notes.",
            owner_identity_id="synthetic-rag-tenant-b-user",
            tenant_id="tenant-b",
            classification=ResourceClassification.TENANT,
            required_permissions=[Permission.READ_TENANT],
        )
        self.store.upsert_vector_document(document)
        denied = self.vector.search(VectorSearchRequest(
            identity_id="synthetic-user-a",
            session_id="synthetic-session-user-a",
            query="Tenant B restricted notes",
            collection_id=collection.collection_id,
        ))
        deleted = self.vector.delete(
            document.document_id,
            "synthetic-user-a",
            "synthetic-session-user-a",
        )

        self.assertEqual(denied.results, [])
        self.assertEqual(denied.audits[0].authorization_decision.value, "tenant_mismatch")
        self.assertFalse(deleted)
        self.assertIsNotNone(self.store.get_vector_document(document.document_id))
        self.assertTrue(any(
            item.collection_id == collection.collection_id and item.tenant_id == "tenant-b"
            for item in self.store.list_vector_collections()
        ))

    def test_agent_memory_owner_tenant_session_and_write_policy(self) -> None:
        self.memory._seed_fixtures()
        owner_request = MemoryAccessRequest(
            identity_id="synthetic-user-a",
            session_id="synthetic-session-user-a",
        )
        other_request = MemoryAccessRequest(
            identity_id="synthetic-user-b",
            session_id="synthetic-session-user-b",
        )
        owner = self.memory.retrieve("synthetic-memory-user-a", owner_request)
        cross_user = self.memory.retrieve("synthetic-memory-user-a", other_request)
        cross_tenant = self.memory.retrieve(
            "synthetic-memory-tenant-b",
            MemoryAccessRequest(
                identity_id="synthetic-user-a",
                session_id="synthetic-session-user-a",
            ),
        )
        session_mismatch = self.memory.retrieve("synthetic-memory-session-a", other_request)
        denied_update = self.memory.update(
            "synthetic-memory-user-a",
            "[SYNTHETIC] unauthorized overwrite",
            other_request,
        )
        denied_delete = self.memory.delete("synthetic-memory-user-a", other_request)

        self.assertIsNotNone(owner.memory)
        self.assertIsNone(cross_user.memory)
        self.assertEqual(cross_user.audit.authorization_decision.value, "insufficient_permissions")
        self.assertIsNone(cross_tenant.memory)
        self.assertEqual(cross_tenant.audit.authorization_decision.value, "tenant_mismatch")
        self.assertIsNone(session_mismatch.memory)
        self.assertIsNone(denied_update.memory)
        self.assertEqual(denied_update.audit.outcome, "denied")
        self.assertEqual(denied_delete.outcome, "denied")
        self.assertTrue(self.store.list_memory_audits())

    def test_agent_memory_creation_enforces_policy_and_expiry_lifecycle(self) -> None:
        manager_request = MemoryAccessRequest(
            identity_id="synthetic-manager",
            session_id="synthetic-session-manager",
        )
        created = self.memory.create(
            MemoryCreate(
                tenant_id="tenant-a",
                scope=MemoryScope.USER,
                classification=ResourceClassification.PRIVATE,
                required_permissions=[Permission.READ_OWNED],
                content="[SYNTHETIC] Manager scoped memory.",
                ttl_seconds=1,
            ),
            manager_request,
        )
        with self.assertRaises(PermissionError):
            self.memory.create(
                MemoryCreate(
                    tenant_id="tenant-a",
                    scope=MemoryScope.USER,
                    classification=ResourceClassification.PRIVATE,
                    required_permissions=[Permission.READ_OWNED],
                    content="[SYNTHETIC] User cannot create protected memory.",
                ),
                MemoryAccessRequest(
                    identity_id="synthetic-user-a",
                    session_id="synthetic-session-user-a",
                ),
            )

        self.assertIsNotNone(created.expires_at)
        self.assertEqual(created.owner_identity_id, "synthetic-manager")
        self.assertTrue(any(audit.operation == "create" for audit in self.store.list_memory_audits()))

    def test_all_memory_scenarios_return_explicit_policy_and_audit(self) -> None:
        for scenario in MemoryScenario:
            with self.subTest(scenario=scenario.value):
                result = self.memory.run_scenario(scenario)
                self.assertEqual(result.scenario, scenario)
                self.assertTrue(result.audit.evidence_reference)
                self.assertTrue(result.audit.provenance.startswith("synthetic_fixture:"))

    def test_web_fixture_reports_known_control_differences_without_network(self) -> None:
        fixture = LocalWebSecurityFixture()
        test_ids = [case.test_id for case in fixture.tests()]
        vulnerable = fixture.run(WebTestRunRequest(
            fixture_id="synthetic-webapp-vulnerable",
            test_ids=test_ids,
        ))
        secure = fixture.run(WebTestRunRequest(
            fixture_id="synthetic-webapp-secure",
            test_ids=test_ids,
        ))

        self.assertTrue(vulnerable.simulated)
        self.assertTrue(all(item.status == WebTestStatus.FAIL for item in vulnerable.results))
        self.assertTrue(all(item.status == WebTestStatus.PASS for item in secure.results))
        self.assertTrue(all(item.evidence_reference for item in vulnerable.results))
        self.assertTrue(all(item.synthetic_request["fixture"].startswith("synthetic-webapp-") for item in vulnerable.results))
        with self.assertRaises(ValueError):
            fixture.run(WebTestRunRequest(
                fixture_id="https://example.com",
                test_ids=[test_ids[0]],
            ))


class GapClosureApiAndMigrationTests(unittest.TestCase):
    def test_local_fixture_apis_are_registered_and_validated(self) -> None:
        client = TestClient(app)
        fixtures = client.get("/web-security/fixtures")
        tests = client.get("/web-security/tests")
        self.assertEqual(fixtures.status_code, 200)
        self.assertEqual(tests.status_code, 200)
        self.assertEqual(len(fixtures.json()), 2)
        run = client.post("/web-security/runs", json={
            "fixture_id": "synthetic-webapp-secure",
            "test_ids": ["web_security_headers"],
        })
        self.assertEqual(run.status_code, 200)
        self.assertEqual(run.json()["results"][0]["status"], "PASS")
        self.assertEqual(client.get("/vector-store/collections").status_code, 200)
        self.assertEqual(client.get("/memories/audits").status_code, 200)
        bad_target = client.post("/web-security/runs", json={
            "fixture_id": "https://example.com",
            "test_ids": ["web_security_headers"],
        })
        self.assertEqual(bad_target.status_code, 422)

    def test_additive_schema_v10_creates_gap_closure_tables_and_preserves_identity(self) -> None:
        store = Database("sqlite://")
        self.addCleanup(store.close)
        store.initialize()
        identity = store.get_identity("synthetic-user-a")
        target = TargetManager(store).create(TargetCreate(
            name="Historical synthetic migration target",
            target_type=TargetType.CHATBOT,
            endpoint="https://api.openai.com/v1/chat/completions",
        ))
        scan = ScanRecord(
            scan_id="synthetic-historical-migration-scan",
            target_id=target.target_id,
            status=ScanStatus.COMPLETED,
            requested_case_count=1,
            generated_case_count=1,
            executed_case_count=1,
            finding_count=1,
        )
        case = FuzzCase(
            case_id="synthetic-historical-migration-case",
            prompt="Synthetic historical migration test.",
            category="prompt_injection",
        )
        finding = Finding(
            finding_id="synthetic-historical-migration-finding",
            case_id=case.case_id,
            target_id=target.target_id,
            scan_id=scan.scan_id,
            category=case.category,
            title="Synthetic historical finding",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence="Synthetic historical evidence.",
            recommendation="Preserve the historical test record.",
        )
        store.save_scan(
            scan,
            ScanCreateRequest(
                target_id=target.target_id,
                authorization_confirmed=True,
                count=1,
            ),
        )
        store.save_generated_cases(scan.scan_id, [case])
        store.save_result(scan.scan_id, {
            "case": case,
            "execution": ExecutionResult(
                target_id=target.target_id,
                case_id=case.case_id,
                scan_id=scan.scan_id,
                status="completed",
                response_body="Synthetic historical response.",
                message="Synthetic historical execution.",
            ),
            "analysis": AnalysisResult(
                target_id=target.target_id,
                case_id=case.case_id,
                scan_id=scan.scan_id,
                category=case.category,
                vulnerable=True,
                findings=[finding],
            ),
        })
        with store.engine.begin() as connection:
            connection.execute(text("DELETE FROM schema_version WHERE version = 10"))
        store.initialize()
        with store.engine.connect() as connection:
            versions = set(connection.execute(text("SELECT version FROM schema_version")).scalars())
        tables = set(inspect(store.engine).get_table_names())

        self.assertEqual(identity.identity_id, store.get_identity("synthetic-user-a").identity_id)
        self.assertEqual(store.get_target(target.target_id).target_id, target.target_id)
        self.assertEqual(store.get_scan(scan.scan_id).status, ScanStatus.COMPLETED)
        self.assertEqual(
            store.get_results(scan.scan_id)[0]["analysis"].findings[0].finding_id,
            finding.finding_id,
        )
        self.assertIn(10, versions)
        self.assertTrue({
            "synthetic_vector_collections",
            "synthetic_vector_documents",
            "synthetic_vector_audits",
            "synthetic_agent_memories",
            "synthetic_agent_memory_audits",
        }.issubset(tables))


if __name__ == "__main__":
    unittest.main()

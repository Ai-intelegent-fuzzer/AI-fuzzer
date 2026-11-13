import json
import unittest
from collections import Counter
from pathlib import Path

from app.authorization.models import AuthorizationDecision, Permission, ResourceClassification
from app.database.store import Database
from app.rag.models import RAGDocumentCreate, RAGRetrievalRequest
from app.rag.service import RAGService


_BENCHMARK_PATH = Path(__file__).parent / "fixtures" / "prompt_injection_benchmark.json"
_EXPECTED_CATEGORIES = {
    "email_based_indirect_injection",
    "web_content_injection",
    "table_and_structured_data_injection",
    "document_and_summarization_injection",
    "code_context_injection",
    "system_prompt_extraction",
    "instruction_hijacking",
    "unauthorized_tool_actions",
    "private_data_disclosure",
}


def _load_cases() -> list[dict[str, str]]:
    return json.loads(_BENCHMARK_PATH.read_text(encoding="utf-8"))


class PromptInjectionBenchmarkOfflineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Database("sqlite://")
        self.store.initialize()
        self.addCleanup(self.store.close)
        self.service = RAGService(self.store)

    def test_test_only_benchmark_has_180_cases_across_nine_categories(self) -> None:
        cases = _load_cases()
        counts = Counter(case["category"] for case in cases)

        self.assertEqual(len(cases), 180)
        self.assertEqual(len({case["case_id"] for case in cases}), 180)
        self.assertEqual(set(counts), _EXPECTED_CATEGORIES)
        self.assertEqual(set(counts.values()), {20})
        self.assertTrue(all(case["prompt"].strip() for case in cases))

    def test_untrusted_benchmark_content_cannot_bypass_synthetic_document_policy(self) -> None:
        cases = _load_cases()

        for case in cases:
            with self.subTest(case_id=case["case_id"]):
                title = f"Synthetic Offline Benchmark {case['case_id']}"
                document = self.service.ingest(RAGDocumentCreate(
                    title=title,
                    content=f"[SYNTHETIC] {case['prompt']}",
                    owner_identity_id="synthetic-admin",
                    tenant_id="tenant-a",
                    classification=ResourceClassification.ADMIN,
                    required_permissions=[Permission.READ_ADMIN],
                    metadata={
                        "dataset": "offline-prompt-injection-benchmark",
                        "category": case["category"],
                    },
                    contains_untrusted_instructions=True,
                ))
                self.assertTrue(document.contains_untrusted_instructions)

                result = self.service.retrieve(RAGRetrievalRequest(
                    identity_id="synthetic-guest",
                    session_id="synthetic-session-guest",
                    query=title,
                    top_k=1,
                    test_case_id=case["case_id"],
                ))

                self.assertEqual(result.documents, [])
                self.assertEqual(len(result.audits), 1)
                audit = result.audits[0]
                self.assertEqual(audit.document_id, document.document_id)
                self.assertEqual(audit.test_case_id, case["case_id"])
                self.assertEqual(
                    audit.authorization_decision,
                    AuthorizationDecision.INSUFFICIENT_PERMISSIONS,
                )
                self.assertFalse(audit.retrieval_decision)
                self.assertEqual(len(audit.sanitized_evidence_reference), 64)
                self.assertNotIn(case["prompt"], json.dumps(audit.model_dump(mode="json")))

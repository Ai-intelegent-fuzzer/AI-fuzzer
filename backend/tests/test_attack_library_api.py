import unittest
from concurrent.futures import Future
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.adapters.models import (
    CapabilityName,
    CapabilityProfile,
    CapabilitySetting,
    CapabilityValidationStatus,
    TargetScope,
)
from app.attacks.capabilities import applicable_categories, category_supported_by_profile
from app.attacks.models import AttackRiskLevel
from app.attacks.registry import attack_registry
from app.fuzzing.engine import fuzz_engine
from app.fuzzing.models import FuzzCase
from app.fuzzing.models import ScanCreateRequest
from app.fuzzing.mutator import prompt_mutator
from app.fuzzing.scheduler import ScanScheduler
from app.main import app


class AttackTaxonomyTests(unittest.TestCase):
    def test_taxonomy_has_required_categories_and_complete_metadata(self) -> None:
        expected = {
            "prompt_injection",
            "jailbreak",
            "system_prompt_extraction",
            "sensitive_information_disclosure",
            "data_leakage",
            "context_manipulation",
            "rag_poisoning",
            "unauthorized_retrieval",
            "rag_cross_tenant_data_leakage",
            "tool_misuse",
            "unauthorized_tool_invocation",
            "mcp_security_abuse",
            "agent_identity_confusion",
            "privilege_escalation",
            "excessive_agency",
            "memory_poisoning",
            "insecure_output_handling",
            "external_integration_abuse",
        }
        self.assertTrue(expected.issubset(set(attack_registry.list_categories())))
        for attack in attack_registry.list_attacks():
            with self.subTest(attack=attack.attack_id):
                self.assertTrue(attack.risk_level)
                self.assertTrue(attack.applicable_target_scopes)
                self.assertTrue(attack.preconditions)
                self.assertTrue(attack.mutation_strategy)
                self.assertTrue(attack.detection_logic)
                self.assertTrue(attack.evidence_requirements)

    def test_capability_filter_blocks_features_from_model_endpoint(self) -> None:
        profile = CapabilityProfile(capabilities={
            capability: CapabilitySetting(
                enabled=True,
                validation_status=CapabilityValidationStatus.CONFIGURED,
            )
            for capability in (
                CapabilityName.RAG_ENABLED,
                CapabilityName.TOOL_CALLING,
                CapabilityName.MCP_ENABLED,
                CapabilityName.AUTHORIZATION_ENABLED,
                CapabilityName.AUTHENTICATION_ENABLED,
                CapabilityName.MULTI_TENANT,
                CapabilityName.AGENT_MEMORY,
                CapabilityName.WEB_APPLICATION,
                CapabilityName.EXTERNAL_INTEGRATIONS,
            )
        })

        self.assertFalse(category_supported_by_profile(
            "rag_security",
            profile,
            TargetScope.MODEL_ENDPOINT,
        ))
        self.assertFalse(category_supported_by_profile(
            "tool_misuse",
            profile,
            TargetScope.MODEL_ENDPOINT,
        ))
        self.assertFalse(category_supported_by_profile(
            "mcp_security_abuse",
            profile,
            TargetScope.MODEL_ENDPOINT,
        ))
        self.assertTrue(category_supported_by_profile(
            "tool_misuse",
            profile,
            TargetScope.AI_APPLICATION,
        ))
        self.assertTrue(category_supported_by_profile(
            "external_integration_abuse",
            profile,
            TargetScope.APPLICATION_INTEGRATION,
        ))

    def test_incomplete_profiles_mark_capability_categories_not_applicable(self) -> None:
        applicable, not_applicable = applicable_categories(
            ["prompt_injection", "rag_security", "mcp_security_abuse"],
            CapabilityProfile(),
            TargetScope.MODEL_ENDPOINT,
        )
        self.assertEqual(applicable, ["prompt_injection"])
        self.assertEqual(not_applicable, ["rag_security", "mcp_security_abuse"])

    def test_scheduler_records_not_applicable_categories_without_generating_them(self) -> None:
        scheduler = ScanScheduler(max_workers=1)
        try:
            request = ScanCreateRequest(
                target_id="synthetic-target",
                count=4,
                categories=[
                    "prompt_injection",
                    "rag_security",
                    "tool_misuse",
                    "mcp_security_abuse",
                ],
            )
            with patch.object(scheduler._executor, "submit", return_value=Future()):
                queued = scheduler.start(
                    request,
                    target_scope=TargetScope.MODEL_ENDPOINT,
                    capability_profile=CapabilityProfile(),
                )
            self.assertEqual(queued.applicable_categories, ["prompt_injection"])
            self.assertEqual(
                queued.not_applicable_categories,
                ["rag_security", "tool_misuse", "mcp_security_abuse"],
            )
            self.assertEqual(
                scheduler._requests[queued.scan_id].categories,
                ["prompt_injection"],
            )
            self.assertEqual(queued.coverage.applicable_categories, ["prompt_injection"])
        finally:
            scheduler._executor.shutdown(wait=True)

    def test_all_mutation_strategies_are_deterministic_and_total_budget_is_respected(self) -> None:
        case = FuzzCase(case_id="synthetic-mutation-case", category="prompt_injection", prompt="Synthetic test prompt.")
        strategy_names = [strategy.name for strategy in prompt_mutator.strategies]
        first = prompt_mutator.mutate(
            case,
            count=len(strategy_names),
            strategy_names=strategy_names,
            max_mutation_depth=1,
        )
        second = prompt_mutator.mutate(
            case,
            count=len(strategy_names),
            strategy_names=strategy_names,
            max_mutation_depth=1,
        )

        self.assertEqual([item.prompt for item in first], [item.prompt for item in second])
        self.assertIn("unicode_mutation", strategy_names)
        self.assertIn("instruction_hierarchy_variation", strategy_names)
        self.assertIn("payload_obfuscation", strategy_names)
        self.assertIn("multi_turn_context_mutation", strategy_names)
        self.assertIn("structured_input_mutation", strategy_names)
        self.assertIn("tool_argument_mutation", strategy_names)
        generated = fuzz_engine.generate(
            count=7,
            categories=["prompt_injection", "jailbreak"],
            max_mutation_depth=5,
            max_mutations_per_case=10,
        )
        self.assertEqual(len(generated), 7)


class AttackLibraryApiTests(unittest.TestCase):
    def test_attack_library_filters_and_previews_applicable_synthetic_cases(self) -> None:
        client = TestClient(app)
        target = client.post("/targets", json={
            "name": "Synthetic model-only preview target",
            "target_type": "openai_compatible",
            "target_scope": "model_endpoint",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "provider": "openai",
        })
        self.assertEqual(target.status_code, 201)
        target_id = target.json()["target_id"]

        categories = client.get("/attacks/categories", params={"target_id": target_id})
        self.assertEqual(categories.status_code, 200)
        category_map = {item["category"]: item for item in categories.json()}
        self.assertTrue(category_map["prompt_injection"]["applicable"])
        self.assertFalse(category_map["rag_security"]["applicable"])

        attacks = client.get(
            "/attacks",
            params={"target_id": target_id, "risk_level": AttackRiskLevel.HIGH.value},
        )
        self.assertEqual(attacks.status_code, 200)
        self.assertTrue(all(item["risk_level"] == "high" for item in attacks.json()))
        self.assertNotIn(
            "rag_security",
            {item["category"] for item in attacks.json()},
        )

        preview = client.post(
            f"/targets/{target_id}/attacks/preview",
            json={
                "categories": ["prompt_injection", "rag_security"],
                "count": 4,
                "max_mutation_depth": 2,
                "max_mutations_per_case": 4,
            },
        )
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.json()["generated_count"], 4)
        self.assertEqual(preview.json()["applicable_categories"], ["prompt_injection"])
        self.assertEqual(preview.json()["not_applicable_categories"], ["rag_security"])
        self.assertTrue(all(item["category"] == "prompt_injection" for item in preview.json()["cases"]))
        self.assertTrue(all(item["metadata"]["required_capabilities"] == [] for item in preview.json()["cases"]))

    def test_attack_details_and_unknown_category_validation(self) -> None:
        client = TestClient(app)
        attack = client.get("/attacks/attack_mcp_security_01")
        self.assertEqual(attack.status_code, 200)
        self.assertEqual(attack.json()["required_capabilities"], ["mcp_enabled"])
        self.assertTrue(attack.json()["evidence_requirements"])

        preview = client.post("/targets/missing/attacks/preview", json={
            "categories": ["unknown_category"],
            "count": 1,
        })
        self.assertEqual(preview.status_code, 404)

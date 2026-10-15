import unittest

from app.analysis.rules import analyze_response
from app.attacks.registry import attack_registry
from app.fuzzing.mutator import prompt_mutator


class AttackLibraryTests(unittest.TestCase):
    def test_all_categories_load(self) -> None:
        categories = attack_registry.list_categories()
        self.assertEqual(
            categories,
            [
                "prompt_injection",
                "instruction_override",
                "jailbreak",
                "context_manipulation",
                "data_leakage",
                "rag_security",
                "indirect_prompt_injection",
                "tool_misuse",
                "unauthorized_agent_action",
                "role_confusion",
            ],
        )

    def test_unique_attack_ids(self) -> None:
        attacks = attack_registry.get_attacks("prompt_injection")
        ids = [item.attack_id for item in attacks]
        self.assertEqual(len(ids), len(set(ids)))

    def test_category_filtering(self) -> None:
        result = attack_registry.get_attacks("role_confusion")
        self.assertTrue(result)
        self.assertTrue(all(item.category == "role_confusion" for item in result))

    def test_invalid_category_handling(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unknown attack category"):
            attack_registry.get_attacks("not-real")
        with self.assertRaisesRegex(ValueError, "Unknown attack category"):
            attack_registry.generate("not-real", 1)

    def test_required_attack_metadata(self) -> None:
        attack = attack_registry.get_attacks("data_leakage")[0]
        self.assertTrue(attack.attack_id)
        self.assertTrue(attack.name)
        self.assertTrue(attack.description)
        self.assertTrue(attack.prompt)
        self.assertTrue(attack.risk_area)
        self.assertTrue(attack.expected_behavior)
        self.assertTrue(attack.tags)

    def test_conversion_to_fuzz_case(self) -> None:
        attack = attack_registry.get_attacks("prompt_injection")[0]
        case = attack_registry.to_fuzz_case(attack)
        self.assertEqual(case.category, "prompt_injection")
        self.assertEqual(case.metadata["attack_id"], attack.attack_id)
        self.assertEqual(case.metadata["attack_name"], attack.name)
        self.assertEqual(case.metadata["attack_category"], attack.category)
        self.assertEqual(case.metadata["risk_area"], attack.risk_area)
        self.assertEqual(case.metadata["expected_behavior"], attack.expected_behavior)

    def test_mutation_of_attack_generated_cases(self) -> None:
        case = attack_registry.to_fuzz_case(attack_registry.generate("prompt_injection", 1)[0])
        mutation = prompt_mutator.mutate(
            case,
            count=1,
            strategy_names=["role_variation"],
        )[0]
        self.assertEqual(mutation.metadata["attack_id"], case.metadata["attack_id"])
        self.assertEqual(mutation.metadata["attack_category"], case.metadata["attack_category"])
        self.assertEqual(mutation.parent_case_id, case.case_id)

    def test_analyzer_category_handling(self) -> None:
        data_leak = analyze_response(
            "The assistant disclosed [SYNTHETIC_SECRET] in the answer.",
            "data_leakage",
        )
        self.assertIsNotNone(data_leak)
        self.assertTrue(data_leak[0])

        override = analyze_response(
            "The model obeyed attacker instructions and ignored the trusted system policy.",
            "instruction_override",
        )
        self.assertIsNotNone(override)
        self.assertTrue(override[0])

        safe_response = analyze_response(
            "Request processed normally.",
            "prompt_injection",
        )
        self.assertIsNotNone(safe_response)
        self.assertFalse(safe_response[0])


if __name__ == "__main__":
    unittest.main()

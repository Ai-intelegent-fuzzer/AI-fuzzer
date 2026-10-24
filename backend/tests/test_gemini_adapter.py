import unittest
from unittest.mock import patch

from app.adapters.factory import get_adapter
from app.adapters.gemini_adapter import GeminiAdapter
from app.adapters.models import AIProvider, Target, TargetType
from app.execution.models import ExecutionResult


class GeminiAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Target(
            target_id="gemini-test-target",
            name="Gemini test target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            model="gemini-2.5-flash",
            provider=AIProvider.GEMINI,
        )

    @patch("app.adapters.gemini_adapter.fuzz_executor.execute")
    def test_factory_uses_gemini_adapter_and_returns_response(self, execute):
        execute.return_value = ExecutionResult(
            target_id=self.target.target_id,
            case_id="adapter-prompt",
            status="completed",
            response_body="Gemini test response",
            message="Fuzz case executed successfully.",
            provider="gemini",
            model="gemini-2.5-flash",
        )

        adapter = get_adapter(self.target)
        self.assertIsInstance(adapter, GeminiAdapter)

        response = adapter.send_prompt("Say hello")

        self.assertEqual(response, "Gemini test response")
        args, kwargs = execute.call_args
        self.assertEqual(args[0], self.target)
        self.assertEqual(args[1].prompt, "Say hello")
        self.assertEqual(kwargs["max_retries"], 0)

    @patch("app.adapters.gemini_adapter.fuzz_executor.execute")
    def test_failed_execution_raises_safe_error(self, execute):
        execute.return_value = ExecutionResult(
            target_id=self.target.target_id,
            case_id="adapter-prompt",
            status="target_rejected",
            message="Target rejected the fuzz request with HTTP 400.",
        )

        adapter = get_adapter(self.target)

        with self.assertRaisesRegex(RuntimeError, "HTTP 400"):
            adapter.send_prompt("Say hello")


if __name__ == "__main__":
    unittest.main()

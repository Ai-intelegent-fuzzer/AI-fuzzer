import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.adapters.models import Target
from app.api.adapter import PromptRequest, PromptResponse, send_prompt


class AdapterPromptApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Target(
            target_id="controlled-target",
            name="Controlled test target",
            target_type="openai_compatible",
            endpoint="https://controlled.test/v1/chat/completions",
            model="synthetic-model",
        )

    @patch("app.api.adapter.get_adapter")
    @patch("app.api.adapter.target_manager.get")
    def test_successful_prompt_response_is_preserved(
        self, get_target, get_adapter
    ) -> None:
        get_target.return_value = self.target
        adapter = Mock()
        adapter.send_prompt.return_value = "synthetic response"
        get_adapter.return_value = adapter

        result = send_prompt(
            "controlled-target",
            PromptRequest(prompt="synthetic prompt"),
        )

        self.assertIsInstance(result, PromptResponse)
        self.assertEqual(result.target_id, "controlled-target")
        self.assertEqual(result.response, "synthetic response")
        adapter.send_prompt.assert_called_once_with("synthetic prompt")

    @patch("app.api.adapter.target_manager.get", return_value=None)
    def test_missing_target_still_returns_404(self, _get_target) -> None:
        with self.assertRaises(HTTPException) as caught:
            send_prompt(
                "missing-target",
                PromptRequest(prompt="synthetic prompt"),
            )

        self.assertEqual(caught.exception.status_code, 404)
        self.assertEqual(caught.exception.detail, "Target not found")

    @patch("app.api.adapter.get_adapter")
    @patch("app.api.adapter.target_manager.get")
    def test_provider_exception_is_sanitized(
        self, get_target, get_adapter
    ) -> None:
        get_target.return_value = self.target
        adapter = Mock()
        adapter.send_prompt.side_effect = RuntimeError(
            "SECRET_API_KEY private prompt and provider internals"
        )
        get_adapter.return_value = adapter

        with self.assertLogs("app.api.adapter", level="ERROR") as captured:
            with self.assertRaises(HTTPException) as caught:
                send_prompt(
                    "controlled-target",
                    PromptRequest(prompt="synthetic prompt"),
                )

        self.assertEqual(caught.exception.status_code, 502)
        self.assertNotIn("SECRET_API_KEY", caught.exception.detail)
        self.assertNotIn("private prompt", caught.exception.detail)
        self.assertNotIn("provider internals", caught.exception.detail)

        logged = "\n".join(captured.output)
        self.assertIn("controlled-target", logged)
        self.assertIn("RuntimeError", logged)
        self.assertNotIn("SECRET_API_KEY", logged)
        self.assertNotIn("synthetic prompt", logged)
        self.assertNotIn("provider internals", logged)


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.adapters.base import AdapterError
from app.adapters.models import Target
from app.execution.models import ExecutionResult
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

    def test_empty_prompt_is_rejected_by_request_validation(self) -> None:
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            PromptRequest(prompt="")

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

    @patch("app.api.adapter.get_adapter")
    @patch("app.api.adapter.target_manager.get")
    def test_configuration_error_is_actionable_without_exposing_credentials(
        self, get_target, get_adapter
    ) -> None:
        get_target.return_value = self.target
        execution = ExecutionResult(
            target_id=self.target.target_id,
            case_id="adapter-prompt",
            status="configuration_error",
            message="Missing GROQ_API_KEY in backend/.env or environment.",
            failure_reason="provider_api_key_missing",
            provider="groq",
        )
        adapter = Mock()
        adapter.send_prompt.side_effect = AdapterError(execution)
        get_adapter.return_value = adapter

        with self.assertLogs("app.api.adapter", level="ERROR") as captured:
            with self.assertRaises(HTTPException) as caught:
                send_prompt(
                    "controlled-target",
                    PromptRequest(prompt="synthetic prompt"),
                )

        self.assertEqual(caught.exception.status_code, 503)
        self.assertIn("GROQ_API_KEY", caught.exception.detail)
        logged = "\n".join(captured.output)
        self.assertIn("provider_api_key_missing", logged)
        self.assertIn("GROQ_API_KEY", logged)
        self.assertNotIn("synthetic prompt", logged)
        self.assertNotIn("test-secret", logged)

    @patch("app.api.adapter.get_adapter")
    @patch("app.api.adapter.target_manager.get")
    def test_rate_limit_and_timeout_have_provider_specific_http_statuses(
        self, get_target, get_adapter
    ) -> None:
        get_target.return_value = self.target
        adapter = Mock()
        get_adapter.return_value = adapter

        for failure_status, expected_http_status in (
            ("rate_limited", 429),
            ("timeout", 504),
        ):
            adapter.send_prompt.side_effect = AdapterError(
                ExecutionResult(
                    target_id=self.target.target_id,
                    case_id="adapter-prompt",
                    status=failure_status,
                    message="Safe provider error.",
                    failure_reason=f"provider_{failure_status}",
                    provider="groq",
                )
            )
            with self.assertRaises(HTTPException) as caught:
                send_prompt(
                    "controlled-target",
                    PromptRequest(prompt="synthetic prompt"),
                )
            self.assertEqual(caught.exception.status_code, expected_http_status)

    @patch("app.api.adapter.target_manager.get")
    def test_unsupported_target_type_returns_validation_error(self, get_target) -> None:
        self.target.target_type = "chatbot"
        get_target.return_value = self.target

        with self.assertRaises(HTTPException) as caught:
            send_prompt(
                "controlled-target",
                PromptRequest(prompt="synthetic prompt"),
            )

        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("Unsupported target type", caught.exception.detail)


if __name__ == "__main__":
    unittest.main()

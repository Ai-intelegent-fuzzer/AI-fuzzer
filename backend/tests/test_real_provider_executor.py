import json
import unittest
from unittest.mock import patch

import httpx

from app.adapters.models import AIProvider, Target, TargetType
from app.execution.executor import FuzzExecutor
from app.fuzzing.models import FuzzCase


class RealProviderExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Target(
            target_id="live-target",
            name="Groq test target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="https://api.groq.com/openai/v1/chat/completions",
            provider=AIProvider.GROQ,
            model="test-model",
        )
        self.case = FuzzCase(
            case_id="case-1",
            prompt="Reply with the word hello.",
            category="prompt_injection",
        )

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret", "GROQ_MODEL": "test-model"})
    @patch("app.execution.executor.httpx.post")
    def test_sends_chat_completion_and_extracts_real_response(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "hello"}}],
                "usage": {"prompt_tokens": 8, "completion_tokens": 1, "total_tokens": 9},
            },
        )
        result = FuzzExecutor().execute(self.target, self.case)
        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-secret")
        self.assertEqual(kwargs["json"]["model"], "test-model")
        self.assertEqual(kwargs["json"]["messages"][0]["content"], self.case.prompt)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "hello")
        self.assertEqual(result.provider, "groq")
        self.assertEqual(result.model, "test-model")
        self.assertEqual(result.total_tokens, 9)
        self.assertNotIn("test-secret", result.model or "")

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_key_returns_safe_configuration_error(self) -> None:
        result = FuzzExecutor().execute(self.target, self.case)
        self.assertEqual(result.status, "configuration_error")
        self.assertNotIn("test-secret", result.message)

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret"})
    def test_missing_model_returns_configuration_error(self) -> None:
        target = self.target.model_copy(update={"model": None})
        result = FuzzExecutor().execute(target, self.case)
        self.assertEqual(result.status, "configuration_error")
        self.assertEqual(result.failure_reason, "provider_model_missing")

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret"})
    @patch("app.execution.executor.httpx.post")
    def test_rate_limit_is_not_a_vulnerability_response(self, post) -> None:
        post.return_value = httpx.Response(429, json={"error": {"message": "quota"}})
        result = FuzzExecutor().execute(self.target, self.case)
        self.assertEqual(result.status, "rate_limited")
        self.assertIsNone(result.response_body)
        self.assertEqual(result.failure_reason, "provider_rate_limited")

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret"})
    @patch("app.execution.executor.httpx.post")
    def test_authentication_failure_does_not_expose_provider_body(self, post) -> None:
        post.return_value = httpx.Response(401, text="credential detail")
        result = FuzzExecutor().execute(self.target, self.case)
        self.assertEqual(result.status, "authentication_error")
        self.assertNotIn("credential detail", result.message)
        self.assertIsNone(result.response_body)

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret"})
    @patch("app.execution.executor.httpx.post")
    def test_malformed_success_response_is_reported(self, post) -> None:
        post.return_value = httpx.Response(200, json={"unexpected": "format"})
        result = FuzzExecutor().execute(self.target, self.case)
        self.assertEqual(result.status, "invalid_response")
        self.assertIsNone(result.response_body)

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret"})
    @patch("app.execution.executor.httpx.post")
    def test_timeout_is_reported_without_secret(self, post) -> None:
        post.side_effect = httpx.TimeoutException("private diagnostic")
        result = FuzzExecutor().execute(self.target, self.case)
        self.assertEqual(result.status, "timeout")
        self.assertNotIn("private diagnostic", result.message)

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-secret"})
    @patch("app.execution.executor.httpx.post")
    def test_openai_provider_uses_openai_key(self, post) -> None:
        target = self.target.model_copy(update={"provider": AIProvider.OPENAI})
        post.return_value = httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
        )
        result = FuzzExecutor().execute(target, self.case)
        self.assertEqual(result.provider, "openai")
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer test-secret")


if __name__ == "__main__":
    unittest.main()

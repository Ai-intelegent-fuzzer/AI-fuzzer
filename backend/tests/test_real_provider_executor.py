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
    def test_provider_response_truncation_is_recorded(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "hello world"}}],
            },
        )

        result = FuzzExecutor().execute(
            self.target,
            self.case,
            response_size_limit=5,
        )

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "hello")
        self.assertTrue(result.response_truncated)

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

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret", "GROQ_MODEL": ""})
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
    def test_unavailable_model_is_reported_without_raw_provider_body(self, post) -> None:
        post.return_value = httpx.Response(404, text="private model diagnostic")
        result = FuzzExecutor().execute(self.target, self.case)
        self.assertEqual(result.status, "target_error")
        self.assertEqual(result.status_code, 404)
        self.assertNotIn("private model diagnostic", result.message)
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

    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret"})
    @patch("app.execution.executor.httpx.post")
    def test_network_error_is_sanitized(self, post) -> None:
        post.side_effect = httpx.ConnectError("private connection details")
        result = FuzzExecutor().execute(self.target, self.case)
        self.assertEqual(result.status, "network_error")
        self.assertNotIn("private connection details", result.message)

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



    def _gemini_target(self):
        return self.target.model_copy(update={
            "provider": AIProvider.GEMINI,
            "model": "gemini-2.5-flash",
            "endpoint": "https://generativelanguage.googleapis.com/v1beta",
        })

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_success_parses_text_usage_and_endpoint(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "candidates": [{
                    "content": {"parts": [{"text": "Gemini says hello"}]}
                }],
                "usageMetadata": {
                    "promptTokenCount": 7,
                    "candidatesTokenCount": 3,
                    "totalTokenCount": 10,
                },
            },
        )

        result = FuzzExecutor().execute(self._gemini_target(), self.case)
        kwargs = post.call_args.kwargs

        self.assertEqual(
            post.call_args.args[0],
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        )
        self.assertEqual(kwargs["headers"]["x-goog-api-key"], "test-gemini-key")
        self.assertEqual(kwargs["json"]["contents"][0]["parts"][0]["text"], self.case.prompt)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.provider, "gemini")
        self.assertEqual(result.response_body, "Gemini says hello")
        self.assertEqual(result.prompt_tokens, 7)
        self.assertEqual(result.completion_tokens, 3)
        self.assertEqual(result.total_tokens, 10)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_endpoint_uses_target_model_when_endpoint_names_another_model(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"candidates": [{
                "content": {"parts": [{"text": "Gemini response"}]}
            }]},
        )
        target = self._gemini_target().model_copy(update={
            "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/old-model:generateContent",
            "model": "gemini-2.5-flash",
        })

        result = FuzzExecutor().execute(target, self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(
            post.call_args.args[0],
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        )

    @patch.dict(
        "os.environ",
        {"GEMINI_API_KEY": "test-gemini-key", "GEMINI_MODEL": "gemini-2.5-flash"},
        clear=True,
    )
    @patch("app.execution.executor.httpx.post")
    def test_gemini_response_truncation_is_recorded(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"candidates": [{
                "content": {"parts": [{"text": "hello world"}]}
            }]},
        )
        result = FuzzExecutor().execute(
            self._gemini_target(), self.case, response_size_limit=5
        )
        self.assertEqual(result.response_body, "hello")
        self.assertTrue(result.response_truncated)

    @patch.dict("os.environ", {}, clear=True)
    def test_gemini_missing_key_returns_safe_configuration_error(self) -> None:
        result = FuzzExecutor().execute(self._gemini_target(), self.case)
        self.assertEqual(result.status, "configuration_error")
        self.assertEqual(result.failure_reason, "provider_api_key_missing")

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_rate_limit_is_handled(self, post) -> None:
        post.return_value = httpx.Response(429, text="private quota details")
        result = FuzzExecutor().execute(self._gemini_target(), self.case)
        self.assertEqual(result.status, "rate_limited")
        self.assertNotIn("private quota details", result.message)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_authentication_error_is_sanitized(self, post) -> None:
        post.return_value = httpx.Response(403, text="private credential details")
        result = FuzzExecutor().execute(self._gemini_target(), self.case)
        self.assertEqual(result.status, "authentication_error")
        self.assertNotIn("private credential details", result.message)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_malformed_response_is_handled(self, post) -> None:
        post.return_value = httpx.Response(200, json={"unexpected": "format"})
        result = FuzzExecutor().execute(self._gemini_target(), self.case)
        self.assertEqual(result.status, "invalid_response")
        self.assertIsNone(result.response_body)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_prompt_safety_block_is_recognized(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"promptFeedback": {"blockReason": "SAFETY"}},
        )

        result = FuzzExecutor().execute(self._gemini_target(), self.case)

        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.failure_reason, "provider_safety_blocked")
        self.assertIsNone(result.response_body)
        self.assertNotIn("test-gemini-key", result.message)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_candidate_safety_finish_reason_is_recognized(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"candidates": [{"finishReason": "SAFETY"}]},
        )

        result = FuzzExecutor().execute(self._gemini_target(), self.case)

        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.failure_reason, "provider_safety_blocked")
        self.assertIsNone(result.response_body)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_non_safety_finish_reason_is_not_classified_as_blocked(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"candidates": [{"finishReason": "MAX_TOKENS"}]},
        )

        result = FuzzExecutor().execute(self._gemini_target(), self.case)

        self.assertEqual(result.status, "invalid_response")
        self.assertEqual(result.failure_reason, "provider_response_malformed")

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_unspecified_block_reason_allows_normal_candidate(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "promptFeedback": {"blockReason": "BLOCK_REASON_UNSPECIFIED"},
                "candidates": [
                    {
                        "content": {"parts": [{"text": "Hello"}]},
                        "finishReason": "STOP",
                    }
                ],
            },
        )

        result = FuzzExecutor().execute(self._gemini_target(), self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "Hello")

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_text_refusal_is_not_a_provider_safety_block(self, post) -> None:
        refusal = "I cannot help with that request."
        post.return_value = httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"parts": [{"text": refusal}]},
                        "finishReason": "STOP",
                    }
                ],
            },
        )

        result = FuzzExecutor().execute(self._gemini_target(), self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, refusal)
        self.assertNotEqual(result.failure_reason, "provider_safety_blocked")

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_empty_candidate_text_is_invalid_response(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "candidates": [{
                    "content": {"parts": [{"text": "   "}]}
                }]
            },
        )

        result = FuzzExecutor().execute(self._gemini_target(), self.case)

        self.assertEqual(result.status, "invalid_response")
        self.assertEqual(result.failure_reason, "provider_response_empty")
        self.assertIsNone(result.response_body)


    @patch.dict("os.environ", {"GROQ_API_KEY": "test-secret", "GROQ_MODEL": "test-model"})
    @patch("app.execution.executor.httpx.post")
    def test_security_test_instruction_is_sent_as_system_message(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"choices": [{"message": {"content": "test response"}}]},
        )
        case = self.case.model_copy(update={
            "metadata": {
                "security_test_system_instruction":
                    "For this controlled test, use marker CANARY-TEST-42."
            }
        })

        result = FuzzExecutor().execute(self.target, case)
        messages = post.call_args.kwargs["json"]["messages"]

        self.assertEqual(result.status, "completed")
        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("CANARY-TEST-42", messages[0]["content"])
        self.assertEqual(messages[-1]["content"], case.prompt)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-gemini-key"}, clear=True)
    @patch("app.execution.executor.httpx.post")
    def test_gemini_security_test_instruction_uses_system_instruction_field(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"candidates": [{
                "content": {"parts": [{"text": "test response"}]}
            }]},
        )
        case = self.case.model_copy(update={
            "metadata": {
                "security_test_system_instruction":
                    "For this controlled test, use marker CANARY-TEST-42."
            }
        })

        result = FuzzExecutor().execute(self._gemini_target(), case)
        payload = post.call_args.kwargs["json"]

        self.assertEqual(result.status, "completed")
        self.assertEqual(
            payload["systemInstruction"]["parts"][0]["text"],
            "For this controlled test, use marker CANARY-TEST-42.",
        )
        self.assertEqual(
            payload["contents"][0]["parts"][0]["text"],
            case.prompt,
        )

if __name__ == "__main__":
    unittest.main()

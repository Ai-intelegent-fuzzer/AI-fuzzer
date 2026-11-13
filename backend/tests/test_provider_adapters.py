import unittest
from unittest.mock import patch

import httpx
from pydantic import SecretStr, ValidationError

from app.adapters.models import AIProvider, Target, TargetCreate, TargetType
from app.execution.executor import FuzzExecutor
from app.fuzzing.models import FuzzCase


class ProviderAdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = FuzzCase(
            case_id="provider-contract",
            prompt="controlled prompt",
            category="prompt_injection",
        )
        self.public_dns = patch(
            "app.adapters.endpoint_policy.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
        )
        self.public_dns.start()
        self.addCleanup(self.public_dns.stop)

    @patch("app.execution.executor.bounded_post")
    def test_anthropic_messages_request_is_normalized(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "controlled answer"}],
                "usage": {"input_tokens": 7, "output_tokens": 3},
            },
        )
        target = Target(
            target_id="anthropic",
            name="Anthropic contract target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="https://api.anthropic.com",
            provider=AIProvider.ANTHROPIC,
            model="claude-test",
            api_key=SecretStr("anthropic-secret"),
            system_prompt="Controlled system instruction",
            max_output_tokens=96,
        )

        result = FuzzExecutor().execute(target, self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "controlled answer")
        self.assertEqual(result.total_tokens, 10)
        self.assertEqual(post.call_args.args[0], "https://api.anthropic.com/v1/messages")
        self.assertEqual(post.call_args.kwargs["headers"]["x-api-key"], "anthropic-secret")
        self.assertEqual(post.call_args.kwargs["json"]["max_tokens"], 96)
        self.assertNotIn("anthropic-secret", repr(result))

    @patch("app.execution.executor.bounded_post")
    def test_ollama_chat_request_allows_explicit_local_endpoint(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": "local controlled answer"},
                "prompt_eval_count": 5,
                "eval_count": 4,
            },
        )
        target = Target(
            target_id="ollama",
            name="Local Ollama contract target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="http://127.0.0.1:11434",
            provider=AIProvider.OLLAMA,
            model="controlled-local-model",
        )

        result = FuzzExecutor().execute(target, self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "local controlled answer")
        self.assertEqual(result.total_tokens, 9)
        self.assertEqual(post.call_args.args[0], "http://127.0.0.1:11434/api/chat")
        self.assertFalse(post.call_args.kwargs["json"]["stream"])

    @patch.dict("os.environ", {"OPENAI_API_KEY": "controlled-openai-key"})
    @patch("app.execution.executor.bounded_post")
    def test_openai_responses_api_uses_distinct_request_and_response_schema(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={
                "output": [{
                    "content": [{"type": "output_text", "text": "responses API answer"}],
                }],
                "usage": {"input_tokens": 11, "output_tokens": 4},
            },
        )
        target = Target(
            target_id="openai-responses",
            name="OpenAI Responses contract target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="https://api.openai.com",
            provider=AIProvider.OPENAI,
            api_path="/v1/responses",
            model="controlled-model",
        )

        result = FuzzExecutor().execute(target, self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "responses API answer")
        self.assertEqual(result.total_tokens, 15)
        self.assertEqual(post.call_args.args[0], "https://api.openai.com/v1/responses")
        self.assertIn("input", post.call_args.kwargs["json"])
        self.assertNotIn("messages", post.call_args.kwargs["json"])

    @patch.dict("os.environ", {"MISTRAL_API_KEY": "controlled-mistral-key"})
    @patch("app.execution.executor.bounded_post")
    def test_mistral_uses_openai_compatible_chat_contract(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"choices": [{"message": {"content": "mistral response"}}]},
        )
        target = Target(
            target_id="mistral",
            name="Mistral contract target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="https://api.mistral.ai/v1",
            provider=AIProvider.MISTRAL,
            model="controlled-model",
        )

        result = FuzzExecutor().execute(target, self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "mistral response")
        self.assertEqual(post.call_args.args[0], "https://api.mistral.ai/v1/chat/completions")

    @patch("app.execution.executor.bounded_post")
    def test_custom_endpoint_uses_configured_auth_header_and_path(self, post) -> None:
        post.return_value = httpx.Response(
            200,
            json={"choices": [{"message": {"content": "custom response"}}]},
        )
        target = Target(
            target_id="custom",
            name="Custom contract target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="https://custom.example.test",
            provider=AIProvider.CUSTOM,
            model="controlled-model",
            api_key=SecretStr("custom-key"),
            api_path="/v1/chat/completions",
            auth_header="X-API-Key",
        )

        result = FuzzExecutor().execute(target, self.case)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.response_body, "custom response")
        self.assertEqual(post.call_args.args[0], "https://custom.example.test/v1/chat/completions")
        self.assertEqual(post.call_args.kwargs["headers"]["X-API-Key"], "custom-key")
        self.assertNotIn("Authorization", post.call_args.kwargs["headers"])

    def test_custom_api_path_rejects_traversal_and_query_parameters(self) -> None:
        common = {
            "name": "Custom endpoint",
            "target_type": TargetType.OPENAI_COMPATIBLE,
            "endpoint": "https://custom.example.test/api",
            "provider": AIProvider.CUSTOM,
            "model": "controlled-model",
        }
        with self.assertRaises(ValidationError):
            TargetCreate(**common, api_path="/v1/../admin")
        with self.assertRaises(ValidationError):
            TargetCreate(**common, api_path="/v1/chat?override=1")

    @patch.dict(
        "os.environ",
        {
            "AI_FUZZER_ALLOW_LOCAL_OLLAMA": "false",
            "AI_FUZZER_ALLOW_PRIVATE_TARGETS": "false",
        },
    )
    def test_local_ollama_requires_explicit_server_policy(self) -> None:
        with self.assertRaises(ValidationError):
            TargetCreate(
                name="Blocked Ollama target",
                target_type=TargetType.OPENAI_COMPATIBLE,
                endpoint="http://127.0.0.1:11434",
                provider=AIProvider.OLLAMA,
                model="controlled-model",
            )


if __name__ == "__main__":
    unittest.main()

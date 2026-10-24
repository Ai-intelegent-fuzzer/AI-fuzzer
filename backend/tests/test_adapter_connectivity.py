import unittest
from unittest.mock import patch

import httpx

from app.adapters.models import Target
from app.adapters.openai_compatible import OpenAICompatibleAdapter
from app.connectivity.models import ConnectivityStatus
from app.connectivity.tester import ConnectivityTester


class AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Target(
            target_id="controlled-target",
            name="Controlled OpenAI-compatible target",
            target_type="openai_compatible",
            endpoint="http://controlled.test/chat",
            model="synthetic-model",
        )
        self.adapter = OpenAICompatibleAdapter(self.target)

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-secret"})
    def test_send_prompt_parses_successful_response(self) -> None:
        response = httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": "synthetic response"}}
                ]
            },
            request=httpx.Request("POST", str(self.target.endpoint)),
        )

        with patch(
            "app.adapters.openai_compatible.httpx.post",
            return_value=response,
        ) as post:
            result = self.adapter.send_prompt("synthetic prompt")

        self.assertEqual(result, "synthetic response")
        self.assertEqual(post.call_args.kwargs["json"]["model"], "synthetic-model")
        self.assertEqual(
            post.call_args.kwargs["json"]["messages"],
            [{"role": "user", "content": "synthetic prompt"}],
        )

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-secret"})
    def test_send_prompt_propagates_http_status_error(self) -> None:
        response = httpx.Response(
            503,
            request=httpx.Request("POST", str(self.target.endpoint)),
        )

        with (
            patch("app.adapters.openai_compatible.httpx.post", return_value=response),
            self.assertRaises(httpx.HTTPStatusError),
        ):
            self.adapter.send_prompt("synthetic prompt")

    @patch.dict("os.environ", {"OPENAI_API_KEY": "test-secret"})
    def test_send_prompt_rejects_malformed_response(self) -> None:
        response = httpx.Response(
            200,
            json={"choices": []},
            request=httpx.Request("POST", str(self.target.endpoint)),
        )

        with (
            patch("app.adapters.openai_compatible.httpx.post", return_value=response),
            self.assertRaises(IndexError),
        ):
            self.adapter.send_prompt("synthetic prompt")


class ConnectivityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Target(
            target_id="controlled-target",
            name="Controlled chatbot target",
            target_type="chatbot",
            endpoint="http://controlled.test/chat",
        )
        self.tester = ConnectivityTester()
        self.real_client = httpx.Client

    def _client_patch(self, handler):
        return patch(
            "app.connectivity.tester.httpx.Client",
            side_effect=lambda **kwargs: self.real_client(
                transport=httpx.MockTransport(handler),
                **kwargs,
            ),
        )

    def test_test_reports_reachable_response(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="synthetic", request=request)

        with self._client_patch(handler):
            result = self.tester.test(self.target)

        self.assertEqual(result.status, ConnectivityStatus.REACHABLE)
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.response_time_ms)

    def test_test_reports_timeout(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("synthetic timeout", request=request)

        with self._client_patch(handler):
            result = self.tester.test(self.target)

        self.assertEqual(result.status, ConnectivityStatus.TIMEOUT)
        self.assertEqual(result.target_id, self.target.target_id)

    def test_test_reports_network_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("synthetic connection failure", request=request)

        with self._client_patch(handler):
            result = self.tester.test(self.target)

        self.assertEqual(result.status, ConnectivityStatus.ERROR)
        self.assertIn("connect", result.message.lower())


class GeminiConnectivityTests(unittest.TestCase):
    def setUp(self) -> None:
        from app.adapters.models import AIProvider, TargetType

        self.target = Target(
            target_id="gemini-connectivity-target",
            name="Gemini connectivity target",
            target_type=TargetType.OPENAI_COMPATIBLE,
            endpoint="https://generativelanguage.googleapis.com/v1beta",
            model="gemini-2.5-flash",
            provider=AIProvider.GEMINI,
        )
        self.tester = ConnectivityTester()

    @patch("app.connectivity.tester.fuzz_executor.execute")
    def test_gemini_connectivity_uses_authenticated_execution(self, execute) -> None:
        from app.execution.models import ExecutionResult

        execute.return_value = ExecutionResult(
            target_id=self.target.target_id,
            case_id="connectivity-check",
            status="completed",
            status_code=200,
            response_time_ms=42.0,
            response_body="AI-Fuzzer connectivity OK",
            message="Real Gemini inference completed.",
            provider="gemini",
            model="gemini-2.5-flash",
        )

        result = self.tester.test(self.target)

        self.assertEqual(result.status, ConnectivityStatus.REACHABLE)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.target_id, self.target.target_id)
        execute.assert_called_once()
        args, kwargs = execute.call_args
        self.assertEqual(args[0], self.target)
        self.assertEqual(args[1].category, "connectivity_check")
        self.assertEqual(kwargs["timeout_seconds"], 30.0)
        self.assertEqual(kwargs["max_retries"], 0)

    @patch("app.connectivity.tester.fuzz_executor.execute")
    def test_gemini_connectivity_reports_authentication_failure(self, execute) -> None:
        from app.execution.models import ExecutionResult

        execute.return_value = ExecutionResult(
            target_id=self.target.target_id,
            case_id="connectivity-check",
            status="authentication_error",
            message="Gemini rejected the API credentials or access.",
            failure_reason="provider_authentication_failed",
        )

        result = self.tester.test(self.target)

        self.assertEqual(result.status, ConnectivityStatus.ERROR)
        self.assertEqual(result.target_id, self.target.target_id)
        self.assertIn("authentication_error", result.message)
        self.assertNotIn("API key", result.message)


if __name__ == "__main__":
    unittest.main()

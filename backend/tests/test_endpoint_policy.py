import os
import unittest
from unittest.mock import patch

import httpcore
import httpx
from pydantic import ValidationError

from app.adapters.endpoint_policy import (
    _PinnedNetworkBackend,
    ResponseTooLargeError,
    UnsafeTargetEndpointError,
    bounded_post,
    validate_target_endpoint,
)
from app.adapters.models import TargetCreate


class EndpointPolicyTests(unittest.TestCase):
    def _target_data(self, endpoint: str) -> dict[str, str]:
        return {
            "name": "Controlled endpoint test",
            "target_type": "openai_compatible",
            "provider": "groq",
            "endpoint": endpoint,
            "model": "synthetic-model",
        }

    def test_non_local_http_provider_endpoint_is_rejected(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValidationError):
                TargetCreate(**self._target_data(
                    "http://api.groq.com/openai/v1/chat/completions"
                ))

    def test_private_ip_and_embedded_credentials_are_rejected(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValidationError):
                TargetCreate(**self._target_data(
                    "https://127.0.0.1/v1/chat/completions"
                ))
            with self.assertRaises(ValidationError):
                TargetCreate(**self._target_data(
                    "https://user:password@api.groq.com/openai/v1/chat/completions"
                ))

    def test_non_official_provider_host_requires_explicit_allowlist(self) -> None:
        endpoint = "https://provider.example/v1/chat/completions"
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValidationError):
                TargetCreate(**self._target_data(endpoint))

        with patch.dict(
            os.environ,
            {"AI_FUZZER_ALLOWED_PROVIDER_HOSTS": "provider.example"},
            clear=True,
        ):
            target = TargetCreate(**self._target_data(endpoint))

        self.assertEqual(str(target.endpoint), endpoint)

    def test_private_dns_resolution_is_rejected_at_request_time(self) -> None:
        private_result = (
            2,
            1,
            6,
            "",
            ("10.0.0.8", 443),
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "app.adapters.endpoint_policy.socket.getaddrinfo",
                return_value=[private_result],
            ),
        ):
            with self.assertRaisesRegex(
                UnsafeTargetEndpointError,
                "private or reserved address",
            ):
                validate_target_endpoint("https://provider.example")

    def test_local_http_targets_require_explicit_development_mode(self) -> None:
        endpoint = "http://127.0.0.1:8080/chat"
        with patch.dict(
            os.environ,
            {"AI_FUZZER_ALLOW_PRIVATE_TARGETS": "true"},
            clear=True,
        ):
            target = TargetCreate(
                name="Local controlled target",
                target_type="chatbot",
                endpoint=endpoint,
            )

        self.assertEqual(str(target.endpoint), endpoint)

    def test_connection_backend_pins_the_validated_public_address(self) -> None:
        with (
            patch(
                "app.adapters.endpoint_policy.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
            ),
            patch(
                "httpcore.SyncBackend.connect_tcp",
                return_value="controlled-stream",
            ) as connect_tcp,
        ):
            backend = _PinnedNetworkBackend(
                allow_private=False,
                allow_local_ollama=False,
            )
            result = backend.connect_tcp("provider.example", 443)

        self.assertEqual(result, "controlled-stream")
        self.assertEqual(connect_tcp.call_args.args[0], "8.8.8.8")

    def test_connection_backend_rejects_private_dns_rebinding(self) -> None:
        with (
            patch(
                "app.adapters.endpoint_policy.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("10.0.0.8", 443))],
            ),
            patch("httpcore.SyncBackend.connect_tcp") as connect_tcp,
        ):
            backend = _PinnedNetworkBackend(
                allow_private=False,
                allow_local_ollama=False,
            )
            with self.assertRaises(httpcore.ConnectError):
                backend.connect_tcp("provider.example", 443)

        connect_tcp.assert_not_called()

    def test_provider_response_limit_is_enforced_during_streaming(self) -> None:
        def handler(request):
            return httpx.Response(200, content=b"0123456789", request=request)

        with patch(
            "app.adapters.endpoint_policy.PinnedHTTPTransport",
            return_value=httpx.MockTransport(handler),
        ):
            with self.assertRaises(ResponseTooLargeError):
                bounded_post(
                    "https://provider.example/v1/chat/completions",
                    headers={"Content-Type": "application/json"},
                    json={"model": "controlled", "messages": []},
                    timeout=1,
                    response_size_limit=4,
                )

    def test_provider_redirects_are_not_followed(self) -> None:
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(
                302,
                headers={"Location": "https://redirect.example/"},
                request=request,
            )

        with patch(
            "app.adapters.endpoint_policy.PinnedHTTPTransport",
            return_value=httpx.MockTransport(handler),
        ):
            response = bounded_post(
                "https://provider.example/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                json={"model": "controlled", "messages": []},
                timeout=1,
                response_size_limit=128,
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()

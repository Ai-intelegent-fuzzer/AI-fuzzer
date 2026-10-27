import os
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from app.adapters.endpoint_policy import (
    UnsafeTargetEndpointError,
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


if __name__ == "__main__":
    unittest.main()

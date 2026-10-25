import os

from app.adapters.base import AIAdapter
from app.adapters.provider_security import bounded_post, validate_provider_endpoint


class OpenAICompatibleAdapter(AIAdapter):

    def send_prompt(self, prompt: str) -> str:
        provider = self.target.provider.value
        try:
            validate_provider_endpoint(provider, str(self.target.endpoint))
        except ValueError:
            raise RuntimeError(
                "Provider endpoint must use the official HTTPS API host and route."
            ) from None

        env_name = f"{provider.upper()}_API_KEY"
        api_key = os.getenv(env_name)

        if not api_key:
            raise RuntimeError(
                f"Missing {env_name}. Configure it in backend/.env "
                "and restart the backend."
            )

        payload = {
            "model": self.target.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        response = bounded_post(
            str(self.target.endpoint),
            json=payload,
            headers=headers,
            timeout=30.0,
        )
        if response.extensions.get("ai_fuzzer_response_too_large"):
            raise RuntimeError("Provider response exceeded the configured safety limit.")
        if 300 <= response.status_code < 400:
            raise RuntimeError("Provider redirects are not followed.")

        response.raise_for_status()

        data = response.json()
        return data["choices"][0]["message"]["content"]

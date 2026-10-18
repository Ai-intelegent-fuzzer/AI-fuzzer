import os

import httpx

from app.adapters.base import AIAdapter


class OpenAICompatibleAdapter(AIAdapter):

    def send_prompt(self, prompt: str) -> str:
        provider = self.target.provider.value
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

        response = httpx.post(
            str(self.target.endpoint),
            json=payload,
            headers=headers,
            timeout=30.0,
        )

        response.raise_for_status()

        data = response.json()
        return data["choices"][0]["message"]["content"]

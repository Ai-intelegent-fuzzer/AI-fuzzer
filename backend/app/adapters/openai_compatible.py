import httpx

from app.adapters.base import AIAdapter


class OpenAICompatibleAdapter(AIAdapter):

    def send_prompt(self, prompt: str) -> str:

        payload = {
            "model": self.target.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        headers = {
            "Content-Type": "application/json"
        }

        response = httpx.post(
            str(self.target.endpoint),
            json=payload,
            headers=headers,
            timeout=30.0
        )

        response.raise_for_status()

        data = response.json()

        return data["choices"][0]["message"]["content"]

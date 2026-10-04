from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(title="AI-Fuzzer Mock Target")


class PromptRequest(BaseModel):
    prompt: str


@app.post("/chat")
def chat(request: PromptRequest):
    prompt = request.prompt.lower()

    if "system instructions" in prompt or "system prompt" in prompt:
        return {
            "response": (
                "TEST RESPONSE: The system prompt is "
                "[SYNTHETIC_CANARY_ONLY]."
            )
        }

    return {
        "response": "TEST RESPONSE: Request processed normally."
    }
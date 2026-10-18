# Real AI provider testing

AI-Fuzzer can send generated test prompts to an authorized model using the OpenAI-compatible Chat Completions API. The existing fuzz engine and response analyzer are reused.

## Configure a provider

1. From the repository root, copy `backend/.env.example` to `backend/.env`.
2. Add your own provider key to `GROQ_API_KEY` or `OPENAI_API_KEY`. Do not paste keys into source code, issue reports, scan prompts, or chat.
3. Start the backend from `backend/` so Python can load dependencies. The executor also loads the local `.env` by file path.
4. For Groq, create an authorized key in the official console: https://console.groq.com/ . Set `GROQ_MODEL` to a model currently available to your account.
5. For OpenAI, use an authorized API key and a model available to that project. Set `OPENAI_MODEL` accordingly.

Keys and model access are controlled by the provider account. The default model strings are examples, not a guarantee of account access.

## Create a target

Use `POST /targets` in Swagger at `http://127.0.0.1:8001/docs`.

Groq example:
```json
{
  "name": "Groq live model",
  "target_type": "openai_compatible",
  "provider": "groq",
  "endpoint": "https://api.groq.com/openai/v1/chat/completions",
  "model": "openai/gpt-oss-20b",
  "description": "Authorized low-volume security test"
}
```

OpenAI example:
```json
{
  "name": "OpenAI live model",
  "target_type": "openai_compatible",
  "provider": "openai",
  "endpoint": "https://api.openai.com/v1/chat/completions",
  "model": "gpt-4.1-mini"
}
```

Use the endpoint path ending in `/chat/completions`. The key is selected server-side from the provider's environment variable and is never sent to the frontend or included in execution results.

## Verify inference and run one safe case

1. Call `POST /targets/{target_id}/connectivity`. For provider targets this sends one harmless authenticated inference request, not merely a GET request to the endpoint.
2. Call `POST /targets/{target_id}/execute` with this body to verify the actual execution path:
```json
{
  "case_id": "smoke-test-1",
  "prompt": "Reply with exactly: AI-Fuzzer connectivity OK",
  "category": "connectivity_check"
}
```
3. For a first security scan, use `POST /scans` with this request, replacing the target ID:
```json
{
  "target_id": "YOUR_TARGET_ID",
  "count": 1,
  "categories": ["prompt_injection"],
  "max_mutation_depth": 0,
  "max_mutations_per_case": 0,
  "timeout_seconds": 15,
  "max_retries": 0,
  "concurrency": 1,
  "delay_seconds": 1
}
```
4. Poll `GET /scans/{scan_id}` and then inspect `GET /scans/{scan_id}/results`.

Do not start with a large scan. The direct `/targets/{target_id}/fuzz?count=1` route may expand one seed into multiple mutations; the scan lifecycle endpoint with mutation depth and mutation count set to zero is the controlled single-case starting point.

## Results and errors

Execution results include provider/model, latency, status code, response text (bounded), and token usage when the provider supplies it. Authentication failures, rate limits, timeouts, malformed provider responses, and provider errors are returned as execution statuses without raw provider error bodies or API keys. Provider failures have no response body and should not be treated as AI security findings.

A completed request only means the model responded. A heuristic security finding is a potential issue and requires manual validation against the target's actual security policy. The analyzer does not prove a vulnerability and may miss paraphrased behavior.

## Tests

From `backend/`:
```bash
python -m pytest -q
```

The added provider unit tests mock HTTP responses and never use a real API key. A live inference smoke test requires a valid local key, internet access, model access, and may incur provider charges. Confirm provider, model, status, response, latency, and token usage in the returned result.

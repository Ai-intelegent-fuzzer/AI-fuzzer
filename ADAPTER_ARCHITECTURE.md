# Adapter Architecture

`AIAdapter` provides provider/model identity and a common `execute_case()` entry point. The fuzzing orchestrator selects an adapter through `get_adapter()` and receives the shared `ExecutionResult` schema, so case generation, execution persistence, and analysis remain provider-independent.

Provider-specific request handling lives in the execution layer:

- OpenAI-compatible chat completions are shared by OpenAI, Groq, Mistral, and configured custom endpoints.
- OpenAI Responses uses its distinct request and output parsing shape when the configured URL ends in `/responses`.
- Gemini uses native `generateContent` request/response normalization.
- Anthropic uses the Messages API and native token usage fields.
- Ollama uses its native `/api/chat` shape and local endpoint policy.
- Existing chatbot, RAG, and agent HTTP target types retain their generic JSON-prompt execution path.

Credentials are represented as `SecretStr`, encrypted by the persistence repository using `AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY`, and excluded from API serialization. Provider responses are normalized to status, response body, elapsed time, and available token usage before existing analysis runs. Provider errors are sanitized into stable status/failure-reason values.

Provider-specific HTTP contracts must be covered by mocked contract tests. Mocked tests are not evidence of live provider compatibility. Request timeouts and disabled redirects are enforced. Provider responses are streamed with a byte limit. Outbound connections pin a validated DNS address using an httpcore transport hook; revalidate this version-sensitive hook when upgrading HTTPX/httpcore. Generic target responses are also size-limited.

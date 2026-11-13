# Provider Support

Provider compatibility is implemented through the shared `AIAdapter` contract and the common execution result model. Automated tests use controlled HTTP responses and do not establish live-service compatibility. On 2026-11-04, a single benign Groq request to the configured model returned HTTP 200 and usage metadata but no usable text; it is not counted as successful live verification. No live security scan was run. No OpenAI key was configured.

| Provider | API integration | Current contract-test evidence | Live provider verified |
|---|---|---|---|
| OpenAI | Chat Completions; Responses when `/responses` is configured | Mocked executor tests | No |
| Groq | OpenAI-compatible Chat Completions | Mocked executor tests; one live HTTP 200 response had empty text | No |
| Google Gemini | Native `generateContent` | Mocked Gemini tests | No |
| Anthropic Claude | Native Messages API | Mocked Messages contract test | No |
| Mistral AI | OpenAI-compatible Chat Completions | Mocked Chat Completions contract test | No |
| Ollama | Native `/api/chat` | Mocked local endpoint contract test | No |
| Custom endpoint | Configurable OpenAI-compatible Chat Completions | Mocked auth/path contract test | No |

All adapters return normalized execution status, response content, latency, and token counts when the provider supplies them. A provider response is analyzed only after a successful inference response; configuration, authentication, rate-limit, timeout, malformed-response, and transport failures are not treated as findings.

## Security behavior

- Provider credentials are encrypted server-side with Fernet before database persistence. API responses omit credential fields.
- Requests use the selected target's credential; one target's credential is never forwarded to another provider.
- Provider endpoints are checked against the configured provider host policy. Custom endpoints are subject to the outbound endpoint policy.
- Redirect following is disabled.
- Local Ollama is accepted only when the target provider is `ollama` and `AI_FUZZER_ALLOW_LOCAL_OLLAMA=true`.
- Private targets can otherwise be enabled globally with `AI_FUZZER_ALLOW_PRIVATE_TARGETS=true`; this should only be used in a controlled environment.

## Contract test scope

The backend tests exercise normalized response parsing and representative success/error behavior with mock HTTP responses. The suite does not contact paid services, verify account entitlement, or guarantee that a provider has not changed its external contract. Validate a provider against an account and model that you control before production use.

See [PROVIDER_CONFIGURATION.md](./PROVIDER_CONFIGURATION.md) for setup and [ADAPTER_ARCHITECTURE.md](./ADAPTER_ARCHITECTURE.md) for implementation details.

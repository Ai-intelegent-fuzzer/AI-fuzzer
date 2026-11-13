# Provider Configuration

## Configure credentials

Credentials are submitted to FastAPI over the application's configured transport, encrypted before they are stored in SQLite, and never returned in target API responses. The frontend keeps the credential only in the form state while editing; it does not persist it in local storage.

Set a stable Fernet key in the backend environment before saving target credentials:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the generated value as `AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY`. Keep it outside source control. Losing or rotating this key without re-encrypting the database makes stored provider credentials unavailable.

Optional server-side environment credential fallback variables are:

- `OPENAI_API_KEY`, `OPENAI_MODEL`
- `GROQ_API_KEY`, `GROQ_MODEL`
- `GEMINI_API_KEY`, `GEMINI_MODEL`
- `ANTHROPIC_API_KEY`
- `MISTRAL_API_KEY`, `MISTRAL_MODEL`
- `CUSTOM_API_KEY`, `CUSTOM_MODEL`

An API key entered for a target is preferred over that provider's environment fallback.

## Database configuration

The default SQLite file is stored outside the repository at `%LOCALAPPDATA%\\AI-Fuzzer\\ai_fuzzer.sqlite3`. Override it with `AI_FUZZER_DB_PATH`, or supply a SQLAlchemy URL through `AI_FUZZER_DATABASE_URL`. Tables are initialized on startup.

## Provider endpoint and path

The target form configures provider, endpoint, model, optional API path, system prompt, temperature, and maximum output tokens.

- OpenAI, Groq, and Mistral accept a full request URL; an endpoint ending in `/v1` defaults to `/chat/completions`.
- OpenAI Responses can be selected with an API path such as `/v1/responses`.
- Gemini uses its native `generateContent` API. Configure the provider's model and endpoint as required by the deployment.
- Anthropic defaults to `/v1/messages` (or `/messages` when the endpoint already ends in `/v1`).
- Ollama defaults to `/api/chat`; select provider `ollama` and explicitly enable `AI_FUZZER_ALLOW_LOCAL_OLLAMA=true` to use a loopback endpoint.
- Custom endpoints use the configured API path and authentication header with OpenAI-compatible Chat Completions request/response semantics.

Use only target systems you own or are explicitly authorized to assess. Endpoint allowlists and private-network controls are enforced by the backend, not by browser validation.

# AI-Fuzzer

AI-Fuzzer is a web application for authorized, controlled security assessments of AI endpoints. It configures provider targets, submits category-scoped test prompts, records real endpoint responses, analyzes them with heuristic behavioral rules, persists scan evidence, and creates printable assessment reports.

> Only assess targets that you own or are explicitly authorized to test. Findings are heuristic response evidence and require human review. A clean run is not proof that a system is secure.

## Architecture

- **Backend:** FastAPI, Pydantic, SQLAlchemy, SQLite, HTTPX; source under `backend/app`.
- **Frontend:** React, TypeScript, Vite; source under `AI-Fuzzer/frontend`.
- **Provider execution:** shared adapter contract plus normalized provider execution results. See [ADAPTER_ARCHITECTURE.md](./ADAPTER_ARCHITECTURE.md).
- **Persistence:** SQLite stores targets, encrypted provider credentials, scans/configurations, test cases, execution and analysis data, findings, and reports.
- **Provider information:** implementation and contract-test status are in [PROVIDER_SUPPORT.md](./PROVIDER_SUPPORT.md).

## Supported provider adapters

The app implements OpenAI Chat Completions and Responses, Groq Chat Completions, Gemini `generateContent`, Anthropic Messages, Mistral Chat Completions, Ollama `/api/chat`, and configurable OpenAI-compatible endpoints. Automated contracts use mocked HTTP responses. **No live provider compatibility is claimed unless separately verified against a controlled account and model.**

Live verification on 2026-11-04: one benign request to Groq using the configured `openai/gpt-oss-20b` model returned HTTP 200 and usage metadata, but the adapter received no usable text. This confirms endpoint reachability only, not successful Groq compatibility. No security scan was run against a live provider; no OpenAI credential was configured.

## Windows setup

Use two PowerShell terminals from the repository root.

### Backend

```powershell
cd D:\AI-fuzzer-1\backend
..\.venv\Scripts\python.exe -m pip install -r requirements.txt
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If the root virtual environment is not present, create it from the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

Then start the API from `backend`:

```powershell
cd D:\AI-fuzzer-1\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API health endpoint is `http://127.0.0.1:8000/health`; OpenAPI docs are at `http://127.0.0.1:8000/docs`.

### Frontend

```powershell
cd D:\AI-fuzzer-1\AI-Fuzzer\frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open **http://127.0.0.1:5173**. Vite proxies `/api` requests to `http://localhost:8000`. Set `VITE_BACKEND_PROXY_TARGET` if your backend listens elsewhere.

## Environment and secret configuration

Set `AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY` before saving provider API keys. Generate a Fernet key with:

```powershell
cd D:\AI-fuzzer-1
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store it in the backend process environment or a local ignored backend environment file. Do not commit the key. Losing or rotating it without re-encrypting the database makes stored credentials unreadable.

Database configuration:

- Default: `%LOCALAPPDATA%\AI-Fuzzer\ai_fuzzer.sqlite3`, outside the repository.
- Override file path with `AI_FUZZER_DB_PATH`.
- Override with SQLAlchemy URL using `AI_FUZZER_DATABASE_URL`.
- Existing tables are retained; startup applies safe additive column migrations and creates missing tables.

Remote endpoints require HTTPS and pass the server endpoint allowlist/private-address checks. The local Ollama exception requires `AI_FUZZER_ALLOW_LOCAL_OLLAMA=true` and provider `ollama`. Do not enable broad private-target access in a production environment.

Full provider endpoint, model, and credential details are in [PROVIDER_CONFIGURATION.md](./PROVIDER_CONFIGURATION.md).

## Use the application

1. Open **Targets**, add a target, choose its provider, endpoint, model, and supported parameters.
2. Enter an API key in the password field. The key is sent to the backend for encrypted storage; it is never returned in API responses or persisted in browser storage.
3. Use **Test Connection** to run a harmless inference request. Confirm authorization before connectivity testing.
4. Open **New Scan**, select the authorized target and categories, configure test count/timeout/rate delay, and confirm authorization.
5. Follow the scan status and actual returned test-case responses in **Scan Details**. Running scans refresh automatically; cancellation is available while active.
6. Review findings and their supporting analyzer evidence from **Findings**.
7. Open a report from **Reports**. Reports are generated from recorded scan data, persisted, and can be exported as JSON/HTML or printed. Choose **Save as PDF** in the browser's print dialog to create a PDF.

API key updates and deletion are available from the target configuration. The backend omits credentials from target models and never includes credentials in report data.

## Reports and interpretation

Reports include assessment scope, authorization statement, methodology, executed categories, scan statistics, severity distribution, evidence-backed findings, a deterministic severity/confidence risk score, remediation, conclusion, and limitations. Evidence is sanitized for common credential formats and the configured target key. A zero-finding report explicitly states that no vulnerability was detected by the executed tests and does not claim that the target is secure.

Browser PDF output uses the print stylesheet and the browser's **Save as PDF** destination; this application does not silently generate a PDF file in the background. Reports can also be exported as standalone HTML and JSON.

## Tests and checks

Backend, from the `backend` directory:

```powershell
..\.venv\Scripts\python.exe -m pytest -q
```

Frontend, from `AI-Fuzzer\frontend`:

```powershell
npm test
npm run lint
npm run build
```

The controlled backend end-to-end test starts a temporary loopback-only HTTP mock target and exercises target creation, connectivity, scan execution, analysis, findings, and report retrieval. Provider contract tests use mocked responses and do not contact paid providers. Frontend tests cover API schema mapping and the authorized new-scan workflow.

## Known limitations

- The Groq live check returned HTTP 200 but no usable answer text; Groq and all other providers remain unverified for successful inference.
- The analyzer uses category-scoped behavioral heuristics. Findings need human triage and do not establish external impact.
- Provider responses are streamed with a configured byte limit, redirects and environment proxies are disabled, and outbound connections pin a validated DNS address. The pinning uses an httpcore transport hook and should be revalidated when upgrading HTTPX/httpcore.
- Comparative multi-provider suite execution and aggregate comparison UI are not implemented.
- PDF creation is delegated to the browser's print-to-PDF workflow; the frontend provides a print action, not server-side PDF rendering.
- API-key validation against the provider occurs when a connection test is run; a target can be saved before credentials are provided.

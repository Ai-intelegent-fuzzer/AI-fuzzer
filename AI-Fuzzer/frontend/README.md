# AI-Fuzzer Frontend

React, TypeScript, and Vite dashboard for viewing AI-Fuzzer backend health, registered targets, and scan results. The current integration is deliberately **read-only**: it does not register/delete targets, test connectivity, create/cancel scans, or send prompts to configured targets.

## Prerequisites

- Node.js 22+ with npm 10+
- Python 3.10+ for the FastAPI backend

## Install

From `AI-Fuzzer/frontend`:

```powershell
npm ci
Copy-Item .env.example .env.local
```

`.env.local` is ignored by Git. Leave `VITE_API_BASE_URL` empty for the local Vite proxy, or set it to the backend origin for a deployment that has an appropriate same-origin proxy or restricted CORS configuration. Never put provider credentials in Vite environment variables; frontend variables are public to browser users.

## Start locally

Start the backend in one PowerShell terminal:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Verify health at `http://127.0.0.1:8000/health`. FastAPI's generated OpenAPI and Swagger UI are available at `/openapi.json` and `/docs`.

In a second terminal:

```powershell
Set-Location AI-Fuzzer\frontend
npm ci
npm run dev
```

The local Vite proxy exposes backend reads under `/api/health`, `/api/targets`, and `/api/scans/...`, rewriting the `/api` prefix before forwarding. For those recognized route families, non-GET requests receive HTTP 405. The React app's routes (for example `/scans/new`) are separate from this `/api` prefix. For a deployed frontend, configure a same-origin reverse proxy for `/api` or set `VITE_API_BASE_URL` to the backend origin and have the backend owner configure CORS for the exact frontend origin; do not use wildcard origins with credentials.

## Current FastAPI integration

The centralized TypeScript service calls these existing backend routes using GET:

- `GET /health` — backend status.
- `GET /targets` and `GET /targets/{target_id}` — target inventory and report metadata.
- `GET /scans/{scan_id}` and `GET /scans/{scan_id}/results` — scan status, metrics, and result records.

There is no backend route to list scans or reports. Scan lookup, findings, and report views therefore require a known scan ID. The scan detail page refreshes active status from the backend and stops when the status is terminal. API errors, network/timeouts, and response-schema mismatches are shown rather than replaced with mock data.

The integration is read-only. It does not call `POST /targets`, `DELETE /targets/{target_id}`, `POST /targets/{target_id}/connectivity`, `POST /targets/{target_id}/prompt`, `POST /targets/{target_id}/execute`, `POST /targets/{target_id}/fuzz`, `POST /targets/{target_id}/fuzz-cases`, `POST /targets/{target_id}/attack-cases`, `POST /scans`, or `POST /scans/{scan_id}/cancel`. Those routes can modify backend state, contact configured targets, or initiate/cancel scans. The local Vite proxy rejects non-GET requests for the recognized `/api` route families listed above.

## Provider credentials

Health, targets, and existing scan results do not require a provider key. If backend-only provider configuration is needed for an independently authorized workflow, copy `backend/.env.example` to `backend/.env` and set `GROQ_API_KEY` or `OPENAI_API_KEY` there. The backend also reads `GROQ_MODEL` and `OPENAI_MODEL`. Keep `backend/.env` local, never paste keys into chat or frontend settings, and do not commit it. The frontend does not use or receive these values.

## View existing data

- Dashboard: backend health and current registered-target count.
- Targets: actual target ID, provider/model, type, and endpoint host (credentials, URL path, and query are not displayed).
- Scan History: enter an existing scan ID. The backend has no scan-list API, and scan state is held in memory.
- Findings: enter a scan ID to inspect findings in that scan's result records. Analyzer output is not proof of a vulnerability; manually validate conclusions.
- Reports: enter a scan ID to view and export a JSON report assembled from the returned scan and result data. Print / Save PDF uses the browser print dialog.

Scan IDs and targets disappear when the backend process restarts because the backend currently stores them in process memory. The UI shows errors rather than substituting demo data. Scan creation/cancellation, connectivity checks, and target mutations remain disabled in this read-only integration.

## Troubleshooting

- **Backend unavailable / network error:** confirm the backend is listening on `127.0.0.1:8000`, then retry from the page.
- **CORS error in a deployed frontend:** set up a same-origin reverse proxy or a backend CORS allowlist for the exact frontend origin. The local Vite proxy is development-only.
- **404 for target or scan:** backend state is in-memory; the ID may be invalid or the backend may have restarted.
- **Malformed response:** compare the endpoint's response with the generated OpenAPI schema at `/openapi.json`; the UI intentionally reports schema mismatches.
- **Provider errors:** the read-only frontend does not call providers. If another authorized backend workflow reports provider errors, check the locally configured provider variable/model and backend logs without sharing credentials.

## Validation

```powershell
npm run lint
npm run build
npm test
```

# AI-Fuzzer End-to-End Test Report

> Historical baseline report dated 2026-10-28. Its findings describe the repository before the current API integration, SQLite persistence, reporting, and provider-adapter changes; they are not the current verification result. Current checks: backend 147 passed plus 15 subtests, frontend 6 passed, lint/build passed, and a loopback mock-server scan-to-report workflow passed. No live paid-provider request was made.

**Test date:** 2026-10-28  
**Branch:** `feature/target-adapters-analysis`  
**Commit:** `f83fcf8b32607e8bf8e2ffc74bffc74c932b46a6`  
**Base:** `main`  
**Scope:** Backend/API scan lifecycle, local mock targets, frontend build and rendered routes, provider/endpoint policy regressions, and deployment risks.

## Executive result

**The backend local scan workflow passed end to end against controlled loopback fixtures. The complete application workflow did not pass:** the React pages are mock-backed rather than connected to the backend, browser-to-backend requests fail CORS, and the backend has neither a database nor report-generation endpoints. No paid provider request or third-party target was used.

No product-code change was necessary to complete the safe tests. The only new file is this report. Existing application and user changes were preserved.

## Environment and startup

| Component | Observed environment |
|---|---|
| OS | Windows |
| Python | 3.13.3; repository virtual environment `D:\AI-fuzzer-1\.venv\Scripts\python.exe` |
| Backend packages | FastAPI 0.142.2, httpx 0.28.1, Pydantic 2.13.5 |
| Frontend | Node v22.14.0, npm 11.2.0, Vite 8.3.0; dependencies already installed |
| Branch/worktree | `feature/target-adapters-analysis`; clean before adding this report |

Commands and actual startup outcomes:

1. **PASS — documented backend startup and health**
   - Command from `backend/`: `..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001`
   - `GET /health` returned `200 {"status":"healthy"}`; `GET /` returned `200` with running status; OpenAPI returned `200`.
2. **PASS — isolated E2E backend**
   - Same Uvicorn command on loopback port `8006`, with `AI_FUZZER_ALLOW_PRIVATE_TARGETS=true` set only in that process to allow the controlled local mock target. This override bypasses normal endpoint restrictions and must not be used on a network-exposed service.
3. **PASS — local AI mock**
   - `..\.venv\Scripts\python.exe -m uvicorn tests.fixtures.mock_target:app --host 127.0.0.1 --port 8765`
4. **PASS — Vite frontend**
   - The initial `npm run dev -- --host 127.0.0.1 --port 5173` attempt failed because the installed npm/Vite CLI parsed the arguments as unused positional arguments.
   - Corrected invocation: `node .\node_modules\vite\bin\vite.js --host 127.0.0.1 --port 5173`. Vite reported ready and served the application.
5. **PASS — malformed-response fixture**
   - A temporary HTTP server bound only to `127.0.0.1:8766` returned an intentionally malformed JSON body for one normalization test. It was not a public or third-party target.

All processes started for this test were stopped afterward. The application stores targets, scans, and results in process memory; identifiers below will not resolve after the test backend exits.

## Baseline checks

| Command/check | Result | Actual outcome |
|---|---|---|
| `..\.venv\Scripts\python.exe -m pytest -q` from `backend/` | **PASS** | 127 passed, 15 subtests passed. |
| `..\.venv\Scripts\python.exe -m compileall -q app tests` from `backend/` | **PASS** | Exit 0. |
| `npm run lint` from `AI-Fuzzer\frontend` | **PASS** | Exit 0. |
| `npm run build` from `AI-Fuzzer\frontend` | **PASS, WARNING** | TypeScript project build and Vite production build succeeded. Vite emitted a 699.36 kB minified chunk warning (500 kB advisory threshold). |
| Frontend unit tests | **NOT IMPLEMENTED** | `package.json` has no test script or frontend test runner. |
| Separate type-check command | **PASS via build** | `npm run build` runs `tsc -b` before Vite. |
| Backend OpenAPI | **PASS** | Schema serialized; 14 API paths. |
| Provider network calls | **NOT RUN** | No Groq, OpenAI, Gemini, or other paid API request was made. Existing provider tests use mocks. |

## Actual backend workflow

The backend exposes `/health`, target routes, prompt/execute/connectivity routes, legacy fuzz routes, and scan lifecycle routes. The observed OpenAPI schema has no `/reports` route.

| Step | Result | Evidence |
|---|---|---|
| Health and route discovery | **PASS** | E2E backend health returned healthy; OpenAPI had 14 paths. |
| Required-field validation | **PASS** | Incomplete `POST /targets` returned 422. Unsupported provider value returned 422. |
| Create local target | **PASS** | `POST /targets` returned 201; target `52820144-3b22-4bc5-a68d-1380a5556c22` appeared in `GET /targets`. Target type was `chatbot`, endpoint was the local fixture only. |
| Connectivity | **PASS, limited** | Connectivity returned `reachable`. The generic connectivity path uses GET; the fixture only accepts POST and returned HTTP 405. This proves an HTTP service answered, not that its inference POST contract works. |
| Canary scan / implemented detector | **PASS** | Scan `29799a92-4470-42e5-86a5-692b689e19e4` moved through `queued → running → completed`, generated/executed one case, and the existing analyzer produced one `controlled_data_disclosure` finding with High severity. |
| Finding traceability | **PASS** | Finding `9d84fb6b-fdce-59e6-8a01-12537c56327f` linked to the scan, case, and target and contained detection rationale, indicator metadata, and reproducibility lineage. The synthetic canary was redacted in evidence. |
| Repeated scan isolation | **PASS** | Repeat scan `3a795e90-4200-4baa-97bb-0bdb3d4babdd` produced its own finding; result scan IDs did not cross-link between scans. |
| Normal/no-finding scan | **PASS** | Scan `f541c9fd-d422-48d6-b76e-d6eeea0fa345` completed successfully with zero findings and inconclusive analysis. |
| Timeout / unreachable target | **PASS** | Scan `8bcadf8c-0b1f-47bf-b7dd-d146e9856bdb` completed as a scan record with one execution error; its execution status was `timeout`, analysis was inconclusive, and no finding was created. |
| Malformed target output | **PASS, with limitation** | Scan `f6a6a0e3-df64-4cf7-aea3-dc5bfcf12d4f` received HTTP 200 with a malformed JSON body. The generic chatbot executor preserved it as raw response text, marked execution completed, and analysis was inconclusive with zero findings; no exception occurred. This adapter does not validate JSON response schemas. |
| Direct execute | **PASS** | `POST /targets/{target_id}/execute` returned 200 and a normalized completed result against the local fixture. |
| Empty/zero-case scan | **PASS — rejected by validation** | `POST /scans` with `count: 0` returned 422. Zero-case scans are not supported. |
| Report generation/retrieval | **NOT IMPLEMENTED** | `GET /reports` and `/reports/export` returned 404; no backend report routes or persistence exist. |
| Database consistency | **NOT IMPLEMENTED** | `backend/app/database/` contains no database implementation; targets/scans/results are in-memory dictionaries. No durable database records or cross-restart state can be verified. |

No raw provider credentials, authorization headers, or real secrets were used or printed. The positive finding was intentionally based on the fixture’s synthetic marker and an existing category-scoped detector, not a real target.

## Frontend route checks and backend integration

**PASS — UI pages render:** Vite served `/dashboard`, `/findings`, `/reports`, and `/reports/RPT-0084` in the browser. The findings table and report details rendered.

**FAIL — frontend/backend integration:** The tested UI imports `mockAppService` / `mockData`; Dashboard, Targets, New Scan, Findings, and Reports are backed by local synthetic data rather than these API responses. There is no configured `VITE_*` API base URL or backend API client. The UI’s displayed scan/finding/report data did not include the live E2E scan.

**FAIL — browser CORS probe:** From origin `http://127.0.0.1:5173`, a browser `fetch` to `http://127.0.0.1:8006/health` was blocked because FastAPI returned no `Access-Control-Allow-Origin` header. The app currently does not use this API from the frontend; integration requires both an API client/base URL and an explicit CORS policy.

The frontend report page displays demo report cards and export controls. These are not generated from the live scan, and cannot be treated as a successful backend report export.

## Adapter and endpoint safety

**PASS — offline regression coverage:** The full backend suite includes mocked Groq/OpenAI/Gemini provider selection, response parsing, missing credentials, status errors, timeout, malformed provider payloads, and endpoint-policy cases. No provider API was called.

**PASS — endpoint policy regression tests:** Existing tests cover rejection of non-HTTPS provider URLs, private addresses by default, embedded credentials, non-official provider hosts without allowlisting, and private DNS results. The E2E backend’s explicit private-target override was limited to localhost fixtures.

**LIMITATION — SSRF/DNS rebinding:** Runtime DNS is checked before outbound HTTP, redirects are disabled, but resolved IPs are not pinned to the connection. `AI_FUZZER_ALLOW_PRIVATE_TARGETS=true` bypasses private-address and provider-host restrictions; this must remain disabled outside isolated local testing. This is not proof of complete SSRF protection.

## Security and reliability findings

Confidence describes evidence for the implementation weakness; each risk’s exploitability depends on deployment exposure and configuration.

| ID | Severity | Confidence | Finding and evidence | Preconditions / impact | Status and recommended action |
|---|---|---:|---|---|---|
| E2E-01 | **High, conditional** | 9/10 | Scan submission has no authentication dependency and `ScanScheduler.start` submits each request to a fixed-size `ThreadPoolExecutor` without a global admission cap (`backend/app/api/scan.py`, `backend/app/fuzzing/scheduler.py`). This test successfully created scans without credentials. | If network-reachable, unauthenticated callers can queue work without bound, consume memory/workers, and incur provider usage. Individual scan limits do not bound aggregate queue size. | **Unfixed.** Add authentication/authorization, rate limits, bounded queue admission, quotas, and controlled overload responses before network exposure. |
| E2E-02 | **High, conditional** | 8/10 | Target, prompt, execute, and scan APIs have no authentication/ownership dependencies. Provider targets normally restrict hosts, but the explicit private-target override bypasses that restriction (`backend/app/adapters/endpoint_policy.py`). | If exposed with provider credentials and the override enabled (or unsafe custom host allowlisting), a caller can direct credentialed requests to a caller-controlled endpoint. | **Partially mitigated by default policy; not eliminated.** Keep the override off in deployment, restrict allowed hosts, add auth, and enforce outbound egress policy. |
| E2E-03 | **Medium** | 9/10 | DNS addresses are validated before the HTTP request but are not pinned; the HTTP client resolves the name again. Redirect following is disabled (`backend/app/adapters/endpoint_policy.py`, `backend/app/execution/executor.py`). | A changing DNS response could make the actual connection differ from the checked address. | **Unfixed limitation.** Use an egress proxy/firewall or connection-level destination validation/pinning. No rebinding attempt was made. |
| E2E-04 | **Medium / product integration** | 10/10 | Browser fetch to backend failed CORS; UI pages use `mockAppService` / `mockData` instead of backend calls (`AI-Fuzzer/frontend/src/services/mockApi.ts`, `AI-Fuzzer/frontend/src/pages/FindingsPage.tsx`). | Real backend scans are not visible in dashboard/findings pages. | **Not implemented.** Add a real API client, configured base URL, CORS allowlist, and contract/error tests. |
| E2E-05 | **Medium / product completeness** | 10/10 | No report API or report-generation implementation exists; `/reports` returned 404. UI reports are synthetic demo records. No database implementation exists. | No durable report/finding/scan history; state is lost on backend restart; UI exports do not represent the live API scan. | **Not implemented.** Add persistence and a backend report/export workflow before claiming live reporting. |
| E2E-06 | **Low** | 9/10 | The generic chatbot executor accepts arbitrary 2xx response text as completed, including malformed JSON, and does not validate response shape. | A target-specific JSON contract violation can be counted as a successful execution, though analysis returned inconclusive in this test. | **Observed and documented; not changed.** Define response contracts per target type if structured validation is required. |

No Critical issue was demonstrated. No destructive tests, public targets, private internal services, or external provider calls were made.

## Failures, fixes, and limitations

- **No application-code defect was changed during this run.** The offline suite and local scan path passed. The larger gaps (frontend integration, authentication, queue admission, persistence, and report generation) require product/design work and were not replaced with test-only behavior.
- The first Vite startup attempt used an argument form rejected by npm/Vite; the direct Vite invocation succeeded.
- The first PowerShell HTTP checks encountered response-parsing/tooling errors; equivalent backend and fixture reachability checks succeeded using the working local test client/curl checks.
- Browser-to-backend CORS was intentionally probed and failed as described above; the app currently remains mock-backed.
- Frontend tests are unavailable because no frontend test runner is configured.
- The scan and target IDs above are safe local identifiers but are process-local. They are for this execution record only; they cannot be retrieved after shutdown.
- The backend startup command binds to loopback. Do not expose this unauthenticated service through a public interface or reverse proxy.

## Reproduction

From separate terminals, use only loopback fixtures:

```powershell
# Terminal 1: from backend/
..\.venv\Scripts\python.exe -m uvicorn tests.fixtures.mock_target:app --host 127.0.0.1 --port 8765

# Terminal 2: from backend/; private target mode is ONLY for the localhost fixture
$env:AI_FUZZER_ALLOW_PRIVATE_TARGETS = "true"
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8006
```

Create a target via `POST http://127.0.0.1:8006/targets`:

```json
{
  "name": "Local deterministic E2E mock",
  "target_type": "chatbot",
  "endpoint": "http://127.0.0.1:8765/chat"
}
```

Then submit one synthetic detector case to `POST /scans` (replace the target ID):

```json
{
  "target_id": "TARGET_ID",
  "count": 1,
  "categories": ["prompt_injection"],
  "max_mutation_depth": 0,
  "max_mutations_per_case": 0,
  "timeout_seconds": 5,
  "max_retries": 0,
  "concurrency": 1
}
```

Poll `GET /scans/{scan_id}` until terminal, then retrieve `GET /scans/{scan_id}/results`. The fixture’s existing system-prompt canary response exercises the implemented synthetic-canary detector. Do not use the private-target override on a network-exposed backend or with untrusted users.

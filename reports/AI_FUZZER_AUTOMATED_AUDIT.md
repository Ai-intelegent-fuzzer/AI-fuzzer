# AI-Fuzzer Automated Audit

**Audit date:** 2026-10-27
**Scope:** Repository backend, provider adapters, scan and analysis paths, tracked frontend, configuration, tests, and Git secret hygiene.

## 1. Executive summary

The Groq prompt failure was consistent with a missing provider key in the running Uvicorn process. In the pre-audit Groq/OpenAI-compatible adapter, a missing provider key raised `RuntimeError`; the prompt API discarded its message and returned a generic 502. That matches the observed exception type. The exact historical process environment is no longer observable, so whether it was started before the `.env` loader change cannot be proven. The current absolute-path dotenv load was verified, and one short, harmless prompt through the patched backend and Groq succeeded.

The prompt adapter now uses the same executor as fuzz and connectivity requests. Provider configuration errors are actionable without including secret values; provider rate limits, timeouts, malformed responses, unsupported target types, and other upstream failures have distinct safe API handling. Exception text is no longer copied into generic execution results or scan failure records.

No Critical issue was demonstrated. The target/API integration now rejects non-HTTPS and private destinations by default, restricts provider endpoints to official hosts (or an explicit trusted-host allowlist), rechecks DNS before requests, and does not follow redirects. This materially reduces provider-key egress risk, but DNS results are not pinned to the HTTP connection, so DNS rebinding and unsafe operator allowlists remain residual concerns. One **High**, deployment-conditional risk remains: unauthenticated scan submissions can grow an unbounded in-memory work queue and incur provider usage. The supplied startup command binds to loopback, reducing remote exposure while that deployment choice is preserved.

The analyzer is a bounded heuristic response matcher, not proof of exploitability. Tool-use and agent-action detections are response-claim-only; the code does not execute tools. RAG checks use synthetic prompts, not a RAG connector or corpus. The tracked frontend uses a mock service, and the backend has no report-generation/export endpoints.

## 2. Groq integration root cause

### Verified path and diagnosis

1. `POST /targets` stores the provider and endpoint in a process-local `TargetManager`.
2. The factory dispatches `openai_compatible` Groq targets to `OpenAICompatibleAdapter`.
3. Before this audit, the prompt adapter had its own direct HTTP/error path, separate from the shared executor used by fuzz and connectivity operations.
4. The pre-audit adapter raised `RuntimeError` when the selected provider key was absent. Its API route logged only the exception type and mapped every exception to 502. The observed `RuntimeError` therefore points to the missing-key branch; an upstream HTTP status failure would instead be an `httpx.HTTPStatusError`.
5. The current startup loads `backend/.env` using a path derived from `main.py`, and the executor also loads the file using a path derived from its module. Importing `app.main` in a fresh process confirmed that the Groq key is present without displaying its value.
6. Targets are held only in memory. An empty target list after a restart is expected; the target must be recreated.

The exact environment of the earlier Uvicorn process cannot be recovered. The likely operational cause was that the process handling the request did not have `GROQ_API_KEY` loaded when the request arrived (for example, because it had not restarted after the dotenv change). The current code responds with an explicit configuration status rather than hiding that condition behind a generic 502.

The configured Groq URL, `https://api.groq.com/openai/v1/chat/completions`, is a Chat Completions endpoint and is used with the OpenAI-compatible payload. The model remains target-configurable and falls back to `GROQ_MODEL`. Selecting Groq reads `GROQ_API_KEY`; it does not require `OPENAI_API_KEY`.

### Smoke test

**PASS — one live request.** The patched backend was started on `127.0.0.1:8002`, a fresh Groq target was created, and one short harmless prompt was sent through `/targets/{target_id}/prompt`. The response matched the requested marker (24 characters). No key, authorization header, target identifier, or response text was printed. The temporary server was stopped afterward. This request may incur normal provider usage.

## 3. Changes made

- Unified OpenAI-compatible prompt requests with the existing executor so provider selection, credentials, configured model fallback, timeout, response size cap, parsing, and upstream error statuses use one path.
- Added a typed adapter failure carrying the executor's already-sanitized result. The prompt API now maps missing configuration to 503, provider rate limiting to 429, timeout to 504, other provider errors to 502, and unsupported target types to 422.
- Added safe provider error logging with provider, safe failure category, and actionable configuration message; prompts and credential values are not logged.
- Applied the same typed provider error path to Gemini adapter failures.
- Replaced raw exception text in generic target execution and asynchronous scan failures with safe messages; unexpected connectivity failures are logged by type without logging exception text.
- Added endpoint policy validation at target creation and again before outbound requests, with HTTPS/public-address defaults, provider-host restrictions, explicit local-development opt-in, DNS checks, and redirect disabling. DNS rebinding is not fully mitigated because checked addresses are not pinned to the HTTP connection.
- Added scan-ID propagation into execution results, analysis results, and findings; findings now have deterministic IDs within a target/scan/case/category/indicator set, timestamps, descriptions, detection rationale, and reproducibility lineage.
- Bounded analysis input and redacted configured canaries and common API-key patterns in evidence and matched-text metadata.
- Added minimum-length validation for prompt requests.
- Added regression coverage for provider selection, model fallback, missing configuration, provider status/error handling, malformed responses, timeout, unsupported targets, prompt validation, sanitized exception handling, and in-memory target lifecycle.
- Updated provider setup documentation with startup, restart, and in-memory target/scan behavior.

The existing dotenv loader in `backend/app/main.py` was verified and left unchanged. Existing `.env.example` edits were preserved, with the new endpoint-policy options added.

## 4. Tests and validation

| Check | Result | Notes |
|---|---|---|
| Full backend suite | **PASS** | 127 passed, 15 subtests passed. Run from `backend/` with `python -m pytest -q`. |
| Provider-focused tests | **PASS** | Groq/OpenAI selection, configured model fallback, missing key, 401, 404, 429, 5xx, timeout, network failure, malformed success body, response parsing and sanitization. |
| Adapter/API and target-manager tests | **PASS** | Prompt success/error mapping, unsupported target, target create/list/get/delete and process-local state. |
| Scan lifecycle and analyzer tests | **PASS** | Included in the full test suite; scan linkage, redaction, bounded input, and exception-text regressions are covered. |
| Endpoint policy tests | **PASS** | Private/local destinations, non-HTTPS endpoints, provider-host allowlisting, and private DNS resolution are covered. |
| Python syntax/import check | **PASS** | `python -m compileall -q app tests`. |
| OpenAPI generation | **PASS** | JSON-serializable schema; 14 paths, including prompt and scan routes. |
| Uvicorn startup and health | **PASS** | Fresh instance started on loopback port 8003; `/health` returned `{"status":"healthy"}` and the temporary process was stopped. |
| Frontend production build | **PASS with warning** | `npm run build` in `AI-Fuzzer/frontend`; Vite reports a minified JavaScript chunk above 500 kB. |
| Frontend lint | **PASS** | `npm run lint` in `AI-Fuzzer/frontend`. |
| Frontend tests | **NOT CONFIGURED** | The tracked frontend package has no test script or frontend test suite. |
| Git secret scan | **PASS** | No likely API-key patterns found in the changed source, tests, or report; `backend/.env` is ignored and not tracked. No secret values were displayed. |
| `git diff --check` | **PASS** | No whitespace errors. |
| Initial pytest from repository root | **FAIL — invocation context** | Collection could not import `app`; rerunning from the documented `backend/` directory passed. This was not a test assertion failure. |

## 5. Critical and high-risk findings

No Critical finding was supported by the evidence collected. One **High** risk remains: unbounded unauthenticated scan submission. The provider-credential egress issue is mitigated by the endpoint policy but retained below as a reduced **Medium** residual risk due to DNS rebinding, optional host allowlisting, and the unsafe private-target override.

Keep the backend bound to loopback until authentication, authorization, and queue admission controls are implemented. Do not enable `AI_FUZZER_ALLOW_PRIVATE_TARGETS` on a network-exposed service or with provider credentials configured.

## 6. Full prioritized findings

Confidence is the confidence in the finding, not the likelihood of an exploit in a deployment.

| ID | Severity | Confidence | Finding, evidence, and reproduction | Impact and preconditions | Recommended remediation | Fixed / regression |
|---|---|---:|---|---|---|---|
| AF-02 | High | 9/10 | **Unbounded scan queue and request volume.** [`ScanScheduler`](../backend/app/fuzzing/scheduler.py#L20) uses a fixed worker pool and [`start`](../backend/app/fuzzing/scheduler.py#L41) submits each request without an admission cap. [`POST /scans`](../backend/app/api/scan.py#L47) has no auth dependency. Per-scan parameters are individually capped (up to 100 cases, concurrency 8, timeout 120 seconds) in [`ScanCreateRequest`](../backend/app/fuzzing/models.py#L45), but the total number of queued scans is not capped. | An unauthenticated network caller can exhaust memory/worker slots and consume model quota. Requires network exposure; current loopback startup restricts remote callers. | Add authentication, rate limiting, a bounded queue and per-user quotas; reject overload with 429/503; set an overall execution/time budget and provider spend limit. | **Not fixed.** No queue-cap behavior is defined. |
| AF-01 | Medium | 8/10 | **Residual provider credential egress via unsafe endpoint configuration or DNS rebinding.** [`TargetCreate`](../backend/app/adapters/models.py#L20) validates target endpoints with [`validate_target_endpoint`](../backend/app/adapters/endpoint_policy.py#L28); provider hosts are restricted to official hostnames or the explicit `AI_FUZZER_ALLOWED_PROVIDER_HOSTS` setting. [`FuzzExecutor.execute`](../backend/app/execution/executor.py#L42) rechecks DNS before requests and disables redirects. However, the checked IP is not pinned to the subsequent HTTP connection, and `AI_FUZZER_ALLOW_PRIVATE_TARGETS=true` bypasses these restrictions. DNS rebinding and unsafe deployment configuration were not dynamically exploited. | A network-reachable API with provider credentials could still leak them if the private-target override is enabled, an unsafe host is allowlisted, or DNS changes between validation and connection. | Keep the private-target override disabled outside isolated development; minimize trusted hosts; enforce outbound network policy with an egress proxy/firewall that blocks internal and metadata destinations; pin/validate actual connection destinations. | **Partially mitigated.** Endpoint-policy tests cover default rejection, allowlisting, and private DNS results; no connection pinning exists. |
| AF-03 | Medium | 9/10 | **Heuristic findings do not establish exploitability.** [`_RULES`](../backend/app/analysis/rules.py#L63) and [`_collect_indicators`](../backend/app/analysis/rules.py#L333) match response text; [`calculate_severity`](../backend/app/analysis/rules.py#L420) assigns High for selected response indicators. Tool/action indicators explicitly record `response_claim_only` and `external_impact_verified: false` at [`rules.py`](../backend/app/analysis/rules.py#L359). | Paraphrased behavior can be missed, while quoted or self-descriptive language can still create misleading findings. Tool-use, action execution, and real data exposure are not verified. | Keep findings labeled heuristic, require human validation for High/Critical, add evidence fixtures for quoted/refusal/claim cases, and integrate observable tool/action instrumentation only for authorized mock targets. | **Not fixed.** Existing analyzer tests test text rules, not external target ground truth. |
| AF-04 | Informational | 10/10 | **Frontend and reporting are not integrated with the backend.** The tracked UI imports [`mockAppService`](../AI-Fuzzer/frontend/src/services/mockApi.ts#L50); the connection check explicitly says it is mock-only at [`mockApi.ts`](../AI-Fuzzer/frontend/src/services/mockApi.ts#L94). The backend registers no report router in [`main.py`](../backend/app/main.py#L38), and `backend/app/reports/` has no implementation. | Dashboard, findings, scan history, and reports shown by the UI are synthetic demo state, not backend results. This is a product-completeness issue, not a demonstrated security exploit. | Clearly label demo data in deployment; implement a real API service and backend report/export endpoints before claiming end-to-end operation. | **Not fixed.** Frontend remains intentionally mock-backed. |
| AF-05 | Low | 10/10 | **Targets and scans are process-local.** [`TargetManager`](../backend/app/adapters/manager.py#L6) stores targets in a dict; [`ScanScheduler`](../backend/app/fuzzing/scheduler.py#L22) stores scans/results in process dictionaries. The added manager regression test confirms a new manager has no earlier targets. | Restart loses target IDs, scans, and results; a restart during execution loses state. This is documented behavior but harms continuity. | Use a durable database and explicit retention/backup policy before production use. | **Documented, not fixed.** [`REAL_PROVIDER_SETUP.md`](../backend/REAL_PROVIDER_SETUP.md) now explains restart behavior. |
| AF-06 | Medium | 8/10 | **Raw unexpected exception text could expose sensitive request details.** Previously, generic target execution copied exception text into `ExecutionResult`, and scheduler failures copied it into `ScanRecord.failure_reason`. The generic execution path is now sanitized at [`executor.py`](../backend/app/execution/executor.py#L105); scan errors are sanitized at [`scheduler.py`](../backend/app/fuzzing/scheduler.py#L122). | A transport/library exception could include URL details or data derived from a request and then be returned from execution or scan APIs. | Continue returning stable safe error codes; send detailed diagnostics only to a protected redacting log sink. | **Fixed.** Regression tests assert that synthetic secret/prompt text is absent from execution results and scan errors. |
| AF-07 | Medium | 9/10 | **Provider configuration failures were opaque 502s.** The earlier adapter raised `RuntimeError` for a missing provider key; the prompt API logged only its type and returned a generic 502. The shared executor returns a safe configuration result at [`executor.py`](../backend/app/execution/executor.py#L460), and [`send_prompt`](../backend/app/api/adapter.py#L45) now logs the actionable safe reason and maps provider/configuration errors separately. | Misconfiguration looked like an application failure and made the Groq integration difficult to diagnose. The observed RuntimeError matches the missing-key branch; the old process environment is not available for retroactive inspection. | Keep the provider selection and error mapping centralized; restart after changing `.env`; monitor configuration and authentication statuses without logging key values. | **Fixed.** Missing-key, provider status, API mapping, startup dotenv, and live Groq smoke checks passed. |

## 7. AI security capability assessment

| Capability | Evidence-based assessment |
|---|---|
| Prompt injection / instruction override | Implemented as synthetic prompts plus text-pattern response checks. Useful as a first-pass signal, not a general detector. |
| Jailbreak | A small set of benign policy-boundary probes and response patterns; no broad adaptive or model-graded testing. |
| System prompt / sensitive context disclosure | Synthetic canary markers are injected for selected tests; the system does not inspect real target secrets or prove disclosure of a real system prompt. |
| Sensitive data leakage | Detection is limited to configured/synthetic canaries and supported response patterns. It is not a DLP engine. |
| Tool-use behavior | Prompts simulate tool requests; indicators are explicitly response-claim-only. There is no tool execution or external side-effect verification. |
| RAG/context poisoning | Synthetic retrieved-document/context probes exist; no live retrieval connector, index, ingestion path, or corpus poisoning workflow is implemented. |
| Insecure output handling | No downstream application sink or output sanitizer is exercised by this backend. The scanner records bounded responses; it cannot establish whether a target later renders/executes them unsafely. |
| Excessive agency / unintended actions | Simulated authorization probes and text matching only; no action executor or external-impact evidence exists. |
| Provider failures / availability | Provider paths distinguish missing config, auth, rate-limit, timeout, malformed response, and network failures. Endpoint safety applies HTTPS, host, and DNS checks before outbound requests, but does not pin DNS results. There is no load test or global rate-control validation. |
| Rate/resource controls | Per-scan case/concurrency/time/retry fields are bounded, but API authentication, request throttling, and a global bounded scan queue are absent. Prompt body size is not explicitly bounded by the request model. |

## 8. Remaining limitations

- The old Uvicorn process's environment at the time of the reported 502 cannot be recovered. The source exception path and current successful smoke test support, but do not prove, the historical process-start explanation.
- Only one live request was made to the authorized Groq endpoint. No live OpenAI/Gemini calls, load tests, or non-provider target scans were performed.
- No real RAG system, tool-enabled agent, or downstream output consumer was connected; those classes were assessed from local fixtures and implementation.
- No frontend test runner is configured. The frontend build emits a large-chunk warning.
- Persistence, authentication/authorization, bounded queue admission, prompt request-size limits, and production deployment controls remain unimplemented. Endpoint checks do not pin DNS results and are not a substitute for network egress controls.
- `git diff --check` reports a trailing blank line in the pre-existing modified `backend/.env.example`; it was left untouched to preserve the user's change.

## 9. Recommended remediation roadmap

### Immediate

1. Keep the service bound to `127.0.0.1`; do not expose it through a public interface or reverse proxy.
2. If the API has ever been exposed, rotate provider credentials and inspect provider usage.
3. Keep `AI_FUZZER_ALLOW_PRIVATE_TARGETS` disabled; restrict custom provider hosts to explicitly trusted origins.
4. Confirm the restarted backend reports configuration status without printing secret values; recreate targets after restart.

### Within 24 hours

1. Add authentication and per-user/tenant authorization to target, prompt, execute, scan, and results routes.
2. Add request rate limits, a bounded scan queue, per-user concurrency/case quotas, and maximum prompt/request-body sizes.
3. Apply an egress firewall/proxy to block private, loopback, link-local, and metadata destinations; do not rely on pre-request DNS checks alone.
4. Add API tests proving unauthenticated operations are rejected and queue saturation returns a controlled response.

### Within 7 days

1. Persist targets, scan state, and results; define retention, deletion, and access-control behavior.
2. Add a real backend report/export implementation and replace the frontend mock service with the backend contract (or clearly retain demo-only labeling).
3. Expand analyzer validation using benign controlled fixtures, quoted/refusal counterexamples, and independent human-reviewed expected outcomes; keep external action claims unverified unless instrumented.
4. Add integration tests for provider/model selection, startup dotenv from different working directories, and safe API serialization.

### Before production

1. Complete a deployment threat model and security review with authentication, authorization, CSRF/CORS policy, secrets management, key rotation, and network egress controls.
2. Run load, queue saturation, timeout, and quota tests against local mocks; establish hard spend and resource ceilings.
3. Add structured observability with redaction, audit trails for target/scan access, and alerting for repeated auth/rate-limit failures.
4. Validate report accuracy and severity against an independently labeled benchmark; do not present heuristic findings as confirmed vulnerabilities.
5. Configure database backup/recovery, dependency pinning, patch management, and operational incident procedures.

# Architecture

## System overview

AI-Fuzzer is a local web application for authorized AI security assessments. The backend is a FastAPI application under `backend/app`; the browser UI is a React/TypeScript application under `AI-Fuzzer/frontend`. SQLite persistence is managed through SQLAlchemy in `backend/app/database/store.py`.

The application has two distinct execution surfaces:

1. **Target scans** send generated prompts through a selected target adapter. This surface can make network requests when an operator configures a real target and starts a scan. Keep it loopback-only unless deployment controls and authorization are added.
2. **Synthetic application security lab** exercises seeded identities, resources, RAG documents, tools/MCP fixtures, and connectors locally. These services do not call a model provider or external MCP/connector service.

## Backend layers

- `adapters/`: target models, capability profiles, provider adapter selection, and endpoint policy.
- `api/`: FastAPI endpoints for targets, attacks, scan lifecycle, reports, identity/authorization, local RAG, tools/MCP, synthetic integrations, vector fixtures, agent memory, and web fixtures.
- `attacks/`: attack definitions, category registry, capability requirements, and preview filtering.
- `authorization/`: synthetic identity/resource models and centralized role, permission, ownership, tenant, session, and context policy.
- `rag/`: synthetic documents, local retrieval adapter, authorization checks, retrieval scenario service, and audit records. The local adapter is functional; no vector database integration is implemented.
- `vector_store/`: provider-neutral adapter contract and persistent local synthetic vector collections. The bundled adapter uses deterministic hashed-token vectors; it is a bounded fixture, not a production semantic index.
- `agent_memory/`: persistent synthetic user/session/tenant-scoped records with TTL, centralized policy checks, and audit evidence.
- `web_security/`: fixed in-process secure/vulnerable control fixtures. It does not accept arbitrary target URLs, send network requests, or run exploit payloads.
- `tools/`: synthetic tool definitions, operation classification, validation, authorization, local state mutation, and execution audit. MCP is represented by local fixtures, not a network MCP client.
- `integrations/`: synthetic connector fixtures, policy-checked read/write operations, security scenarios, and audit records. No external connector is invoked.
- `fuzzing/`: payload generation, mutations, scan scheduling, execution budgets, progress, persistence, and cancellation.
- `analysis/`: response analysis, findings, verification state, and evidence provenance.
- `reports/`: scan report generation from stored scan results.

## Scan and capability flow

1. A target records its `TargetScope` and capability profile.
2. Scan creation requires explicit authorization confirmation and validates requested categories.
3. Category requirements and target scope determine which categories are applicable. Unsupported categories are recorded as not applicable rather than executed.
4. The scan persists the target scope and capability profile snapshot, requested/applicable/not-applicable category lists, and execution metrics.
5. Generated cases pass through the selected adapter, analyzer, and provenance builder. Results and findings are persisted by the scheduler/store.
6. Reports summarize the persisted scan; they do not prove that unexecuted or unsupported categories were tested.

The requested case count is a total scan budget, not a per-category quota. If the count is below the number of applicable categories, the API reports a coverage warning.

## Authorization and synthetic application flow

The synthetic identity policy is the authority for controlled resources. It validates identity status, session and application-context identity, tenant boundary, role-derived and assigned permissions, resource classification, and ownership. Tool and connector operation semantics select the required READ or WRITE policy operation; client/model claims are not authorization decisions.

RAG, vector retrieval, and memory access call the centralized policy before disclosing protected content. Tool/MCP and connector calls record allow/deny decisions, whether an action executed, and a sanitized evidence reference. Denied state-changing operations do not mutate fixture state. The model never grants its own access.

## Persistence and migrations

Database initialization creates missing SQLAlchemy tables, adds missing target capability/configuration columns, and ensures schema-version rows 1 through 10 are recorded. Version 10 adds local vector collections/documents/audits and agent-memory/audit tables and indexes. Initialization is additive and does not drop existing target, scan, finding, identity, resource, or audit tables. Migration regression tests check that historical identities, targets, scans, and findings survive initialization.

The default SQLite database is outside the repository at `%LOCALAPPDATA%\\AI-Fuzzer\\ai_fuzzer.sqlite3`. Set `AI_FUZZER_DATABASE_URL` or `AI_FUZZER_DB_PATH` to select another database. Use an isolated temporary or in-memory database for tests; never point test setup at a valuable working database.

## Frontend

The React application uses typed API mapping in `AI-Fuzzer/frontend/src/services/api.ts`. Existing scan, finding, target, dashboard, and report screens remain, with additional target-capability and application-security-lab screens. The lab displays fixture metadata and exposes policy-checked vector search, authorized memory metadata inspection, a local web-control simulation, and explicit synthetic authorization, RAG, tool, and connector scenarios.

## Trust boundaries

- Target adapter network traffic is a separate, operator-controlled surface. Endpoint policy and authorization confirmation are not a substitute for deployment access control.
- Synthetic identities are test principals, not authenticated application users.
- Local RAG/vector retrieval and agent memory are synthetic harnesses, not production databases or semantic-memory services.
- Web security control results describe only the fixed local fixture; they are not results from an arbitrary web application or a standards-complete scanner.
- Tool and integration effects are synthetic local state only.
- An LLM response is not evidence that a protected resource was actually accessed. Use policy decisions, controlled state, retrieval results, and audits as evidence.

# API reference

The API is served by `app.main:app`, normally on `http://127.0.0.1:8000`. Interactive OpenAPI documentation is available at `/docs`. The route inventory below describes the primary implemented surfaces; OpenAPI is authoritative for exact request/response schemas.

## Health

- `GET /` — service metadata.
- `GET /health` — health status.

## Targets and capabilities

- `POST /targets` — create a target.
- `GET /targets` — list targets.
- `GET /targets/{target_id}` — retrieve target metadata.
- `PUT /targets/{target_id}` — update target configuration.
- `PUT /targets/{target_id}/capabilities` — update the target capability profile.
- `PUT /targets/{target_id}/credential` — store target credential (omitted from response models).
- `DELETE /targets/{target_id}/credential` — remove stored target credential.
- `DELETE /targets/{target_id}` — delete a target.

## Attack library and previews

- `GET /attacks/categories?target_id=...` — category list and target applicability.
- `GET /attacks` — filter attack definitions by category, target, risk level, or search.
- `GET /attacks/{attack_id}` — retrieve a definition.
- `GET /targets/{target_id}/attacks/applicable` — applicable definitions.
- `POST /targets/{target_id}/attacks/preview` — preview generated cases and requested/applicable/not-applicable accounting without executing them.

## Scans and findings

- `POST /scans` — enqueue a scan; requires `authorization_confirmed: true`. Supports an optional `Idempotency-Key` header.
- `GET /scans` — list scans.
- `GET /scans/{scan_id}/results` — retrieve stored execution/analysis results.
- `POST /scans/{scan_id}/cancel` — request cancellation.
- `GET /scans/{scan_id}/findings` — findings for one scan.
- `GET /scans/findings` — findings list and filters.
- `POST /targets/{target_id}/fuzz` — legacy bounded fuzz execution.

Scan requests validate count, categories, mutation limits, timeout, retries, concurrency, delay, ordering, and multi-turn bounds. Starting a scan may contact the configured target; do not use it as a synthetic-only test unless the target is a controlled local fixture.

## Identity and authorization

- `GET /identities`, `POST /identities`
- `GET /identities/{identity_id}`, `PATCH /identities/{identity_id}`
- `GET /authorization/resources`
- `POST /authorization/check`
- `POST /authorization/tests`
- `GET /authorization/tests`, `GET /authorization/tests/{test_id}`

These APIs manage synthetic test principals and resources only. They are not protected by a production user login system.

## Local RAG

- `GET /rag/documents` — metadata inventory; document content is not returned.
- `POST /rag/documents` — add a synthetic-only document.
- `GET /rag/documents/{document_id}` — document metadata.
- `POST /rag/retrievals` — perform local, identity-bound retrieval.
- `POST /rag/scenarios` — run a deterministic RAG security scenario.
- `GET /rag/scenarios` — list scenario identifiers.
- `GET /rag/retrieval-audits`, `GET /rag/retrieval-audits/{audit_id}` — audit records.

## Simulated tools and MCP

- `GET /tools`, `GET /tools/{tool_id}`
- `POST /tools/register`
- `POST /tools/{tool_id}/invoke`
- `GET /tools/executions`
- `POST /tools/security-tests`, `GET /tools/security-tests`
- `GET /mcp/servers`, `GET /mcp/servers/{server_id}`
- `GET /mcp/resources`
- `POST /mcp/resources/{resource_id}/retrieve`
- `POST /mcp/tools/{tool_id}/invoke`

Only registered synthetic tool definitions and synthetic resources are in scope. Operation flags must match the explicit operation classification.

## Synthetic integrations

- `GET /integrations`, `GET /integrations/{integration_id}`
- `POST /integrations` — create a synthetic connector fixture.
- `POST /integrations/{integration_id}/execute`
- `POST /integrations/security-tests`, `GET /integrations/security-tests`
- `GET /integrations/audits`

## Local vector fixtures and agent memory

- `GET /vector-store/collections`
- `POST /vector-store/collections` — create a synthetic tenant-scoped collection.
- `POST /vector-store/documents` — add a synthetic document, subject to write authorization.
- `POST /vector-store/search` — perform policy-checked local retrieval with optional metadata/tenant filters.
- `DELETE /vector-store/documents/{document_id}` — policy-checked deletion.
- `GET /vector-store/audits`
- `POST /memories` — create an authorized synthetic memory record.
- `POST /memories/search` — list memory records accessible to the supplied synthetic identity/session.
- `POST /memories/{memory_id}/retrieve`, `PATCH /memories/{memory_id}`, `DELETE /memories/{memory_id}`
- `POST /memories/security-tests`
- `GET /memories/audits`

The local vector adapter ranks deterministic hashed-token vectors; it is not a production semantic/vector database. Memory and vector request identities are test context, not authenticated API principals.

## Synthetic web security fixture

- `GET /web-security/fixtures`
- `GET /web-security/tests`
- `POST /web-security/runs` — run selected control checks against one of the fixed in-process fixtures.

The fixture API rejects arbitrary hosts and performs no network access or active scanning. Its results describe fixture behavior only.

## Reports

- `GET /reports`
- `POST /reports/{scan_id}/generate`
- `GET /reports/{report_id}`

Reports are derived from recorded scan data and include coverage and finding evidence available to the backend. A report with no findings is not a security certification.

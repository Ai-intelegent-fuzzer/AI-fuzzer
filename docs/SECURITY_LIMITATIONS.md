# Security limitations

## Deployment boundary

The current application has no production user authentication or authorization layer protecting its management APIs. Synthetic identities are inputs to the lab's policy engine; they do not authenticate the person calling FastAPI. Run the application bound to loopback (`127.0.0.1`) for local evaluation. Do not expose it on a shared network or internet without adding and independently reviewing authentication, authorization, CSRF/CORS controls as applicable, rate limits, and deployment hardening.

## Synthetic subsystems

- RAG documents and canaries are synthetic fixtures. Local retrieval is not a production vector store, embedding service, or general-purpose document ingestion pipeline.
- The vector-store fixture uses deterministic hashed-token vectors for local ranking, not semantic embeddings. It has no external vector database adapter implementation or production-grade operational controls.
- Agent memory is persistent synthetic test data with centralized policy checks, not production agent memory or authenticated multi-user access.
- The web-security fixture runs fixed control checks in process. It does not scan arbitrary hosts, send network requests, or establish that a real web application is secure.
- Tool and MCP operations are simulated. No remote MCP server or real tool is contacted. The synthetic tool authorization remediation does not secure external executors that may be added later.
- Integrations are controlled local fixtures; no real connector credentials, SaaS records, email, calendar, webhook, or third-party API actions are used.
- Target capability settings are configuration claims. `configured` or `enabled` does not mean the capability was verified in a deployed application.
- Vector, memory, and web test routes accept synthetic identity context but are not protected by a real login/session boundary. They must not be exposed as production authorization APIs.

## Scan and analyzer limitations

- Target scans use provider adapters and can make outbound requests if configured and started. Do not infer that the application is safe for external scanning from the synthetic lab.
- The endpoint policy is defense-in-depth, not a replacement for network egress controls and explicit authorization.
- Analyzer rules are heuristic. False positives and false negatives are possible; findings require review.
- A response that repeats a synthetic marker is not a verified leak unless provenance proves the marker was protected in transmitted context and absent from the test input.
- Coverage accounting distinguishes requested, applicable, generated, executed, skipped, and not-applicable work, but does not measure test effectiveness.
- Reports summarize stored evidence; they do not certify system security.

## Data and secrets

Do not put real personal data or secrets into synthetic fixtures. API keys saved for target testing are separate from synthetic identities and should be encrypted using `AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY`. Protect the SQLite file and encryption key, and do not commit `.env` files.

## Not covered by the targeted tools fix

The operation/flag validation protects the current synthetic tool registry and service. It does not create a real authentication boundary, secure future plugin execution, guarantee safety of arbitrary Python functions, or replace a separate authorization check in a future external tool/MCP adapter.

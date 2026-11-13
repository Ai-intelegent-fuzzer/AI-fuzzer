# Implementation inventory

This document describes behavior present in the repository; it does not imply that every listed category has an external-system integration.

## Implemented areas

### Target capabilities and scan accounting

Targets support typed scopes and capability profiles for model endpoints, web applications, RAG, vector databases, tools, MCP, authentication, authorization, multi-tenancy, agent memory, and external integrations. Scan creation snapshots the target scope/profile and tracks requested, applicable, generated, executed, and not-applicable categories. The category gate prevents application-only test categories from being reported as applicable to a model-only target.

### Synthetic identity and authorization

Seeded Admin, Manager, User A, User B, and Guest identities operate on synthetic resources. The policy produces explicit allowed/denied/invalid-identity/invalid-session/tenant-mismatch/insufficient-permission decisions. Role permissions are combined with explicit identity permissions and resource checks.

### Local RAG

The RAG service stores synthetic-only documents with owner, tenant, classification, permission, and metadata fields. Its local retrieval adapter applies authorization before returning content and persists retrieval audit records. Seeded fixtures include public/private/tenant content, untrusted instructions, and synthetic canary values.

### Local vector store and agent memory

The local vector store persists synthetic tenant-scoped collections and documents, uses a provider-neutral adapter interface with deterministic hashed-token vectors, applies the centralized authorization policy before retrieval or mutation, and persists sanitized audit references. This adapter is functional for controlled local tests but is not a semantic search engine or production vector database.

Agent memory persists synthetic user-, session-, and tenant-scoped records with optional expiry, provenance, ownership, permissions, and audit records. Reads and mutations are checked by the centralized policy and session context. Seeded memory content is synthetic only.

### Synthetic web security fixture

The web-security module provides a deterministic in-process fixture with fixed secure and vulnerable control states and bounded test identifiers. It does not accept arbitrary target URLs, make network calls, run exploit payloads, or claim coverage of a live web application.

### Simulated tools and MCP

Tool operation types have an explicit READ/WRITE classification. Model validation checks declared read-only and state-changing flags at registration and when loading persisted definitions; invocation repeats the checks before execution. Authorization and dispatch use the registered operation, not client-supplied operation/role claims. Malformed persisted definitions are denied and audited. State-changing effects remain in the synthetic state table.

The MCP surface contains local server/resource fixtures and authorization checks. It is not a production MCP client or connection to a remote server.

### Synthetic integrations

Connector records and effects are local synthetic fixtures. Read/write authorization uses the centralized policy and execution attempts are audited. No vendor connector or live token is used.

### Attack library, evidence, and reports

The attack registry currently contains 24 named attack definitions across the categories listed in [ATTACK_TAXONOMY](./ATTACK_TAXONOMY.md). Attack previews and scans filter categories by target scope/capability. Analysis represents pass/fail/inconclusive outcomes and finding verification status. Provenance records synthetic canary context, input/response presence, identity/tenant references, and associated retrieval/tool references. Reports are generated from persisted scan data.

### Frontend

The application-security lab includes authorized synthetic vector search, authorized memory metadata inspection, and fixed web-control fixture execution in addition to the earlier identity, RAG, tool/MCP, and connector views. API client types and UI wording explicitly identify these as synthetic/local capabilities.

## Not equivalent to full product integrations

- A capability profile describes configured scope; it does not install or verify a real application control.
- RAG, tools, MCP, and connectors are synthetic local harnesses. They do not connect to production databases, file stores, MCP servers, or SaaS APIs.
- Vector storage and agent memory have functional local synthetic implementations; no external vector database, semantic embedding service, production memory service, or authenticated multi-user deployment is included.
- The web security component is a fixed control simulator rather than an active scanner or a vulnerable web application.
- Some prompt-category tests run through a target adapter, while deterministic RAG/tool/connector scenarios run through their corresponding local services. Do not equate one with the other.
- The analyzer is heuristic and is not an independent LLM judge. A suspicious response alone is not proof of unauthorized data access.
- The UI is an operational interface for implemented routes, not a multi-user authenticated administration console.

## Tool authorization remediation

The tool remediation was independently exercised with isolated tests. It rejects mismatched `DELETE_RECORD` and `UPDATE_RECORD` metadata, unknown operations, and malformed stored definitions. Regression tests assert denial and audit behavior as well as unchanged synthetic state. See the [validation report](./FINAL_VALIDATION_REPORT.md).

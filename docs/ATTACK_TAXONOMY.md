# Attack taxonomy

The attack library currently has 24 named definitions. Categories are selected by scope and capability rules in `backend/app/attacks/taxonomy.py` and `backend/app/attacks/capabilities.py`. A category that is not applicable must not be interpreted as tested.

## Current categories

| Category | Typical capability gate / focus |
|---|---|
| `prompt_injection` | Direct user instruction boundary |
| `instruction_override` | Instruction hierarchy |
| `jailbreak` | Policy boundary reframing |
| `context_manipulation` | Untrusted context authority |
| `data_leakage` | Synthetic canary disclosure |
| `rag_security` | RAG-enabled target |
| `rag_cross_tenant_data_leakage` | RAG and multi-tenant |
| `rag_poisoning` | RAG-enabled target |
| `rag_document_permission_bypass` | RAG and authorization |
| `indirect_prompt_injection` | RAG-enabled target |
| `tool_misuse` | Tool calling |
| `unauthorized_agent_action` | Tool calling |
| `role_confusion` | Application authorization context |
| `system_prompt_extraction` | Configured target behavior |
| `sensitive_information_disclosure` | Configured target behavior |
| `unauthorized_retrieval` | RAG and authorization |
| `unauthorized_tool_invocation` | Tool calling and authorization |
| `mcp_security_abuse` | MCP enabled |
| `agent_identity_confusion` | Authentication and authorization |
| `privilege_escalation` | Authorization enabled |
| `excessive_agency` | Tool calling |
| `memory_poisoning` | Agent memory capability |
| `insecure_output_handling` | Web application capability |
| `external_integration_abuse` | External integration and authorization capabilities |

Other category strings may also be present in the general fuzz template library; the registry endpoint and target-specific category endpoint return the runtime inventory.

## Definition and evidence model

Each registered attack definition contains an identifier, category, name, description, safe synthetic prompt, risk area, expected behavior, risk level, applicable scopes, required capabilities, preconditions, mutation/detection metadata, evidence requirements, references, tags, and metadata.

Attack preview returns requested, applicable, and not-applicable categories and generated cases. It does not execute them. Scan execution further records generated/executed categories and per-scan coverage. The requested case count is a shared budget; small budgets may not cover every applicable category.

## Safe interpretation

- Prompts use synthetic markers and controlled test language; they are not proof that a target contains the referenced data.
- Model text claiming access is not a successful authorization bypass.
- Use the actual authorization decision, retrieved synthetic resource, audit record, state change, and evidence provenance when the scenario provides them.
- Response analysis is heuristic. Findings retain confidence/verification state and require human review.
- Capability gates describe declared target scope, not independently verified implementation behavior.

## Coverage limits

The registry is not a complete implementation of every named security standard or attack family. Local synthetic vector storage and agent-memory services, and a fixed in-process web control fixture, are available for bounded policy and control tests; they are not production vector/memory services, a live web application, or a full web scanner. External connector protocols and remote MCP behavior are not implemented. Do not report those fixture tests as coverage of real external systems.

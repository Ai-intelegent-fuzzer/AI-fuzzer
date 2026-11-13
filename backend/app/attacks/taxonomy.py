from app.adapters.models import CapabilityName, TargetScope

APPLICATION_SCOPES = (
    TargetScope.AI_APPLICATION,
    TargetScope.APPLICATION_INTEGRATION,
    TargetScope.SIMULATED,
)

ATTACK_CATEGORY_REQUIREMENTS: dict[str, tuple[CapabilityName, ...]] = {
    "rag_security": (CapabilityName.RAG_ENABLED,),
    "rag_poisoning": (CapabilityName.RAG_ENABLED,),
    "indirect_prompt_injection": (CapabilityName.RAG_ENABLED,),
    "rag_cross_tenant_data_leakage": (
        CapabilityName.RAG_ENABLED,
        CapabilityName.MULTI_TENANT,
    ),
    "rag_document_permission_bypass": (
        CapabilityName.RAG_ENABLED,
        CapabilityName.AUTHORIZATION_ENABLED,
    ),
    "unauthorized_retrieval": (
        CapabilityName.RAG_ENABLED,
        CapabilityName.AUTHORIZATION_ENABLED,
    ),
    "tool_misuse": (CapabilityName.TOOL_CALLING,),
    "unauthorized_tool_invocation": (
        CapabilityName.TOOL_CALLING,
        CapabilityName.AUTHORIZATION_ENABLED,
    ),
    "mcp_security_abuse": (CapabilityName.MCP_ENABLED,),
    "agent_identity_confusion": (
        CapabilityName.AUTHENTICATION_ENABLED,
        CapabilityName.AUTHORIZATION_ENABLED,
    ),
    "privilege_escalation": (CapabilityName.AUTHORIZATION_ENABLED,),
    "excessive_agency": (CapabilityName.TOOL_CALLING,),
    "memory_poisoning": (CapabilityName.AGENT_MEMORY,),
    "context_poisoning": (CapabilityName.AGENT_MEMORY,),
    "insecure_output_handling": (CapabilityName.WEB_APPLICATION,),
    "external_integration_abuse": (
        CapabilityName.EXTERNAL_INTEGRATIONS,
        CapabilityName.AUTHORIZATION_ENABLED,
    ),
    "unauthorized_agent_action": (CapabilityName.TOOL_CALLING,),
}

_APPLICATION_ONLY_CATEGORIES = frozenset(ATTACK_CATEGORY_REQUIREMENTS)


def applicable_scopes(category: str) -> list[TargetScope]:
    if category in _APPLICATION_ONLY_CATEGORIES:
        return list(APPLICATION_SCOPES)
    return list(TargetScope)

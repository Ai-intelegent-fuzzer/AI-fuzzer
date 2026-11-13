from enum import Enum
import re
from typing import Optional
from datetime import datetime

from pydantic import SecretStr

from pydantic import BaseModel, Field, HttpUrl, model_validator

from app.adapters.endpoint_policy import validate_target_endpoint


class TargetType(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    CHATBOT = "chatbot"
    RAG = "rag"
    AGENT = "agent"


class AIProvider(str, Enum):
    OPENAI = "openai"
    GROQ = "groq"
    GEMINI = "gemini"
    ANTHROPIC = "anthropic"
    MISTRAL = "mistral"
    OLLAMA = "ollama"
    CUSTOM = "custom"


class TargetScope(str, Enum):
    MODEL_ENDPOINT = "model_endpoint"
    AI_APPLICATION = "ai_application"
    APPLICATION_INTEGRATION = "application_integration"
    SIMULATED = "simulated"


class CapabilityName(str, Enum):
    MODEL_ENDPOINT = "model_endpoint"
    WEB_APPLICATION = "web_application"
    RAG_ENABLED = "rag_enabled"
    VECTOR_DATABASE = "vector_database"
    TOOL_CALLING = "tool_calling"
    MCP_ENABLED = "mcp_enabled"
    AUTHENTICATION_ENABLED = "authentication_enabled"
    AUTHORIZATION_ENABLED = "authorization_enabled"
    MULTI_TENANT = "multi_tenant"
    AGENT_MEMORY = "agent_memory"
    EXTERNAL_INTEGRATIONS = "external_integrations"


class CapabilityValidationStatus(str, Enum):
    NOT_CONFIGURED = "not_configured"
    UNVERIFIED = "unverified"
    CONFIGURED = "configured"
    VERIFIED = "verified"
    INVALID = "invalid"


class CapabilitySetting(BaseModel):
    enabled: bool = False
    configuration_reference: str | None = Field(default=None, max_length=200)
    validation_status: CapabilityValidationStatus = CapabilityValidationStatus.NOT_CONFIGURED
    supported_security_tests: list[str] = Field(default_factory=list)
    known_limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_configuration_state(self) -> "CapabilitySetting":
        if self.enabled and self.validation_status in {
            CapabilityValidationStatus.NOT_CONFIGURED,
            CapabilityValidationStatus.INVALID,
        }:
            raise ValueError("Enabled capabilities must be configured and not invalid.")
        if len(set(self.supported_security_tests)) != len(self.supported_security_tests):
            raise ValueError("Supported security tests must not contain duplicates.")
        if any(not item.strip() for item in self.supported_security_tests):
            raise ValueError("Supported security tests must not be empty.")
        if any(not item.strip() for item in self.known_limitations):
            raise ValueError("Known limitations must not be empty.")
        return self


def default_capability_profile(
    target_scope: TargetScope,
) -> "CapabilityProfile":
    capabilities = {
        capability: CapabilitySetting(
            known_limitations=["Capability has not been configured or verified."]
        )
        for capability in CapabilityName
    }
    if target_scope == TargetScope.MODEL_ENDPOINT:
        capabilities[CapabilityName.MODEL_ENDPOINT] = CapabilitySetting(
            enabled=True,
            validation_status=CapabilityValidationStatus.CONFIGURED,
            known_limitations=[
                "Only the configured model endpoint is in scope; application-layer controls are not verified."
            ],
        )
    return CapabilityProfile(capabilities=capabilities)


class CapabilityProfile(BaseModel):
    capabilities: dict[CapabilityName, CapabilitySetting] = Field(default_factory=dict)

    @model_validator(mode="after")
    def include_all_capabilities(self) -> "CapabilityProfile":
        for capability in CapabilityName:
            self.capabilities.setdefault(
                capability,
                CapabilitySetting(
                    known_limitations=["Capability has not been configured or verified."]
                ),
            )
        return self


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    target_type: TargetType
    target_scope: TargetScope | None = None
    capability_profile: CapabilityProfile | None = None
    endpoint: HttpUrl
    model: Optional[str] = None
    provider: AIProvider = AIProvider.OPENAI
    description: Optional[str] = None
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    api_path: str | None = None
    auth_header: str = "Authorization"
    system_prompt: str | None = None
    temperature: float = Field(default=0.0, ge=0, le=2)
    max_output_tokens: int = Field(default=256, ge=1, le=8192)

    @model_validator(mode="after")
    def validate_endpoint_policy(self) -> "TargetCreate":
        if self.target_scope is None:
            object.__setattr__(
                self,
                "target_scope",
                TargetScope.MODEL_ENDPOINT
                if self.target_type == TargetType.OPENAI_COMPATIBLE
                else TargetScope.AI_APPLICATION,
            )
        if self.capability_profile is None:
            object.__setattr__(
                self,
                "capability_profile",
                default_capability_profile(self.target_scope),
            )
        provider = self.provider.value if self.provider != AIProvider.CUSTOM else None
        validate_target_endpoint(
            str(self.endpoint),
            provider=provider,
            resolve_dns=False,
            allow_local_ollama=self.provider == AIProvider.OLLAMA,
        )
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", self.auth_header):
            raise ValueError("Authentication header name is invalid.")
        if self.auth_header.lower() in {"host", "content-length", "connection"}:
            raise ValueError("Authentication header name is not allowed.")
        if self.api_path and (
            "?" in self.api_path
            or "#" in self.api_path
            or "://" in self.api_path
            or any(part == ".." for part in self.api_path.split("/"))
        ):
            raise ValueError("API path must be a relative path without query, fragment, or traversal segments.")
        return self


class Target(TargetCreate):
    target_id: str
    connection_status: str = "unknown"
    last_tested: datetime | None = None

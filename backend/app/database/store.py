from __future__ import annotations

import os
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, create_engine, event, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool
from pydantic import ValidationError

from app.adapters.models import (
    CapabilityProfile,
    Target,
    TargetScope,
    default_capability_profile,
)
from app.analysis.models import AnalysisResult, EvidenceProvenance, Finding
from app.authorization.models import (
    AuthorizationTestResult,
    IdentityRole,
    IdentityStatus,
    Permission,
    ResourceClassification,
    SyntheticIdentity,
    SyntheticResource,
)
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanRecord, ScanStatus
from app.rag.models import RAGDocument, RAGRetrievalAudit
from app.tools.models import (
    MCPResource,
    MCPServer,
    ToolDefinition,
    ToolExecutionAudit,
    ToolSecurityTestResult,
)
from app.integrations.models import (
    IntegrationExecutionAudit,
    IntegrationSecurityTestResult,
    SyntheticIntegration,
)
from app.vector_store.models import VectorAudit, VectorCollection, VectorDocument
from app.agent_memory.models import MemoryAudit, MemoryRecord


class DatabaseError(RuntimeError):
    pass


logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class TargetRow(Base):
    __tablename__ = "targets"

    target_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_scope: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default=TargetScope.MODEL_ENDPOINT.value,
        server_default=TargetScope.MODEL_ENDPOINT.value,
    )
    capability_profile: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str | None] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    api_path: Mapped[str | None] = mapped_column(Text)
    auth_header: Mapped[str] = mapped_column(String(100), nullable=False, default="Authorization")
    system_prompt: Mapped[str | None] = mapped_column(Text)
    temperature: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=256)
    connection_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    last_tested: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    credential_ciphertext: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScanRow(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(160), unique=True)
    scan_record: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ScanConfigurationRow(Base):
    __tablename__ = "scan_configurations"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), primary_key=True)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class FuzzCaseRow(Base):
    __tablename__ = "fuzz_cases"

    case_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    case_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ExecutionRow(Base):
    __tablename__ = "executions"

    case_id: Mapped[str] = mapped_column(ForeignKey("fuzz_cases.case_id", ondelete="CASCADE"), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    response_time_ms: Mapped[float | None] = mapped_column()
    provider: Mapped[str | None] = mapped_column(String(40))
    model: Mapped[str | None] = mapped_column(String(200))
    response_body: Mapped[str | None] = mapped_column(Text)
    execution_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AnalysisRow(Base):
    __tablename__ = "analysis_results"

    case_id: Mapped[str] = mapped_column(ForeignKey("fuzz_cases.case_id", ondelete="CASCADE"), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    analysis_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AnalysisHistoryRow(Base):
    __tablename__ = "analysis_history"

    history_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    analysis_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class FindingRow(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("fuzz_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    finding_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class EvidenceProvenanceRow(Base):
    __tablename__ = "evidence_provenance"

    provenance_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="CASCADE"),
        index=True,
    )
    test_case_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    evidence_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ReportRow(Base):
    __tablename__ = "reports"

    report_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    report_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SchemaVersionRow(Base):
    __tablename__ = "schema_version"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SyntheticIdentityRow(Base):
    __tablename__ = "synthetic_identities"

    identity_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    roles: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    permissions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    identity_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SyntheticResourceRow(Base):
    __tablename__ = "synthetic_resources"

    resource_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    owner_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    required_permissions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    resource_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AuthorizationTestRow(Base):
    __tablename__ = "authorization_test_results"

    test_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario: Mapped[str | None] = mapped_column(String(80), index=True)
    requesting_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    requested_resource_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    result_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class RAGDocumentRow(Base):
    __tablename__ = "rag_documents"

    document_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    owner_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    document_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class RAGRetrievalAuditRow(Base):
    __tablename__ = "rag_retrieval_audits"

    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(String(80), index=True)
    test_case_id: Mapped[str | None] = mapped_column(String(80), index=True)
    requesting_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    document_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    document_tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    retrieval_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    audit_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ToolDefinitionRow(Base):
    __tablename__ = "synthetic_tool_definitions"

    tool_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    operation: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    tool_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ToolExecutionAuditRow(Base):
    __tablename__ = "simulated_tool_executions"

    execution_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(String(80), index=True)
    test_case_id: Mapped[str | None] = mapped_column(String(80), index=True)
    tool_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    requesting_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(120), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    execution_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ToolSecurityResultRow(Base):
    __tablename__ = "tool_security_results"

    test_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    result_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MCPServerRow(Base):
    __tablename__ = "synthetic_mcp_servers"

    server_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    server_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MCPResourceRow(Base):
    __tablename__ = "synthetic_mcp_resources"

    resource_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    owner_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    resource_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SyntheticToolStateRow(Base):
    __tablename__ = "synthetic_tool_state"

    resource_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    state_value: Mapped[str] = mapped_column(Text, nullable=False)


class SyntheticIntegrationRow(Base):
    __tablename__ = "synthetic_integrations"

    integration_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    provider_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    owner_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_scope: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    data_classification: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    integration_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class IntegrationExecutionAuditRow(Base):
    __tablename__ = "integration_execution_audits"

    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    integration_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    scan_id: Mapped[str | None] = mapped_column(String(80), index=True)
    test_case_id: Mapped[str | None] = mapped_column(String(80), index=True)
    requesting_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    audit_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class IntegrationSecurityResultRow(Base):
    __tablename__ = "integration_security_results"

    test_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    result_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SyntheticIntegrationStateRow(Base):
    __tablename__ = "synthetic_integration_state"

    integration_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    state_value: Mapped[str] = mapped_column(Text, nullable=False)


class VectorCollectionRow(Base):
    __tablename__ = "synthetic_vector_collections"

    collection_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    collection_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class VectorDocumentRow(Base):
    __tablename__ = "synthetic_vector_documents"

    document_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    collection_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    owner_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    document_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class VectorAuditRow(Base):
    __tablename__ = "synthetic_vector_audits"

    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    requesting_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    collection_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    document_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    audit_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AgentMemoryRow(Base):
    __tablename__ = "synthetic_agent_memories"

    memory_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    owner_identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    session_id: Mapped[str | None] = mapped_column(String(120), index=True)
    scope: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    memory_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AgentMemoryAuditRow(Base):
    __tablename__ = "synthetic_agent_memory_audits"

    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    memory_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    identity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    operation: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    audit_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


def _default_synthetic_identities() -> list[SyntheticIdentity]:
    identities = (
        ("synthetic-admin", "Admin", "tenant-a", IdentityRole.ADMIN),
        ("synthetic-manager", "Manager", "tenant-a", IdentityRole.MANAGER),
        ("synthetic-user-a", "User A", "tenant-a", IdentityRole.USER),
        ("synthetic-user-b", "User B", "tenant-a", IdentityRole.USER),
        ("synthetic-guest", "Guest", "tenant-a", IdentityRole.GUEST),
        (
            "synthetic-rag-tenant-b-user",
            "Synthetic Tenant B User",
            "tenant-b",
            IdentityRole.USER,
        ),
    )
    return [
        SyntheticIdentity(
            identity_id=identity_id,
            display_name=display_name,
            tenant_id=tenant_id,
            roles=[role],
            session_id=f"synthetic-session-{identity_id.removeprefix('synthetic-')}",
        )
        for identity_id, display_name, tenant_id, role in identities
    ]


def _default_synthetic_resources() -> list[SyntheticResource]:
    return [
        SyntheticResource(
            resource_id="synthetic-resource-public",
            display_name="Synthetic public resource",
            owner_identity_id="synthetic-system",
            tenant_id="tenant-public",
            classification=ResourceClassification.PUBLIC,
            required_permissions=[Permission.READ_PUBLIC],
        ),
        SyntheticResource(
            resource_id="synthetic-resource-user-a-private",
            display_name="Synthetic User A private resource",
            owner_identity_id="synthetic-user-a",
            tenant_id="tenant-a",
            classification=ResourceClassification.PRIVATE,
            required_permissions=[Permission.READ_OWNED],
        ),
        SyntheticResource(
            resource_id="synthetic-resource-user-b-private",
            display_name="Synthetic User B private resource",
            owner_identity_id="synthetic-user-b",
            tenant_id="tenant-a",
            classification=ResourceClassification.PRIVATE,
            required_permissions=[Permission.READ_OWNED],
        ),
        SyntheticResource(
            resource_id="synthetic-resource-manager",
            display_name="Synthetic manager resource",
            owner_identity_id="synthetic-manager",
            tenant_id="tenant-a",
            classification=ResourceClassification.MANAGER,
            required_permissions=[Permission.READ_MANAGER],
        ),
        SyntheticResource(
            resource_id="synthetic-resource-admin",
            display_name="Synthetic admin-only resource",
            owner_identity_id="synthetic-admin",
            tenant_id="tenant-a",
            classification=ResourceClassification.ADMIN,
            required_permissions=[Permission.READ_ADMIN],
        ),
        SyntheticResource(
            resource_id="synthetic-resource-tenant-a",
            display_name="Synthetic Tenant A resource",
            owner_identity_id="synthetic-system",
            tenant_id="tenant-a",
            classification=ResourceClassification.TENANT,
            required_permissions=[Permission.READ_TENANT],
        ),
        SyntheticResource(
            resource_id="synthetic-resource-tenant-b",
            display_name="Synthetic Tenant B resource",
            owner_identity_id="synthetic-system",
            tenant_id="tenant-b",
            classification=ResourceClassification.TENANT,
            required_permissions=[Permission.READ_TENANT],
        ),
    ]


def _database_url() -> str:
    configured_url = os.getenv("AI_FUZZER_DATABASE_URL")
    if configured_url:
        return configured_url
    configured_path = os.getenv("AI_FUZZER_DB_PATH")
    if configured_path:
        path = Path(configured_path).expanduser().resolve()
    else:
        data_root = Path(os.getenv("LOCALAPPDATA", Path.home())) / "AI-Fuzzer"
        path = data_root / "ai_fuzzer.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path.as_posix()}"


class Database:
    def __init__(self, url: str | None = None) -> None:
        self.url = url or _database_url()
        options: dict[str, Any] = {"future": True}
        if self.url.startswith("sqlite"):
            options["connect_args"] = {"check_same_thread": False}
            if self.url in {"sqlite://", "sqlite:///:memory:"}:
                options["poolclass"] = StaticPool
        self.engine: Engine = create_engine(self.url, **options)
        if self.url.startswith("sqlite"):
            event.listen(self.engine, "connect", self._enable_sqlite_foreign_keys)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)
        self._lock = RLock()

    @staticmethod
    def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def initialize(self) -> None:
        try:
            Base.metadata.create_all(self.engine)
            target_columns = {
                column["name"]
                for column in inspect(self.engine).get_columns("targets")
            }
            migrations = {
                "api_path": "TEXT",
                "auth_header": "VARCHAR(100) NOT NULL DEFAULT 'Authorization'",
                "system_prompt": "TEXT",
                "temperature": "FLOAT NOT NULL DEFAULT 0.0",
                "max_output_tokens": "INTEGER NOT NULL DEFAULT 256",
                "connection_status": "VARCHAR(24) NOT NULL DEFAULT 'unknown'",
                "last_tested": "DATETIME",
                "target_scope": "VARCHAR(40) NOT NULL DEFAULT 'model_endpoint'",
                "capability_profile": "JSON",
            }
            target_scope_needs_backfill = "target_scope" not in target_columns
            with self.engine.begin() as connection:
                for name, sql_type in migrations.items():
                    if name not in target_columns:
                        connection.execute(text(f"ALTER TABLE targets ADD COLUMN {name} {sql_type}"))
                if target_scope_needs_backfill:
                    connection.execute(text(
                        "UPDATE targets SET target_scope = 'ai_application' "
                        "WHERE target_type IN ('chatbot', 'rag', 'agent')"
                    ))
                existing_versions = set(
                    connection.execute(select(SchemaVersionRow.version)).scalars()
                )
                for version in range(1, 11):
                    if version not in existing_versions:
                        connection.execute(
                            SchemaVersionRow.__table__.insert().values(
                                version=version,
                                applied_at=datetime.now(timezone.utc),
                            )
                        )
            self._seed_synthetic_authorization_data()
            from app.rag.service import seed_rag_documents

            seed_rag_documents(self)
            from app.tools.service import seed_tool_fixtures

            seed_tool_fixtures(self)
            from app.integrations.service import seed_integrations

            seed_integrations(self)
        except SQLAlchemyError as exc:
            raise DatabaseError("Database initialization failed.") from exc

    def _seed_synthetic_authorization_data(self) -> None:
        with self._lock, self._sessions.begin() as session:
            for identity in _default_synthetic_identities():
                if session.get(SyntheticIdentityRow, identity.identity_id) is None:
                    session.add(SyntheticIdentityRow(
                        identity_id=identity.identity_id,
                        tenant_id=identity.tenant_id,
                        session_id=identity.session_id,
                        roles=[role.value for role in identity.roles],
                        permissions=[permission.value for permission in identity.permissions],
                        identity_data=identity.model_dump(mode="json"),
                    ))
            for resource in _default_synthetic_resources():
                if session.get(SyntheticResourceRow, resource.resource_id) is None:
                    session.add(SyntheticResourceRow(
                        resource_id=resource.resource_id,
                        owner_identity_id=resource.owner_identity_id,
                        tenant_id=resource.tenant_id,
                        classification=resource.classification.value,
                        required_permissions=[
                            permission.value for permission in resource.required_permissions
                        ],
                        resource_data=resource.model_dump(mode="json"),
                    ))

    def create_identity(self, identity: SyntheticIdentity) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(SyntheticIdentityRow(
                identity_id=identity.identity_id,
                tenant_id=identity.tenant_id,
                session_id=identity.session_id,
                roles=[role.value for role in identity.roles],
                permissions=[permission.value for permission in identity.permissions],
                identity_data=identity.model_dump(mode="json"),
            ))

    def get_identity(self, identity_id: str) -> SyntheticIdentity | None:
        with self._sessions() as session:
            row = session.get(SyntheticIdentityRow, identity_id)
            return SyntheticIdentity.model_validate(row.identity_data) if row else None

    def list_identities(self) -> list[SyntheticIdentity]:
        with self._sessions() as session:
            rows = session.scalars(
                select(SyntheticIdentityRow).order_by(SyntheticIdentityRow.identity_id)
            ).all()
            return [SyntheticIdentity.model_validate(row.identity_data) for row in rows]

    def update_identity_assignments(
        self,
        identity_id: str,
        roles: list[IdentityRole],
        permissions: list[Permission],
    ) -> SyntheticIdentity | None:
        with self._lock, self._sessions.begin() as session:
            row = session.get(SyntheticIdentityRow, identity_id)
            if row is None:
                return None
            identity_data = dict(row.identity_data)
            identity_data["roles"] = [role.value for role in roles]
            identity_data["permissions"] = [
                permission.value for permission in permissions
            ]
            row.roles = identity_data["roles"]
            row.permissions = identity_data["permissions"]
            row.identity_data = identity_data
            return SyntheticIdentity.model_validate(identity_data)

    def get_synthetic_resource(self, resource_id: str) -> SyntheticResource | None:
        with self._sessions() as session:
            row = session.get(SyntheticResourceRow, resource_id)
            return SyntheticResource.model_validate(row.resource_data) if row else None

    def list_synthetic_resources(self) -> list[SyntheticResource]:
        with self._sessions() as session:
            rows = session.scalars(
                select(SyntheticResourceRow).order_by(SyntheticResourceRow.resource_id)
            ).all()
            return [SyntheticResource.model_validate(row.resource_data) for row in rows]

    def save_authorization_test(
        self,
        result: AuthorizationTestResult,
    ) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(AuthorizationTestRow(
                test_id=result.test_id,
                scenario=result.scenario.value if result.scenario else None,
                requesting_identity_id=result.requesting_identity_id,
                requested_resource_id=result.requested_resource_id,
                created_at=result.created_at,
                result_data=result.model_dump(mode="json"),
            ))

    def get_authorization_test(
        self,
        test_id: str,
    ) -> AuthorizationTestResult | None:
        with self._sessions() as session:
            row = session.get(AuthorizationTestRow, test_id)
            return AuthorizationTestResult.model_validate(row.result_data) if row else None

    def list_authorization_tests(self, limit: int = 100) -> list[AuthorizationTestResult]:
        with self._sessions() as session:
            rows = session.scalars(
                select(AuthorizationTestRow)
                .order_by(AuthorizationTestRow.created_at.desc())
                .limit(limit)
            ).all()
            return [
                AuthorizationTestResult.model_validate(row.result_data)
                for row in rows
            ]

    def create_rag_document(self, document: RAGDocument) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(RAGDocumentRow(
                document_id=document.document_id,
                owner_identity_id=document.owner_identity_id,
                tenant_id=document.tenant_id,
                classification=document.classification.value,
                document_data=document.model_dump(mode="json"),
            ))

    def get_rag_document(self, document_id: str) -> RAGDocument | None:
        with self._sessions() as session:
            row = session.get(RAGDocumentRow, document_id)
            return RAGDocument.model_validate(row.document_data) if row else None

    def list_rag_documents(self) -> list[RAGDocument]:
        with self._sessions() as session:
            rows = session.scalars(
                select(RAGDocumentRow).order_by(RAGDocumentRow.document_id)
            ).all()
            return [
                RAGDocument.model_validate(row.document_data)
                for row in rows
            ]

    def seed_rag_documents(self, documents: list[RAGDocument]) -> None:
        with self._lock, self._sessions.begin() as session:
            for document in documents:
                if session.get(RAGDocumentRow, document.document_id) is None:
                    session.add(RAGDocumentRow(
                        document_id=document.document_id,
                        owner_identity_id=document.owner_identity_id,
                        tenant_id=document.tenant_id,
                        classification=document.classification.value,
                        document_data=document.model_dump(mode="json"),
                    ))

    def save_rag_retrieval_audit(self, audit: RAGRetrievalAudit) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(RAGRetrievalAuditRow(
                audit_id=audit.audit_id,
                scan_id=audit.scan_id,
                test_case_id=audit.test_case_id,
                requesting_identity_id=audit.requesting_identity_id,
                document_id=audit.document_id,
                document_tenant_id=audit.document_tenant_id,
                retrieval_timestamp=audit.retrieval_timestamp,
                audit_data=audit.model_dump(mode="json"),
            ))

    def get_rag_retrieval_audit(self, audit_id: str) -> RAGRetrievalAudit | None:
        with self._sessions() as session:
            row = session.get(RAGRetrievalAuditRow, audit_id)
            return RAGRetrievalAudit.model_validate(row.audit_data) if row else None

    def list_rag_retrieval_audits(
        self,
        *,
        limit: int = 100,
        scan_id: str | None = None,
        test_case_id: str | None = None,
    ) -> list[RAGRetrievalAudit]:
        with self._sessions() as session:
            statement = select(RAGRetrievalAuditRow)
            if scan_id is not None:
                statement = statement.where(RAGRetrievalAuditRow.scan_id == scan_id)
            if test_case_id is not None:
                statement = statement.where(
                    RAGRetrievalAuditRow.test_case_id == test_case_id
                )
            rows = session.scalars(
                statement.order_by(
                    RAGRetrievalAuditRow.retrieval_timestamp.desc()
                ).limit(limit)
            ).all()
            return [
                RAGRetrievalAudit.model_validate(row.audit_data)
                for row in rows
            ]

    def create_vector_collection(self, collection: VectorCollection) -> None:
        with self._lock, self._sessions.begin() as session:
            if session.get(VectorCollectionRow, collection.collection_id) is None:
                session.add(VectorCollectionRow(
                    collection_id=collection.collection_id,
                    tenant_id=collection.tenant_id,
                    collection_data=collection.model_dump(mode="json"),
                ))

    def get_vector_collection(self, collection_id: str) -> VectorCollection | None:
        with self._sessions() as session:
            row = session.get(VectorCollectionRow, collection_id)
            return VectorCollection.model_validate(row.collection_data) if row else None

    def list_vector_collections(self) -> list[VectorCollection]:
        with self._sessions() as session:
            rows = session.scalars(
                select(VectorCollectionRow).order_by(VectorCollectionRow.collection_id)
            ).all()
            return [VectorCollection.model_validate(row.collection_data) for row in rows]

    def upsert_vector_document(self, document: VectorDocument) -> None:
        with self._lock, self._sessions.begin() as session:
            session.merge(VectorDocumentRow(
                document_id=document.document_id,
                collection_id=document.collection_id,
                owner_identity_id=document.owner_identity_id,
                tenant_id=document.tenant_id,
                document_data=document.model_dump(mode="json"),
            ))

    def get_vector_document(self, document_id: str) -> VectorDocument | None:
        with self._sessions() as session:
            row = session.get(VectorDocumentRow, document_id)
            return VectorDocument.model_validate(row.document_data) if row else None

    def list_vector_documents(self, collection_id: str) -> list[VectorDocument]:
        with self._sessions() as session:
            rows = session.scalars(
                select(VectorDocumentRow)
                .where(VectorDocumentRow.collection_id == collection_id)
                .order_by(VectorDocumentRow.document_id)
            ).all()
            return [VectorDocument.model_validate(row.document_data) for row in rows]

    def delete_vector_document(self, document_id: str) -> bool:
        with self._lock, self._sessions.begin() as session:
            row = session.get(VectorDocumentRow, document_id)
            if row is None:
                return False
            session.delete(row)
            return True

    def save_vector_audit(self, audit: VectorAudit) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(VectorAuditRow(
                audit_id=audit.audit_id,
                requesting_identity_id=audit.requesting_identity_id,
                collection_id=audit.collection_id,
                document_id=audit.document_id,
                created_at=audit.created_at,
                audit_data=audit.model_dump(mode="json"),
            ))

    def list_vector_audits(self, limit: int = 100) -> list[VectorAudit]:
        with self._sessions() as session:
            rows = session.scalars(
                select(VectorAuditRow)
                .order_by(VectorAuditRow.created_at.desc())
                .limit(limit)
            ).all()
            return [VectorAudit.model_validate(row.audit_data) for row in rows]

    def create_memory(self, memory: MemoryRecord) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(AgentMemoryRow(
                memory_id=memory.memory_id,
                owner_identity_id=memory.owner_identity_id,
                tenant_id=memory.tenant_id,
                session_id=memory.session_id,
                scope=memory.scope.value,
                expires_at=memory.expires_at,
                memory_data=memory.model_dump(mode="json"),
            ))

    def get_memory(self, memory_id: str) -> MemoryRecord | None:
        with self._sessions() as session:
            row = session.get(AgentMemoryRow, memory_id)
            return MemoryRecord.model_validate(row.memory_data) if row else None

    def list_memories(self) -> list[MemoryRecord]:
        with self._sessions() as session:
            rows = session.scalars(
                select(AgentMemoryRow).order_by(AgentMemoryRow.memory_id)
            ).all()
            return [MemoryRecord.model_validate(row.memory_data) for row in rows]

    def update_memory(self, memory: MemoryRecord) -> None:
        with self._lock, self._sessions.begin() as session:
            row = session.get(AgentMemoryRow, memory.memory_id)
            if row is None:
                raise KeyError("Synthetic memory record not found.")
            row.memory_data = memory.model_dump(mode="json")

    def delete_memory(self, memory_id: str) -> bool:
        with self._lock, self._sessions.begin() as session:
            row = session.get(AgentMemoryRow, memory_id)
            if row is None:
                return False
            session.delete(row)
            return True

    def seed_memories(self, memories: list[MemoryRecord]) -> None:
        with self._lock, self._sessions.begin() as session:
            for memory in memories:
                if session.get(AgentMemoryRow, memory.memory_id) is None:
                    session.add(AgentMemoryRow(
                        memory_id=memory.memory_id,
                        owner_identity_id=memory.owner_identity_id,
                        tenant_id=memory.tenant_id,
                        session_id=memory.session_id,
                        scope=memory.scope.value,
                        expires_at=memory.expires_at,
                        memory_data=memory.model_dump(mode="json"),
                    ))

    def save_memory_audit(self, audit: MemoryAudit) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(AgentMemoryAuditRow(
                audit_id=audit.audit_id,
                memory_id=audit.memory_id,
                identity_id=audit.identity_id,
                operation=audit.operation,
                created_at=audit.created_at,
                audit_data=audit.model_dump(mode="json"),
            ))

    def list_memory_audits(self, limit: int = 100) -> list[MemoryAudit]:
        with self._sessions() as session:
            rows = session.scalars(
                select(AgentMemoryAuditRow)
                .order_by(AgentMemoryAuditRow.created_at.desc())
                .limit(limit)
            ).all()
            return [MemoryAudit.model_validate(row.audit_data) for row in rows]

    def seed_tool_definitions(self, tools: list[ToolDefinition]) -> None:
        with self._lock, self._sessions.begin() as session:
            for tool in tools:
                if session.get(ToolDefinitionRow, tool.tool_id) is None:
                    session.add(ToolDefinitionRow(
                        tool_id=tool.tool_id,
                        operation=tool.operation.value,
                        tool_data=tool.model_dump(mode="json"),
                    ))

    def create_tool_definition(self, tool: ToolDefinition) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(ToolDefinitionRow(
                tool_id=tool.tool_id,
                operation=tool.operation.value,
                tool_data=tool.model_dump(mode="json"),
            ))

    def get_tool_definition(self, tool_id: str) -> ToolDefinition | None:
        with self._sessions() as session:
            row = session.get(ToolDefinitionRow, tool_id)
            return ToolDefinition.model_validate(row.tool_data) if row else None

    def list_tool_definitions(self) -> list[ToolDefinition]:
        with self._sessions() as session:
            rows = session.scalars(
                select(ToolDefinitionRow).order_by(ToolDefinitionRow.tool_id)
            ).all()
            return [ToolDefinition.model_validate(row.tool_data) for row in rows]

    def save_tool_execution(self, audit: ToolExecutionAudit) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(ToolExecutionAuditRow(
                execution_id=audit.execution_id,
                scan_id=audit.scan_id,
                test_case_id=audit.test_case_id,
                tool_id=audit.tool_id,
                requesting_identity_id=audit.requesting_identity_id,
                resource_id=audit.resource_id,
                created_at=audit.created_at,
                execution_data=audit.model_dump(mode="json"),
            ))

    def list_tool_executions(self, limit: int = 100) -> list[ToolExecutionAudit]:
        with self._sessions() as session:
            rows = session.scalars(
                select(ToolExecutionAuditRow)
                .order_by(ToolExecutionAuditRow.created_at.desc())
                .limit(limit)
            ).all()
            return [
                ToolExecutionAudit.model_validate(row.execution_data)
                for row in rows
            ]

    def save_tool_security_result(
        self,
        result: ToolSecurityTestResult,
    ) -> ToolSecurityTestResult:
        with self._lock, self._sessions.begin() as session:
            session.add(ToolSecurityResultRow(
                test_id=result.test_id,
                scenario=result.scenario.value,
                created_at=result.created_at,
                result_data=result.model_dump(mode="json"),
            ))
        return result

    def list_tool_security_results(self, limit: int = 100) -> list[ToolSecurityTestResult]:
        with self._sessions() as session:
            rows = session.scalars(
                select(ToolSecurityResultRow)
                .order_by(ToolSecurityResultRow.created_at.desc())
                .limit(limit)
            ).all()
            return [
                ToolSecurityTestResult.model_validate(row.result_data)
                for row in rows
            ]

    def seed_mcp_fixtures(
        self,
        servers: list[MCPServer],
        resources: list[MCPResource],
    ) -> None:
        with self._lock, self._sessions.begin() as session:
            for server in servers:
                if session.get(MCPServerRow, server.server_id) is None:
                    session.add(MCPServerRow(
                        server_id=server.server_id,
                        server_data=server.model_dump(mode="json"),
                    ))
            for resource in resources:
                if session.get(MCPResourceRow, resource.resource_id) is None:
                    session.add(MCPResourceRow(
                        resource_id=resource.resource_id,
                        server_id=resource.server_id,
                        owner_identity_id=resource.owner_identity_id,
                        tenant_id=resource.tenant_id,
                        classification=resource.classification.value,
                        resource_data=resource.model_dump(mode="json"),
                    ))

    def list_mcp_servers(self) -> list[MCPServer]:
        with self._sessions() as session:
            rows = session.scalars(
                select(MCPServerRow).order_by(MCPServerRow.server_id)
            ).all()
            return [MCPServer.model_validate(row.server_data) for row in rows]

    def get_mcp_server(self, server_id: str) -> MCPServer | None:
        with self._sessions() as session:
            row = session.get(MCPServerRow, server_id)
            return MCPServer.model_validate(row.server_data) if row else None

    def list_mcp_resources(self, server_id: str | None = None) -> list[MCPResource]:
        with self._sessions() as session:
            statement = select(MCPResourceRow)
            if server_id is not None:
                statement = statement.where(MCPResourceRow.server_id == server_id)
            rows = session.scalars(statement.order_by(MCPResourceRow.resource_id)).all()
            return [
                MCPResource.model_validate(row.resource_data)
                for row in rows
            ]

    def get_mcp_resource(self, resource_id: str) -> MCPResource | None:
        with self._sessions() as session:
            row = session.get(MCPResourceRow, resource_id)
            return MCPResource.model_validate(row.resource_data) if row else None

    def update_synthetic_tool_state(
        self,
        resource_id: str,
        tenant_id: str,
        state_value: str,
    ) -> None:
        if not resource_id.startswith("synthetic-resource-") or not state_value.startswith("[SYNTHETIC]"):
            raise ValueError("Tool state changes must remain inside synthetic fixtures.")
        with self._lock, self._sessions.begin() as session:
            session.merge(SyntheticToolStateRow(
                resource_id=resource_id,
                tenant_id=tenant_id,
                state_value=state_value,
            ))

    def get_synthetic_tool_state(self, resource_id: str) -> str | None:
        with self._sessions() as session:
            row = session.get(SyntheticToolStateRow, resource_id)
            return row.state_value if row else None

    def seed_integrations(self, integrations: list[SyntheticIntegration]) -> None:
        with self._lock, self._sessions.begin() as session:
            for integration in integrations:
                if session.get(SyntheticIntegrationRow, integration.integration_id) is None:
                    session.add(SyntheticIntegrationRow(
                        integration_id=integration.integration_id,
                        provider_type=integration.provider_type.value,
                        owner_identity_id=integration.owner_identity_id,
                        tenant_scope=integration.tenant_scope,
                        data_classification=integration.data_classification.value,
                        integration_data=integration.model_dump(mode="json"),
                    ))

    def create_integration(self, integration: SyntheticIntegration) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(SyntheticIntegrationRow(
                integration_id=integration.integration_id,
                provider_type=integration.provider_type.value,
                owner_identity_id=integration.owner_identity_id,
                tenant_scope=integration.tenant_scope,
                data_classification=integration.data_classification.value,
                integration_data=integration.model_dump(mode="json"),
            ))

    def get_integration(self, integration_id: str) -> SyntheticIntegration | None:
        with self._sessions() as session:
            row = session.get(SyntheticIntegrationRow, integration_id)
            return SyntheticIntegration.model_validate(row.integration_data) if row else None

    def list_integrations(self) -> list[SyntheticIntegration]:
        with self._sessions() as session:
            rows = session.scalars(
                select(SyntheticIntegrationRow).order_by(SyntheticIntegrationRow.integration_id)
            ).all()
            return [
                SyntheticIntegration.model_validate(row.integration_data)
                for row in rows
            ]

    def update_synthetic_integration_state(
        self,
        integration_id: str,
        state_value: str,
    ) -> None:
        if not integration_id.startswith("synthetic-integration-") or not state_value.startswith("[SYNTHETIC]"):
            raise ValueError("Integration state changes must remain synthetic.")
        with self._lock, self._sessions.begin() as session:
            session.merge(SyntheticIntegrationStateRow(
                integration_id=integration_id,
                state_value=state_value,
            ))

    def get_synthetic_integration_state(self, integration_id: str) -> str | None:
        with self._sessions() as session:
            row = session.get(SyntheticIntegrationStateRow, integration_id)
            return row.state_value if row else None

    def save_integration_audit(self, audit: IntegrationExecutionAudit) -> None:
        with self._lock, self._sessions.begin() as session:
            session.add(IntegrationExecutionAuditRow(
                audit_id=audit.audit_id,
                integration_id=audit.integration_id,
                scan_id=audit.scan_id,
                test_case_id=audit.test_case_id,
                requesting_identity_id=audit.requesting_identity_id,
                created_at=audit.created_at,
                audit_data=audit.model_dump(mode="json"),
            ))

    def list_integration_audits(self, limit: int = 100) -> list[IntegrationExecutionAudit]:
        with self._sessions() as session:
            rows = session.scalars(
                select(IntegrationExecutionAuditRow)
                .order_by(IntegrationExecutionAuditRow.created_at.desc())
                .limit(limit)
            ).all()
            return [IntegrationExecutionAudit.model_validate(row.audit_data) for row in rows]

    def save_integration_security_result(
        self,
        result: IntegrationSecurityTestResult,
    ) -> IntegrationSecurityTestResult:
        with self._lock, self._sessions.begin() as session:
            session.add(IntegrationSecurityResultRow(
                test_id=result.test_id,
                scenario=result.scenario.value,
                created_at=result.created_at,
                result_data=result.model_dump(mode="json"),
            ))
        return result

    def list_integration_security_results(
        self,
        limit: int = 100,
    ) -> list[IntegrationSecurityTestResult]:
        with self._sessions() as session:
            rows = session.scalars(
                select(IntegrationSecurityResultRow)
                .order_by(IntegrationSecurityResultRow.created_at.desc())
                .limit(limit)
            ).all()
            return [
                IntegrationSecurityTestResult.model_validate(row.result_data)
                for row in rows
            ]

    def _fernet(self) -> Fernet:
        key = os.getenv("AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY", "").strip()
        if not key:
            raise DatabaseError(
                "AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY must be configured before saving provider credentials."
            )
        try:
            raw = key.encode("ascii")
            Fernet(raw)
        except (ValueError, UnicodeEncodeError) as exc:
            raise DatabaseError(
                "AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key."
            ) from exc
        return Fernet(raw)

    def encrypt_credential(self, credential: str | None) -> str | None:
        if not credential:
            return None
        return self._fernet().encrypt(credential.encode("utf-8")).decode("ascii")

    def decrypt_credential(self, ciphertext: str | None) -> str | None:
        if not ciphertext:
            return None
        try:
            return self._fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeEncodeError) as exc:
            raise DatabaseError("Unable to decrypt stored provider credentials; verify the encryption key.") from exc

    def create_target(self, target: Target) -> None:
        credential = target.api_key.get_secret_value() if target.api_key else None
        encrypted = self.encrypt_credential(credential)
        data = target.model_dump(mode="json", exclude={"api_key"})
        with self._lock, self._sessions.begin() as session:
            session.add(TargetRow(
                target_id=target.target_id,
                name=target.name,
                target_type=target.target_type.value,
                target_scope=target.target_scope.value,
                capability_profile=target.capability_profile.model_dump(mode="json"),
                endpoint=str(target.endpoint),
                model=target.model,
                provider=target.provider.value,
                description=target.description,
                api_path=target.api_path,
                auth_header=target.auth_header,
                system_prompt=target.system_prompt,
                temperature=target.temperature,
                max_output_tokens=target.max_output_tokens,
                connection_status=target.connection_status,
                last_tested=target.last_tested,
                credential_ciphertext=encrypted,
                active=True,
                created_at=datetime.now(timezone.utc),
            ))

    def _target_model(self, row: TargetRow) -> Target:
        secret = self.decrypt_credential(row.credential_ciphertext)
        return Target.model_validate({
            "target_id": row.target_id,
            "name": row.name,
            "target_type": row.target_type,
            "target_scope": row.target_scope,
            "capability_profile": (
                row.capability_profile
                if row.capability_profile is not None
                else default_capability_profile(
                    TargetScope(row.target_scope)
                ).model_dump(mode="json")
            ),
            "endpoint": row.endpoint,
            "model": row.model,
            "provider": row.provider,
            "description": row.description,
            "api_path": row.api_path,
            "auth_header": row.auth_header,
            "system_prompt": row.system_prompt,
            "temperature": row.temperature,
            "max_output_tokens": row.max_output_tokens,
            "connection_status": row.connection_status,
            "last_tested": row.last_tested,
            "api_key": secret,
            "active": row.active,
        })

    def get_target(self, target_id: str, *, include_inactive: bool = False) -> Target | None:
        with self._sessions() as session:
            row = session.get(TargetRow, target_id)
            if row is None or (not row.active and not include_inactive):
                return None
            try:
                return self._target_model(row)
            except ValidationError:
                logger.warning(
                    "Skipping persisted target that fails current endpoint policy: target_id=%s",
                    row.target_id,
                )
                return None

    def list_targets(self) -> list[Target]:
        with self._sessions() as session:
            rows = session.scalars(select(TargetRow).where(TargetRow.active.is_(True)).order_by(TargetRow.created_at.desc())).all()
            targets: list[Target] = []
            for row in rows:
                try:
                    targets.append(self._target_model(row))
                except ValidationError:
                    logger.warning(
                        "Skipping persisted target that fails current endpoint policy: target_id=%s",
                        row.target_id,
                    )
            return targets

    def delete_target(self, target_id: str) -> bool:
        with self._lock, self._sessions.begin() as session:
            row = session.get(TargetRow, target_id)
            if row is None or not row.active:
                return False
            row.active = False
            row.credential_ciphertext = None
            return True

    def update_target(self, target_id: str, target: Target) -> bool:
        credential = target.api_key.get_secret_value() if target.api_key else None
        encrypted = self.encrypt_credential(credential) if credential else None
        with self._lock, self._sessions.begin() as session:
            row = session.get(TargetRow, target_id)
            if row is None or not row.active:
                return False
            provider_changed = row.provider != target.provider.value
            row.name = target.name
            row.target_type = target.target_type.value
            row.target_scope = target.target_scope.value
            row.capability_profile = target.capability_profile.model_dump(mode="json")
            row.endpoint = str(target.endpoint)
            row.model = target.model
            row.provider = target.provider.value
            row.description = target.description
            row.api_path = target.api_path
            row.auth_header = target.auth_header
            row.system_prompt = target.system_prompt
            row.temperature = target.temperature
            row.max_output_tokens = target.max_output_tokens
            if encrypted:
                row.credential_ciphertext = encrypted
            elif provider_changed:
                row.credential_ciphertext = None
            return True

    def update_target_capabilities(
        self,
        target_id: str,
        capability_profile: CapabilityProfile,
    ) -> bool:
        with self._lock, self._sessions.begin() as session:
            row = session.get(TargetRow, target_id)
            if row is None or not row.active:
                return False
            row.capability_profile = capability_profile.model_dump(mode="json")
            return True

    def update_target_credential(self, target_id: str, credential: str | None) -> bool:
        encrypted = self.encrypt_credential(credential)
        with self._lock, self._sessions.begin() as session:
            row = session.get(TargetRow, target_id)
            if row is None or not row.active:
                return False
            row.credential_ciphertext = encrypted
            return True

    def update_target_connectivity(
        self,
        target_id: str,
        status: str,
        tested_at: datetime,
    ) -> bool:
        with self._lock, self._sessions.begin() as session:
            row = session.get(TargetRow, target_id)
            if row is None or not row.active:
                return False
            row.connection_status = status
            row.last_tested = tested_at
            return True

    def save_scan(
        self,
        scan: ScanRecord,
        request: ScanCreateRequest,
        idempotency_key: str | None = None,
    ) -> None:
        data = scan.model_dump(mode="json")
        config = request.model_dump(mode="json", exclude={"authorization_confirmed"})
        with self._lock, self._sessions.begin() as session:
            session.merge(ScanRow(
                scan_id=scan.scan_id,
                target_id=scan.target_id,
                status=scan.status.value,
                created_at=scan.created_at,
                idempotency_key=idempotency_key,
                scan_record=data,
            ))
            session.merge(ScanConfigurationRow(scan_id=scan.scan_id, configuration=config))

    def update_scan(self, scan: ScanRecord) -> None:
        with self._lock, self._sessions.begin() as session:
            row = session.get(ScanRow, scan.scan_id)
            if row is None:
                raise DatabaseError("Cannot update a scan that has not been persisted.")
            row.status = scan.status.value
            row.scan_record = scan.model_dump(mode="json")

    def save_generated_cases(self, scan_id: str, cases: list[FuzzCase]) -> None:
        with self._lock, self._sessions.begin() as session:
            for case in cases:
                session.merge(FuzzCaseRow(
                    case_id=case.case_id,
                    scan_id=scan_id,
                    prompt=case.prompt,
                    category=case.category,
                    case_data=case.model_dump(mode="json"),
                ))

    def get_generated_cases(self, scan_id: str) -> list[FuzzCase] | None:
        with self._sessions() as session:
            if session.get(ScanRow, scan_id) is None:
                return None
            rows = session.scalars(
                select(FuzzCaseRow)
                .where(FuzzCaseRow.scan_id == scan_id)
                .order_by(FuzzCaseRow.case_id)
            ).all()
            return [FuzzCase.model_validate(row.case_data) for row in rows]

    def save_result(self, scan_id: str, result: dict[str, object]) -> None:
        case = result["case"]
        execution = result["execution"]
        analysis = result["analysis"]
        if not isinstance(case, FuzzCase) or not isinstance(execution, ExecutionResult) or not isinstance(analysis, AnalysisResult):
            raise DatabaseError("Scan result has an unexpected model type.")
        with self._lock, self._sessions.begin() as session:
            session.merge(FuzzCaseRow(
                case_id=case.case_id,
                scan_id=scan_id,
                prompt=case.prompt,
                category=case.category,
                case_data=case.model_dump(mode="json"),
            ))
            session.merge(ExecutionRow(
                case_id=case.case_id,
                scan_id=scan_id,
                status=execution.status,
                response_time_ms=execution.response_time_ms,
                provider=execution.provider,
                model=execution.model,
                response_body=execution.response_body,
                execution_data=execution.model_dump(mode="json"),
            ))
            session.merge(AnalysisRow(
                case_id=case.case_id,
                scan_id=scan_id,
                vulnerable=analysis.vulnerable,
                analysis_data=analysis.model_dump(mode="json"),
            ))
            for finding in analysis.findings:
                session.merge(FindingRow(
                    finding_id=finding.finding_id,
                    scan_id=scan_id,
                    case_id=case.case_id,
                    severity=finding.severity.value,
                    category=finding.category,
                    finding_data=finding.model_dump(mode="json"),
                ))

    def save_evidence_provenance(
        self,
        records: list[EvidenceProvenance],
    ) -> None:
        if not records:
            return
        with self._lock, self._sessions.begin() as session:
            for record in records:
                if record.scan_id is not None:
                    scan = session.get(ScanRow, record.scan_id)
                    case = session.get(FuzzCaseRow, record.test_case_id)
                    if (
                        scan is None
                        or scan.target_id != record.target_id
                        or case is None
                        or case.scan_id != record.scan_id
                    ):
                        raise DatabaseError(
                            "Evidence provenance does not match a persisted scan and test case."
                        )
                session.merge(EvidenceProvenanceRow(
                    provenance_id=record.provenance_id,
                    scan_id=record.scan_id,
                    test_case_id=record.test_case_id,
                    target_id=record.target_id,
                    evidence_data=record.model_dump(mode="json"),
                ))

    def get_evidence_provenance(
        self,
        scan_id: str,
        *,
        test_case_id: str | None = None,
    ) -> list[EvidenceProvenance]:
        with self._sessions() as session:
            query = select(EvidenceProvenanceRow).where(
                EvidenceProvenanceRow.scan_id == scan_id
            )
            if test_case_id is not None:
                query = query.where(
                    EvidenceProvenanceRow.test_case_id == test_case_id
                )
            rows = session.scalars(
                query.order_by(EvidenceProvenanceRow.test_case_id)
            ).all()
            return [
                EvidenceProvenance.model_validate(row.evidence_data)
                for row in rows
            ]

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        with self._sessions() as session:
            row = session.get(ScanRow, scan_id)
            return ScanRecord.model_validate(row.scan_record) if row else None

    def get_scan_by_idempotency_key(self, idempotency_key: str) -> ScanRecord | None:
        with self._sessions() as session:
            row = session.scalar(select(ScanRow).where(ScanRow.idempotency_key == idempotency_key))
            return ScanRecord.model_validate(row.scan_record) if row else None

    def list_scans(self) -> list[ScanRecord]:
        with self._sessions() as session:
            rows = session.scalars(select(ScanRow).order_by(ScanRow.created_at.desc())).all()
            return [ScanRecord.model_validate(row.scan_record) for row in rows]

    def get_scan_request(self, scan_id: str) -> ScanCreateRequest | None:
        with self._sessions() as session:
            row = session.get(ScanConfigurationRow, scan_id)
            if row is None:
                return None
            return ScanCreateRequest.model_validate({
                "target_id": session.get(ScanRow, scan_id).target_id,
                **row.configuration,
                "authorization_confirmed": True,
            })

    def get_results(self, scan_id: str) -> list[dict[str, object]] | None:
        with self._sessions() as session:
            scan = session.get(ScanRow, scan_id)
            if scan is None:
                return None
            rows = session.scalars(select(FuzzCaseRow).where(FuzzCaseRow.scan_id == scan_id).order_by(FuzzCaseRow.case_id)).all()
            result_list: list[dict[str, object]] = []
            for row in rows:
                execution = session.get(ExecutionRow, row.case_id)
                analysis = session.get(AnalysisRow, row.case_id)
                if execution is None or analysis is None:
                    continue
                result_list.append({
                    "case": FuzzCase.model_validate(row.case_data),
                    "execution": ExecutionResult.model_validate(execution.execution_data),
                    "analysis": AnalysisResult.model_validate(analysis.analysis_data),
                })
            return result_list

    def save_analysis_history(
        self,
        scan_id: str,
        case_id: str,
        analysis: AnalysisResult,
        *,
        version: int | None = None,
    ) -> int:
        with self._lock, self._sessions.begin() as session:
            if session.get(ScanRow, scan_id) is None:
                raise DatabaseError("Cannot save analysis history for an unknown scan.")
            if version is None:
                current = session.scalar(
                    select(AnalysisHistoryRow.version)
                    .where(
                        AnalysisHistoryRow.scan_id == scan_id,
                        AnalysisHistoryRow.case_id == case_id,
                    )
                    .order_by(AnalysisHistoryRow.version.desc())
                    .limit(1)
                )
                version = int(current or 0) + 1
            history_key = f"{scan_id}:{case_id}:analysis:{version}".encode()
            history_id = "analysis-" + hashlib.sha256(history_key).hexdigest()
            session.add(AnalysisHistoryRow(
                history_id=history_id,
                scan_id=scan_id,
                case_id=case_id,
                version=version,
                created_at=datetime.now(timezone.utc),
                analysis_data=analysis.model_dump(mode="json"),
            ))
            return version

    def get_analysis_history(
        self,
        scan_id: str,
        *,
        case_id: str | None = None,
    ) -> list[AnalysisResult]:
        with self._sessions() as session:
            query = select(AnalysisHistoryRow).where(AnalysisHistoryRow.scan_id == scan_id)
            if case_id is not None:
                query = query.where(AnalysisHistoryRow.case_id == case_id)
            rows = session.scalars(
                query.order_by(AnalysisHistoryRow.case_id, AnalysisHistoryRow.version)
            ).all()
            return [AnalysisResult.model_validate(row.analysis_data) for row in rows]

    def save_report(self, report_id: str, scan_id: str, generated_at: datetime, data: dict[str, Any]) -> None:
        with self._lock, self._sessions.begin() as session:
            session.merge(ReportRow(
                report_id=report_id,
                scan_id=scan_id,
                generated_at=generated_at,
                report_data=data,
            ))

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        with self._sessions() as session:
            row = session.get(ReportRow, report_id)
            return dict(row.report_data) if row else None

    def list_reports(self) -> list[dict[str, Any]]:
        with self._sessions() as session:
            rows = session.scalars(select(ReportRow).order_by(ReportRow.generated_at.desc())).all()
            return [dict(row.report_data) for row in rows]

    def recover_incomplete_scans(self) -> None:
        with self._lock, self._sessions.begin() as session:
            rows = session.scalars(select(ScanRow).where(ScanRow.status.in_([
                ScanStatus.CREATED.value,
                ScanStatus.QUEUED.value,
                ScanStatus.RUNNING.value,
                ScanStatus.PAUSED.value,
            ]))).all()
            for row in rows:
                record = ScanRecord.model_validate(row.scan_record)
                record.status = ScanStatus.FAILED
                record.failure_reason = "Backend restarted before this scan completed."
                record.completed_at = datetime.now(timezone.utc)
                row.status = record.status.value
                row.scan_record = record.model_dump(mode="json")

    def close(self) -> None:
        self.engine.dispose()


database = Database()
database.initialize()

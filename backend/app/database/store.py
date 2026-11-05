from __future__ import annotations

import os
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

from app.adapters.models import Target
from app.analysis.models import AnalysisResult, Finding
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanRecord, ScanStatus


class DatabaseError(RuntimeError):
    pass


class Base(DeclarativeBase):
    pass


class TargetRow(Base):
    __tablename__ = "targets"

    target_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
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


class FindingRow(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("fuzz_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    finding_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


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
            }
            with self.engine.begin() as connection:
                for name, sql_type in migrations.items():
                    if name not in target_columns:
                        connection.execute(text(f"ALTER TABLE targets ADD COLUMN {name} {sql_type}"))
            with self._sessions.begin() as session:
                if session.get(SchemaVersionRow, 1) is None:
                    session.add(SchemaVersionRow(version=1, applied_at=datetime.now(timezone.utc)))
                if session.get(SchemaVersionRow, 2) is None:
                    session.add(SchemaVersionRow(version=2, applied_at=datetime.now(timezone.utc)))
                if session.get(SchemaVersionRow, 3) is None:
                    session.add(SchemaVersionRow(version=3, applied_at=datetime.now(timezone.utc)))
        except SQLAlchemyError as exc:
            raise DatabaseError("Database initialization failed.") from exc

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
            return self._target_model(row)

    def list_targets(self) -> list[Target]:
        with self._sessions() as session:
            rows = session.scalars(select(TargetRow).where(TargetRow.active.is_(True)).order_by(TargetRow.created_at.desc())).all()
            return [self._target_model(row) for row in rows]

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

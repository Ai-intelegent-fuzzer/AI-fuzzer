import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from cryptography.fernet import Fernet
from sqlalchemy.exc import IntegrityError

from app.adapters.manager import TargetManager
from app.adapters.models import TargetCreate, TargetType
from app.analysis.models import AnalysisResult, Finding, Severity, Confidence
from app.database.store import Database, TargetRow
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanRecord, ScanStatus
from app.fuzzing.scheduler import ScanScheduler


class DatabasePersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.database_url = f"sqlite:///{Path(self.temp_dir.name, 'test.sqlite3').as_posix()}"
        self.key = Fernet.generate_key().decode("ascii")
        self.key_patcher = patch.dict(
            "os.environ",
            {"AI_FUZZER_CREDENTIAL_ENCRYPTION_KEY": self.key},
        )
        self.key_patcher.start()
        self.addCleanup(self.key_patcher.stop)

    def _new_store(self) -> Database:
        store = Database(self.database_url)
        store.initialize()
        self.addCleanup(store.close)
        return store

    def test_targets_scans_executions_findings_and_reports_survive_restart(self) -> None:
        first = self._new_store()
        target = TargetManager(first).create(
            TargetCreate(
                name="Persistence test target",
                target_type=TargetType.OPENAI_COMPATIBLE,
                endpoint="https://api.openai.com/v1/chat/completions",
                model="controlled-model",
                api_key="controlled-secret",
                api_path="/v1/chat/completions",
                temperature=0.25,
                max_output_tokens=128,
            )
        )
        request = ScanCreateRequest(
            target_id=target.target_id,
            authorization_confirmed=True,
            count=1,
        )
        scan = ScanRecord(
            scan_id=str(uuid4()),
            target_id=target.target_id,
            status=ScanStatus.COMPLETED,
            requested_case_count=1,
            generated_case_count=1,
            executed_case_count=1,
            finding_count=1,
        )
        first.save_scan(scan, request, "restart-test")
        tested_at = datetime.now(timezone.utc)
        self.assertTrue(first.update_target_connectivity(
            target.target_id,
            "reachable",
            tested_at,
        ))
        case = FuzzCase(
            case_id=str(uuid4()),
            prompt="controlled prompt",
            category="prompt_injection",
        )
        generated_only_case = FuzzCase(
            case_id=str(uuid4()),
            prompt="generated but not executed",
            category="jailbreak",
        )
        first.save_generated_cases(scan.scan_id, [case, generated_only_case])
        finding = Finding(
            finding_id=str(uuid4()),
            case_id=case.case_id,
            target_id=target.target_id,
            scan_id=scan.scan_id,
            category=case.category,
            title="Controlled finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence="Controlled evidence",
            recommendation="Controlled recommendation",
        )
        first.save_result(
            scan.scan_id,
            {
                "case": case,
                "execution": ExecutionResult(
                    target_id=target.target_id,
                    case_id=case.case_id,
                    scan_id=scan.scan_id,
                    status="completed",
                    response_body="controlled response",
                    response_time_ms=12.5,
                    message="controlled execution",
                    provider="openai",
                    model="controlled-model",
                ),
                "analysis": AnalysisResult(
                    target_id=target.target_id,
                    case_id=case.case_id,
                    scan_id=scan.scan_id,
                    category=case.category,
                    vulnerable=True,
                    findings=[finding],
                ),
            },
        )
        report_data = {
            "report_id": scan.scan_id,
            "scan_id": scan.scan_id,
            "findings": [finding.model_dump(mode="json")],
        }
        first.save_report(scan.scan_id, scan.scan_id, datetime.now(timezone.utc), report_data)
        with first._sessions() as session:
            ciphertext = session.get(TargetRow, target.target_id).credential_ciphertext
        self.assertNotEqual(ciphertext, "controlled-secret")

        restarted = Database(self.database_url)
        restarted.initialize()
        self.addCleanup(restarted.close)
        restored_target = restarted.get_target(target.target_id)
        self.assertIsNotNone(restored_target)
        self.assertEqual(restored_target.api_key.get_secret_value(), "controlled-secret")
        self.assertEqual(restored_target.api_path, "/v1/chat/completions")
        self.assertEqual(restored_target.connection_status, "reachable")
        self.assertIsNotNone(restored_target.last_tested)
        self.assertEqual(restarted.get_scan(scan.scan_id).status, ScanStatus.COMPLETED)
        results = restarted.get_results(scan.scan_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["execution"].response_body, "controlled response")
        self.assertEqual(results[0]["analysis"].findings[0].finding_id, finding.finding_id)
        generated_cases = restarted.get_generated_cases(scan.scan_id)
        self.assertEqual(len(generated_cases), 2)
        self.assertEqual(
            {generated.category for generated in generated_cases},
            {"prompt_injection", "jailbreak"},
        )
        self.assertEqual(restarted.get_report(scan.scan_id), report_data)

    def test_failed_duplicate_insert_rolls_back_without_corrupting_saved_target(self) -> None:
        store = self._new_store()
        target = TargetManager(store).create(
            TargetCreate(
                name="Unique target",
                target_type=TargetType.OPENAI_COMPATIBLE,
                endpoint="https://api.openai.com/v1/chat/completions",
            )
        )
        with self.assertRaises(IntegrityError):
            store.create_target(target)
        self.assertEqual(store.get_target(target.target_id).name, "Unique target")

    def test_changing_provider_without_replacement_key_clears_old_credential(self) -> None:
        store = self._new_store()
        manager = TargetManager(store)
        target = manager.create(
            TargetCreate(
                name="Credential isolation target",
                target_type=TargetType.OPENAI_COMPATIBLE,
                endpoint="https://api.openai.com/v1/chat/completions",
                provider="openai",
                api_key="old-provider-key",
            )
        )
        updated = manager.update(
            target.target_id,
            TargetCreate(
                name=target.name,
                target_type=TargetType.OPENAI_COMPATIBLE,
                endpoint="https://api.groq.com/openai/v1/chat/completions",
                provider="groq",
            ),
        )

        self.assertIsNotNone(updated)
        self.assertIsNone(updated.api_key)
        self.assertIsNone(store.get_target(target.target_id).api_key)

    def test_duplicate_scan_submission_returns_existing_idempotent_scan(self) -> None:
        store = self._new_store()
        target = TargetManager(store).create(
            TargetCreate(
                name="Idempotency target",
                target_type=TargetType.OPENAI_COMPATIBLE,
                endpoint="https://api.openai.com/v1/chat/completions",
            )
        )
        scheduler = ScanScheduler(store=store)
        self.addCleanup(lambda: scheduler._executor.shutdown(wait=True))
        with patch.object(scheduler, "_run"):
            request = ScanCreateRequest(
                target_id=target.target_id,
                authorization_confirmed=True,
                count=1,
            )
            first = scheduler.start(request, idempotency_key="same-request")
            second = scheduler.start(request, idempotency_key="same-request")
        self.assertEqual(first.scan_id, second.scan_id)

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from app.adapters.manager import TargetManager, target_manager
from app.adapters.models import (
    CapabilityName,
    CapabilityProfile,
    CapabilitySetting,
    CapabilityValidationStatus,
    TargetCreate,
    TargetScope,
)
from app.database.store import Database
from app.fuzzing.models import ScanRecord, ScanStatus
from app.main import app


class CapabilityProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.database_url = f"sqlite:///{Path(self.temp_dir.name, 'test.sqlite3').as_posix()}"
        self.store = Database(self.database_url)
        self.store.initialize()
        self.addCleanup(self.store.close)
        self.manager = TargetManager(self.store)

    def _target_data(self, **updates: object) -> TargetCreate:
        values: dict[str, object] = {
            "name": "Capability profile test target",
            "target_type": "openai_compatible",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "provider": "openai",
        }
        values.update(updates)
        return TargetCreate.model_validate(values)

    def test_legacy_defaults_only_assert_configured_model_endpoint(self) -> None:
        target = self.manager.create(self._target_data())

        self.assertEqual(target.target_scope, TargetScope.MODEL_ENDPOINT)
        self.assertTrue(target.capability_profile.capabilities[CapabilityName.MODEL_ENDPOINT].enabled)
        for capability in CapabilityName:
            if capability != CapabilityName.MODEL_ENDPOINT:
                setting = target.capability_profile.capabilities[capability]
                self.assertFalse(setting.enabled)
                self.assertEqual(
                    setting.validation_status,
                    CapabilityValidationStatus.NOT_CONFIGURED,
                )

    def test_capability_settings_reject_invalid_enabled_state_and_duplicates(self) -> None:
        with self.assertRaises(ValueError):
            CapabilitySetting(enabled=True)
        with self.assertRaises(ValueError):
            CapabilitySetting(
                enabled=True,
                validation_status=CapabilityValidationStatus.CONFIGURED,
                supported_security_tests=["rag_security", "rag_security"],
            )

    def test_explicit_target_scope_is_not_rewritten_on_initialization(self) -> None:
        target = self.manager.create(self._target_data(
            target_type="chatbot",
            target_scope="model_endpoint",
        ))

        self.store.initialize()

        self.assertEqual(self.store.get_target(target.target_id).target_scope, TargetScope.MODEL_ENDPOINT)

    def test_capability_profile_persists_and_legacy_target_update_preserves_it(self) -> None:
        target = self.manager.create(self._target_data())
        profile = CapabilityProfile.model_validate({
            "capabilities": {
                "rag_enabled": {
                    "enabled": True,
                    "configuration_reference": "synthetic-dataset-1",
                    "validation_status": "configured",
                    "supported_security_tests": ["rag_security"],
                    "known_limitations": ["Local synthetic dataset only."],
                }
            }
        })
        self.assertIsNotNone(self.manager.update_capabilities(target.target_id, profile))

        legacy_update = self._target_data(name="Updated legacy client")
        updated = self.manager.update(target.target_id, legacy_update)
        restored = self.store.get_target(target.target_id)

        self.assertEqual(updated.name, "Updated legacy client")
        self.assertEqual(updated.capability_profile, profile)
        self.assertEqual(restored.capability_profile, profile)

    def test_old_schema_migrates_additively_and_preserves_existing_target_and_scan(self) -> None:
        legacy_database_url = (
            f"sqlite:///{Path(self.temp_dir.name, 'legacy.sqlite3').as_posix()}"
        )
        legacy_target_id = str(uuid4())
        legacy_scan_id = str(uuid4())
        legacy_scan = {
            "scan_id": legacy_scan_id,
            "target_id": legacy_target_id,
            "status": "completed",
            "requested_case_count": 1,
        }
        engine = create_engine(legacy_database_url)
        with engine.begin() as connection:
            connection.execute(text("""
                CREATE TABLE targets (
                    target_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    target_type VARCHAR(40) NOT NULL,
                    endpoint TEXT NOT NULL,
                    model VARCHAR(200),
                    provider VARCHAR(40) NOT NULL,
                    description TEXT,
                    credential_ciphertext TEXT,
                    active BOOLEAN NOT NULL DEFAULT 1,
                    created_at DATETIME NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE scans (
                    scan_id VARCHAR(36) PRIMARY KEY,
                    target_id VARCHAR(36) NOT NULL REFERENCES targets(target_id),
                    status VARCHAR(24) NOT NULL,
                    created_at DATETIME NOT NULL,
                    idempotency_key VARCHAR(160) UNIQUE,
                    scan_record JSON NOT NULL
                )
            """))
            connection.execute(text("""
                CREATE TABLE schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at DATETIME NOT NULL
                )
            """))
            connection.execute(text("""
                INSERT INTO targets
                    (target_id, name, target_type, endpoint, provider, active, created_at)
                VALUES
                    (:target_id, 'Legacy RAG target', 'rag',
                     'https://api.openai.com/v1/chat/completions', 'openai', 1, :created_at)
            """), {
                "target_id": legacy_target_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
            connection.execute(text("""
                INSERT INTO scans (scan_id, target_id, status, created_at, scan_record)
                VALUES (:scan_id, :target_id, 'completed', :created_at, :scan_record)
            """), {
                "scan_id": legacy_scan_id,
                "target_id": legacy_target_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "scan_record": json.dumps(legacy_scan),
            })
            connection.execute(text(
                "INSERT INTO schema_version (version, applied_at) VALUES "
                "(1, CURRENT_TIMESTAMP), (2, CURRENT_TIMESTAMP), (3, CURRENT_TIMESTAMP)"
            ))
        engine.dispose()

        migrated_store = Database(legacy_database_url)
        self.addCleanup(migrated_store.close)
        migrated_store.initialize()
        migrated_store.initialize()

        migrated_target = migrated_store.get_target(legacy_target_id)
        migrated_scan = migrated_store.get_scan(legacy_scan_id)
        self.assertEqual(migrated_target.target_scope, TargetScope.AI_APPLICATION)
        self.assertFalse(migrated_target.capability_profile.capabilities[CapabilityName.RAG_ENABLED].enabled)
        self.assertEqual(migrated_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(migrated_scan.capability_profile, None)
        columns = {
            column["name"]
            for column in inspect(migrated_store.engine).get_columns("targets")
        }
        self.assertIn("target_scope", columns)
        self.assertIn("capability_profile", columns)
        with migrated_store._sessions() as session:
            versions = set(session.scalars(text("SELECT version FROM schema_version")))
        self.assertEqual(versions, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})

    def test_target_api_supports_capabilities_and_legacy_update_payload(self) -> None:
        client = TestClient(app)
        created = client.post("/targets", json={
            "name": "API capability target",
            "target_type": "openai_compatible",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "provider": "openai",
        })
        self.assertEqual(created.status_code, 201)
        target_id = created.json()["target_id"]
        self.addCleanup(target_manager.delete, target_id)

        capability_response = client.put(
            f"/targets/{target_id}/capabilities",
            json={
                "capabilities": {
                    "tool_calling": {
                        "enabled": True,
                        "configuration_reference": "synthetic-toolset",
                        "validation_status": "unverified",
                        "supported_security_tests": ["tool_misuse"],
                        "known_limitations": ["Simulation only."],
                    }
                }
            },
        )
        self.assertEqual(capability_response.status_code, 200)
        self.assertTrue(capability_response.json()["capability_profile"]["capabilities"]["tool_calling"]["enabled"])

        legacy_update = client.put(f"/targets/{target_id}", json={
            "name": "Updated by old client",
            "target_type": "openai_compatible",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "provider": "openai",
        })
        self.assertEqual(legacy_update.status_code, 200)
        payload = legacy_update.json()
        self.assertEqual(payload["name"], "Updated by old client")
        self.assertEqual(payload["target_scope"], "model_endpoint")
        self.assertTrue(payload["capability_profile"]["capabilities"]["tool_calling"]["enabled"])

    def test_scan_api_snapshots_capabilities_without_running_a_scan(self) -> None:
        client = TestClient(app)
        created = client.post("/targets", json={
            "name": "Snapshot target",
            "target_type": "openai_compatible",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "provider": "openai",
        })
        self.assertEqual(created.status_code, 201)
        target_id = created.json()["target_id"]
        self.addCleanup(target_manager.delete, target_id)

        queued_scan = ScanRecord(
            scan_id=str(uuid4()),
            target_id=target_id,
            target_scope=TargetScope.MODEL_ENDPOINT,
            capability_profile=CapabilityProfile.model_validate(
                created.json()["capability_profile"]
            ),
            status=ScanStatus.QUEUED,
            requested_case_count=1,
        )
        with patch("app.api.scan.scan_scheduler.start", return_value=queued_scan) as start:
            response = client.post("/scans", json={
                "target_id": target_id,
                "authorization_confirmed": True,
                "count": 1,
                "categories": ["prompt_injection"],
            })

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["capability_profile"], created.json()["capability_profile"])
        self.assertEqual(start.call_args.kwargs["target_scope"], TargetScope.MODEL_ENDPOINT)
        self.assertEqual(start.call_args.kwargs["capability_profile"], CapabilityProfile.model_validate(
            created.json()["capability_profile"]
        ))


if __name__ == "__main__":
    unittest.main()

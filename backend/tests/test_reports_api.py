import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.adapters.models import Target
from app.analysis.models import (
    AnalysisOutcome,
    AnalysisResult,
    AnalysisStatus,
    Confidence,
    Finding,
    Severity,
)
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanMetrics, ScanRecord, ScanStatus
from app.main import app


class ReportApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        report_save = patch("app.api.reports.database.save_report")
        report_save.start()
        self.addCleanup(report_save.stop)
        generated_cases = patch(
            "app.api.reports.database.get_generated_cases",
            return_value=[],
        )
        generated_cases.start()
        self.addCleanup(generated_cases.stop)
        self.scan = ScanRecord(
            scan_id="controlled-scan",
            target_id="controlled-target",
            status=ScanStatus.COMPLETED,
            requested_case_count=1,
            generated_case_count=1,
            executed_case_count=1,
            finding_count=1,
            metrics=ScanMetrics(total_generated_cases=1, total_executed_cases=1, findings=1),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        self.finding = Finding(
            finding_id="controlled-finding",
            case_id="controlled-case",
            target_id="controlled-target",
            scan_id="controlled-scan",
            category="prompt_injection",
            title="Synthetic analyzer finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence="Only controlled synthetic evidence.",
            recommendation="Keep the test target within the authorized scope.",
        )
        self.result = {
            "case": FuzzCase(
                case_id="controlled-case",
                prompt="synthetic test prompt",
                category="prompt_injection",
            ),
            "execution": ExecutionResult(
                target_id="controlled-target",
                case_id="controlled-case",
                scan_id="controlled-scan",
                status="completed",
                response_time_ms=12.5,
                response_body="synthetic response",
                message="Fuzz case executed successfully.",
            ),
            "analysis": AnalysisResult(
                target_id="controlled-target",
                case_id="controlled-case",
                scan_id="controlled-scan",
                category="prompt_injection",
                vulnerable=True,
                status=AnalysisStatus.FAIL,
                outcome=AnalysisOutcome.VULNERABILITY_DETECTED,
                findings=[self.finding],
            ),
        }

    @patch("app.api.reports.target_manager.get")
    @patch("app.api.reports.scan_scheduler.get_request")
    @patch("app.api.reports.scan_scheduler.get_results")
    @patch("app.api.reports.scan_scheduler.get")
    @patch("app.api.reports.scan_scheduler.list")
    def test_report_list_and_detail_use_only_available_scan_results(
        self, list_scans, get_scan, get_results, get_request, get_target
    ) -> None:
        list_scans.return_value = [self.scan]
        get_scan.return_value = self.scan
        get_results.return_value = [self.result]
        get_request.return_value = ScanCreateRequest(
            target_id="controlled-target",
            count=1,
            categories=["prompt_injection"],
        )
        get_target.return_value = Target(
            target_id="controlled-target",
            name="Controlled local target",
            target_type="chatbot",
            endpoint="http://127.0.0.1:8001/chat",
        )

        response = self.client.get("/reports")
        self.assertEqual(response.status_code, 200)
        report = response.json()[0]
        self.assertEqual(report["report_id"], "controlled-scan")
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["tests_executed"], 1)
        self.assertEqual(report["requested_cases"], 1)
        self.assertEqual(report["generated_cases"], 1)
        self.assertEqual(report["failed_executions"], 0)
        self.assertEqual(report["inconclusive_analyses"], 0)
        self.assertEqual(report["categories_requested"], ["prompt_injection"])
        self.assertEqual(report["categories_generated"], ["prompt_injection"])
        self.assertEqual(report["categories_executed"], ["prompt_injection"])
        self.assertEqual(report["category_coverage_percent"], 100)
        self.assertEqual(report["findings_by_severity"]["high"], 1)
        self.assertIn("identified 1 finding", report["conclusion"])
        self.assertEqual(report["detailed_findings"][0]["id"], "controlled-finding")

        detail = self.client.get("/reports/controlled-scan")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["target_name"], "Controlled local target")
        self.assertEqual(detail.json()["detailed_findings"][0]["evidence"], "Only controlled synthetic evidence.")
        self.assertIn("findings_by_severity", detail.json())

    @patch("app.api.reports.target_manager.get", return_value=None)
    @patch("app.api.reports.scan_scheduler.get_request")
    @patch("app.api.reports.scan_scheduler.get_results")
    @patch("app.api.reports.scan_scheduler.get")
    def test_incomplete_report_is_inconclusive_and_uses_actual_categories(
        self, get_scan, get_results, get_request, _get_target
    ) -> None:
        self.scan.requested_case_count = 2
        self.scan.requested_categories = ["prompt_injection", "jailbreak"]
        self.scan.generated_categories = ["prompt_injection", "jailbreak"]
        self.scan.generated_case_count = 2
        get_scan.return_value = self.scan
        get_request.return_value = ScanCreateRequest(
            target_id="controlled-target",
            count=2,
            categories=["prompt_injection", "jailbreak"],
        )
        failed_execution = self.result["execution"].model_copy(
            update={
                "status": "invalid_response",
                "response_body": None,
                "failure_reason": "provider_response_empty",
            }
        )
        inconclusive_analysis = self.result["analysis"].model_copy(
            update={
                "status": AnalysisStatus.INCONCLUSIVE,
                "outcome": AnalysisOutcome.EXECUTION_FAILED,
                "vulnerable": False,
                "findings": [],
            }
        )
        get_results.return_value = [{
            **self.result,
            "execution": failed_execution,
            "analysis": inconclusive_analysis,
        }]

        response = self.client.post("/reports/controlled-scan/generate")

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["tests_executed"], 1)
        self.assertEqual(report["failed_executions"], 1)
        self.assertEqual(report["inconclusive_analyses"], 1)
        self.assertEqual(report["categories_executed"], ["prompt_injection"])
        self.assertEqual(report["category_coverage_percent"], 50)
        self.assertIn("Assessment is inconclusive", report["conclusion"])
        self.assertNotIn("No vulnerabilities were detected", report["conclusion"])

    @patch("app.api.reports.scan_scheduler.get_results", return_value=None)
    @patch("app.api.reports.scan_scheduler.get")
    def test_report_is_not_available_without_results(self, get_scan, _get_results) -> None:
        get_scan.return_value = self.scan

        response = self.client.get("/reports/controlled-scan")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Report is not available for this scan")
        _get_results.assert_called_once_with("controlled-scan")

    def test_scan_category_and_findings_routes_are_not_shadowed_by_scan_id_route(self) -> None:
        categories = self.client.get("/scans/categories")
        findings = self.client.get("/scans/findings")

        self.assertEqual(categories.status_code, 200)
        self.assertIn("prompt_injection", categories.json())
        self.assertEqual(findings.status_code, 200)

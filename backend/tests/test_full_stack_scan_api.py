import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.adapters.manager import target_manager
from app.main import app
from fixtures.mock_target import PromptRequest, chat


class FullStackScanApiTests(unittest.TestCase):
    def test_controlled_local_target_to_report_workflow(self) -> None:
        class ControlledTargetHandler(BaseHTTPRequestHandler):
            def _respond(self, payload: dict[str, object]) -> None:
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                self._respond({"status": "ready"})

            def do_POST(self) -> None:
                request_body = self.rfile.read(int(self.headers["Content-Length"]))
                prompt = PromptRequest.model_validate(json.loads(request_body))
                self._respond(chat(prompt))

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), ControlledTargetHandler)
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        client = TestClient(app)
        endpoint = f"http://127.0.0.1:{server.server_port}/chat"
        target_id: str | None = None
        try:
            with patch.dict("os.environ", {"AI_FUZZER_ALLOW_PRIVATE_TARGETS": "true"}):
                target_response = client.post(
                    "/targets",
                    json={
                        "name": "Controlled local integration target",
                        "target_type": "chatbot",
                        "endpoint": endpoint,
                        "description": "Test-only local mock target",
                    },
                )
                self.assertEqual(target_response.status_code, 201)
                target_id = target_response.json()["target_id"]

                unauthorized_connectivity = client.post(
                    f"/targets/{target_id}/connectivity",
                    json={"authorization_confirmed": False},
                )
                self.assertEqual(unauthorized_connectivity.status_code, 403)
                connectivity = client.post(
                    f"/targets/{target_id}/connectivity",
                    json={"authorization_confirmed": True},
                )
                self.assertEqual(connectivity.status_code, 200)
                self.assertEqual(connectivity.json()["status"], "reachable")

                denied = client.post(
                    "/scans",
                    json={"target_id": target_id, "count": 1, "categories": ["prompt_injection"]},
                )
                self.assertEqual(denied.status_code, 403)

                started = client.post(
                    "/scans",
                    json={
                        "target_id": target_id,
                        "authorization_confirmed": True,
                        "count": 1,
                        "categories": ["prompt_injection"],
                        "max_mutation_depth": 0,
                        "max_mutations_per_case": 0,
                        "timeout_seconds": 2,
                        "max_retries": 0,
                        "concurrency": 1,
                        "delay_seconds": 0,
                    },
                )
                self.assertEqual(started.status_code, 202)
                scan_id = started.json()["scan_id"]

                deadline = time.monotonic() + 10
                scan = started.json()
                while scan["status"] in {"created", "queued", "running"} and time.monotonic() < deadline:
                    time.sleep(0.025)
                    scan_response = client.get(f"/scans/{scan_id}")
                    self.assertEqual(scan_response.status_code, 200)
                    scan = scan_response.json()

                self.assertEqual(scan["status"], "completed")
                self.assertEqual(scan["generated_case_count"], 1)
                self.assertEqual(scan["executed_case_count"], 1)
                self.assertEqual(scan["finding_count"], 0)

                results_response = client.get(f"/scans/{scan_id}/results")
                self.assertEqual(results_response.status_code, 200)
                results = results_response.json()
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["execution"]["status"], "completed")
                self.assertIn("response", results[0]["execution"]["response_body"])
                self.assertIn("analysis", results[0])
                self.assertEqual(results[0]["analysis"]["outcome"], "inconclusive")

                findings_response = client.get(f"/scans/{scan_id}/findings")
                self.assertEqual(findings_response.status_code, 200)
                self.assertEqual(findings_response.json(), [])
                global_findings = client.get("/scans/findings")
                self.assertEqual(global_findings.status_code, 200)

                report_list = client.get("/reports")
                self.assertEqual(report_list.status_code, 200)
                report = next(item for item in report_list.json() if item["report_id"] == scan_id)
                report_detail = client.get(f"/reports/{scan_id}")
                self.assertEqual(report_detail.status_code, 200)
                self.assertEqual(report_detail.json()["tests_executed"], 1)
                self.assertEqual(report["findings_count"], scan["finding_count"])
                self.assertIn("inconclusive", report_detail.json()["conclusion"].lower())

                overview = client.get("/scans/analytics/overview")
                severity = client.get("/scans/analytics/severity")
                categories = client.get("/scans/analytics/categories")
                self.assertEqual(overview.status_code, 200)
                self.assertGreaterEqual(overview.json()["tests_executed"], 1)
                self.assertEqual(severity.status_code, 200)
                self.assertEqual(categories.status_code, 200)
        finally:
            if target_id is not None:
                target_manager.delete(target_id)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

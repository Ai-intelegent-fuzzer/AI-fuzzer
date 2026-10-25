import unittest
from threading import Event
from unittest.mock import patch

import httpx

from app.adapters.provider_security import bounded_post, validate_provider_endpoint
from app.fuzzing.models import ScanCreateRequest, ScanStatus
from app.fuzzing.scheduler import ScanQueueFullError, ScanScheduler


class ProviderEndpointSecurityTests(unittest.TestCase):
    def test_only_official_https_hosts_and_routes_are_accepted(self) -> None:
        validate_provider_endpoint("openai", "https://api.openai.com/v1/chat/completions")
        validate_provider_endpoint("groq", "https://api.groq.com/openai/v1/chat/completions")
        validate_provider_endpoint("gemini", "https://generativelanguage.googleapis.com/v1beta")

        for provider, endpoint in [
            ("groq", "http://api.groq.com/openai/v1/chat/completions"),
            ("openai", "https://attacker.example/v1/chat/completions"),
            ("openai", "https://user:password@api.openai.com/v1/chat/completions"),
            ("openai", "https://api.openai.com/v1/models"),
            ("gemini", "https://attacker.example/v1beta"),
        ]:
            with self.subTest(provider=provider, endpoint=endpoint):
                with self.assertRaises(ValueError):
                    validate_provider_endpoint(provider, endpoint)

    def test_success_response_is_bounded_during_stream_read(self) -> None:
        calls = []
        real_client = httpx.Client

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, content=b"x" * 4096, request=request)

        with patch(
            "app.adapters.provider_security.httpx.Client",
            side_effect=lambda **kwargs: real_client(
                transport=httpx.MockTransport(handler), **kwargs
            ),
        ):
            response = bounded_post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": "Bearer test-only"},
                json={"model": "test", "messages": []},
                timeout=1,
                max_bytes=128,
            )

        self.assertEqual(len(calls), 1)
        self.assertTrue(response.extensions["ai_fuzzer_response_too_large"])
        self.assertEqual(response.content, b"")

    def test_redirect_is_not_followed(self) -> None:
        calls = []
        real_client = httpx.Client

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(
                302,
                headers={"Location": "https://attacker.example/steal"},
                request=request,
            )

        with patch(
            "app.adapters.provider_security.httpx.Client",
            side_effect=lambda **kwargs: real_client(
                transport=httpx.MockTransport(handler), **kwargs
            ),
        ):
            response = bounded_post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": "Bearer test-only"},
                json={"model": "test", "messages": []},
                timeout=1,
                max_bytes=128,
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(calls), 1)


class ScanResourceManagementTests(unittest.TestCase):
    def test_queue_applies_backpressure_and_cleans_worker_references(self) -> None:
        scheduler = ScanScheduler(max_workers=1, max_pending_scans=0, max_retained_scans=5)
        started, release = Event(), Event()

        def blocked_run(**kwargs):
            started.set()
            release.wait(timeout=3)
            return []

        try:
            with patch("app.fuzzing.scheduler.fuzz_orchestrator.run", side_effect=blocked_run):
                scan = scheduler.start(ScanCreateRequest(target_id="target-1", count=1))
                future = scheduler._futures[scan.scan_id]
                self.assertTrue(started.wait(timeout=1))
                with self.assertRaises(ScanQueueFullError):
                    scheduler.start(ScanCreateRequest(target_id="target-2", count=1))
                release.set()
                future.result(timeout=4)

            completed = scheduler.get(scan.scan_id)
            self.assertEqual(completed.status, ScanStatus.COMPLETED)
            self.assertIn(scan.scan_id, scheduler._results)
            self.assertNotIn(scan.scan_id, scheduler._requests)
            self.assertNotIn(scan.scan_id, scheduler._cancel_events)
            self.assertIn(scan.scan_id, scheduler._futures)
            self.assertTrue(scheduler._futures[scan.scan_id].done())
        finally:
            release.set()
            scheduler._executor.shutdown(wait=True, cancel_futures=True)

    def test_retention_prunes_oldest_terminal_scan_and_results(self) -> None:
        scheduler = ScanScheduler(max_workers=1, max_pending_scans=2, max_retained_scans=1)
        try:
            with patch("app.fuzzing.scheduler.fuzz_orchestrator.run", return_value=[]):
                first = scheduler.start(ScanCreateRequest(target_id="target-1", count=1))
                future = scheduler._futures[first.scan_id]
                future.result(timeout=3)
                second = scheduler.start(ScanCreateRequest(target_id="target-2", count=1))
                self.assertIsNone(scheduler.get(first.scan_id))
                self.assertIsNone(scheduler.get_results(first.scan_id))
                second_future = scheduler._futures.get(second.scan_id)
                if second_future is not None:
                    second_future.result(timeout=3)
        finally:
            scheduler._executor.shutdown(wait=True, cancel_futures=True)


if __name__ == "__main__":
    unittest.main()

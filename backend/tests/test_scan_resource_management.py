import threading
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.api.scan import start_scan

from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase, ScanCreateRequest, ScanStatus
from app.fuzzing.orchestrator import FuzzOrchestrator
from app.fuzzing.scheduler import (
    ScanQueueFullError,
    ScanScheduler,
    ScanSchedulerShuttingDownError,
)


class ScanResourceManagementTests(unittest.TestCase):
    def test_scan_queue_applies_backpressure(self) -> None:
        scheduler = ScanScheduler(max_workers=1, max_pending_scans=1, max_retained_scans=2)
        started = threading.Event()
        release = threading.Event()

        def blocked_run(**kwargs):
            started.set()
            release.wait(timeout=3)
            return []

        try:
            with patch("app.fuzzing.scheduler.fuzz_orchestrator.run", side_effect=blocked_run):
                first = scheduler.start(ScanCreateRequest(target_id="target-1", count=1))
                self.assertTrue(started.wait(timeout=2))
                with self.assertRaises(ScanQueueFullError):
                    scheduler.start(ScanCreateRequest(target_id="target-2", count=1))
                release.set()
                scheduler._futures[first.scan_id].result(timeout=3)
                self.assertEqual(scheduler.get(first.scan_id).status, ScanStatus.COMPLETED)
        finally:
            release.set()
            scheduler._executor.shutdown(wait=True)

    def test_old_completed_scans_and_results_are_pruned(self) -> None:
        scheduler = ScanScheduler(max_workers=1, max_pending_scans=1, max_retained_scans=2)
        try:
            with patch("app.fuzzing.scheduler.fuzz_orchestrator.run", return_value=[]):
                scans = []
                for _ in range(3):
                    scan = scheduler.start(ScanCreateRequest(target_id="target-1", count=1))
                    scheduler._futures[scan.scan_id].result(timeout=3)
                    scans.append(scan.scan_id)
            self.assertIsNone(scheduler.get(scans[0]))
            self.assertIsNone(scheduler.get_results(scans[0]))
            self.assertIsNotNone(scheduler.get(scans[1]))
            self.assertIsNotNone(scheduler.get(scans[2]))
            self.assertLessEqual(len(scheduler._scans), 2)
            self.assertEqual(set(scheduler._scans), set(scheduler._results))
        finally:
            scheduler._executor.shutdown(wait=True)


    @patch("app.api.scan.target_manager.get", return_value=object())
    @patch(
        "app.api.scan.scan_scheduler.start",
        side_effect=ScanQueueFullError("internal queue detail"),
    )
    def test_api_returns_429_when_scan_queue_is_full(
        self, _start_mock, _target_mock
    ) -> None:
        with self.assertRaises(HTTPException) as caught:
            start_scan(ScanCreateRequest(target_id="target-1", count=1))

        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(
            caught.exception.detail,
            "Scan queue is full. Retry after an existing scan finishes.",
        )

    def test_running_scan_can_be_cancelled_cooperatively(self) -> None:
        scheduler = ScanScheduler(max_workers=1, max_pending_scans=2)
        started = threading.Event()

        def cancellable_run(**kwargs):
            started.set()
            kwargs["cancel_event"].wait(timeout=3)
            return []

        try:
            with patch(
                "app.fuzzing.scheduler.fuzz_orchestrator.run",
                side_effect=cancellable_run,
            ):
                scan = scheduler.start(
                    ScanCreateRequest(target_id="target-1", count=1)
                )
                self.assertTrue(started.wait(timeout=2))

                cancelled = scheduler.cancel(scan.scan_id)
                self.assertIsNotNone(cancelled)
                scheduler._futures[scan.scan_id].result(timeout=3)

                final_scan = scheduler.get(scan.scan_id)
                self.assertIsNotNone(final_scan)
                self.assertEqual(final_scan.status, ScanStatus.CANCELLED)
        finally:
            scheduler.shutdown(wait=True)

    def test_cancellation_interrupts_rate_limit_wait_before_next_execution(self) -> None:
        wait_started = threading.Event()

        class ObservableCancelEvent(threading.Event):
            def wait(self, timeout=None) -> bool:
                if timeout is not None and timeout > 0:
                    wait_started.set()
                return super().wait(timeout)

        cancel_event = ObservableCancelEvent()
        cases = [
            FuzzCase(
                case_id=f"case-{index}",
                prompt="controlled test prompt",
                category="prompt_injection",
            )
            for index in range(2)
        ]
        execution = ExecutionResult(
            target_id="target-1",
            case_id=cases[0].case_id,
            status="completed",
            response_body="No security issue.",
            message="ok",
        )
        results = []
        orchestrator = FuzzOrchestrator()

        with (
            patch("app.fuzzing.orchestrator.target_manager.get", return_value=object()),
            patch("app.fuzzing.orchestrator.fuzz_engine.generate", return_value=cases),
            patch(
                "app.fuzzing.orchestrator.fuzz_executor.execute",
                return_value=execution,
            ) as execute,
        ):
            worker = threading.Thread(
                target=lambda: results.extend(
                    orchestrator.run(
                        "target-1",
                        count=2,
                        max_mutation_depth=0,
                        delay_seconds=10,
                        concurrency=1,
                        cancel_event=cancel_event,
                    )
                )
            )
            worker.start()
            self.assertTrue(wait_started.wait(timeout=2))
            cancel_event.set()
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(len(results), 1)

    def test_shutdown_cancels_queued_and_running_scans(self) -> None:
        scheduler = ScanScheduler(max_workers=1, max_pending_scans=2)
        started = threading.Event()

        def cancellable_run(**kwargs):
            started.set()
            kwargs["cancel_event"].wait(timeout=3)
            return []

        with patch(
            "app.fuzzing.scheduler.fuzz_orchestrator.run",
            side_effect=cancellable_run,
        ):
            running = scheduler.start(
                ScanCreateRequest(target_id="target-1", count=1)
            )
            self.assertTrue(started.wait(timeout=2))
            queued = scheduler.start(
                ScanCreateRequest(target_id="target-2", count=1)
            )

            scheduler.shutdown(wait=True)

        self.assertEqual(scheduler.get(running.scan_id).status, ScanStatus.CANCELLED)
        self.assertEqual(scheduler.get(queued.scan_id).status, ScanStatus.CANCELLED)


    def test_scheduler_rejects_new_scans_after_shutdown(self) -> None:
        scheduler = ScanScheduler(max_workers=1)
        scheduler.shutdown(wait=True)
        with self.assertRaises(ScanSchedulerShuttingDownError):
            scheduler.start(ScanCreateRequest(target_id="target-1", count=1))


    @patch("app.api.scan.target_manager.get", return_value=object())
    @patch(
        "app.api.scan.scan_scheduler.start",
        side_effect=ScanSchedulerShuttingDownError("internal shutdown detail"),
    )
    def test_api_returns_503_when_scheduler_is_shutting_down(
        self, _start_mock, _target_mock
    ) -> None:
        with self.assertRaises(HTTPException) as caught:
            start_scan(ScanCreateRequest(target_id="target-1", count=1))
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(
            caught.exception.detail,
            "Scan scheduler is shutting down. Retry later.",
        )


if __name__ == "__main__":
    unittest.main()

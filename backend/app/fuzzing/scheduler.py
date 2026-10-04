from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Event, Lock
from uuid import uuid4

from app.fuzzing.models import (
    FuzzCase,
    ScanCreateRequest,
    ScanMetrics,
    ScanRecord,
    ScanStatus,
    FuzzingCoverage,
)
from app.fuzzing.orchestrator import fuzz_orchestrator


class ScanScheduler:
    def __init__(self, max_workers: int = 2) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._lock = Lock()
        self._scans: dict[str, ScanRecord] = {}
        self._requests: dict[str, ScanCreateRequest] = {}
        self._results: dict[str, list[dict[str, object]]] = {}
        self._cancel_events: dict[str, Event] = {}
        self._futures: dict[str, Future[None]] = {}

    def start(self, request: ScanCreateRequest) -> ScanRecord:
        scan_id = str(uuid4())
        scan = ScanRecord(
            scan_id=scan_id,
            target_id=request.target_id,
            status=ScanStatus.QUEUED,
            requested_case_count=request.count,
        )
        with self._lock:
            self._scans[scan_id] = scan
            self._requests[scan_id] = request.model_copy(deep=True)
            self._results[scan_id] = []
            self._cancel_events[scan_id] = Event()
            self._futures[scan_id] = self._executor.submit(self._run, scan_id)
        return scan.model_copy(deep=True)

    def get(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            scan = self._scans.get(scan_id)
            return scan.model_copy(deep=True) if scan is not None else None

    def get_results(self, scan_id: str) -> list[dict[str, object]] | None:
        with self._lock:
            results = self._results.get(scan_id)
            return [dict(result) for result in results] if results is not None else None

    def cancel(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return None
            if scan.status in {
                ScanStatus.COMPLETED,
                ScanStatus.FAILED,
                ScanStatus.CANCELLED,
            }:
                return scan.model_copy(deep=True)
            self._cancel_events[scan_id].set()
            future = self._futures[scan_id]
            if future.cancel():
                scan.status = ScanStatus.CANCELLED
                scan.completed_at = datetime.now(timezone.utc)
            return scan.model_copy(deep=True)

    def _run(self, scan_id: str) -> None:
        with self._lock:
            scan = self._scans[scan_id]
            request = self._requests[scan_id]
            cancel_event = self._cancel_events[scan_id]
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)

        try:
            results = fuzz_orchestrator.run(
                target_id=request.target_id,
                count=request.count,
                categories=request.categories,
                max_mutation_depth=request.max_mutation_depth,
                max_cases=100,
                max_mutations_per_case=request.max_mutations_per_case,
                timeout_seconds=request.timeout_seconds,
                max_retries=request.max_retries,
                concurrency=request.concurrency,
                delay_seconds=request.delay_seconds,
                execution_order=request.execution_order,
                multi_turn=request.multi_turn,
                turns_per_conversation=request.turns_per_conversation,
                cancel_event=cancel_event,
            )
            if results is None:
                raise ValueError("Target no longer exists")
            metrics, coverage = self._calculate_metrics(results)
            with self._lock:
                scan = self._scans[scan_id]
                self._results[scan_id] = results
                scan.generated_case_count = metrics.total_generated_cases
                scan.executed_case_count = metrics.total_executed_cases
                scan.finding_count = metrics.findings
                scan.error_count = metrics.failed_executions
                scan.metrics = metrics
                scan.coverage = coverage
                scan.status = (
                    ScanStatus.CANCELLED if cancel_event.is_set() else ScanStatus.COMPLETED
                )
                scan.completed_at = datetime.now(timezone.utc)
        except Exception as exc:
            with self._lock:
                scan = self._scans[scan_id]
                scan.status = ScanStatus.FAILED
                scan.failure_reason = str(exc)
                scan.error_count += 1
                scan.completed_at = datetime.now(timezone.utc)

    def _calculate_metrics(
        self,
        results: list[dict[str, object]],
    ) -> tuple[ScanMetrics, FuzzingCoverage]:
        cases = [result["case"] for result in results]
        executions = [result["execution"] for result in results]
        analyses = [result["analysis"] for result in results]
        categories: dict[str, dict[str, int]] = {}
        for case, execution, analysis in zip(cases, executions, analyses):
            category_stats = categories.setdefault(
                case.category,
                {"generated": 0, "executed": 0, "vulnerable": 0, "findings": 0},
            )
            category_stats["generated"] += 1
            category_stats["executed"] += 1
            category_stats["vulnerable"] += int(analysis.vulnerable)
            category_stats["findings"] += len(analysis.findings)

        durations = [execution.response_time_ms or 0.0 for execution in executions]
        total_duration = sum(durations)
        strategies = sorted(
            {case.mutation_strategy for case in cases if case.mutation_strategy}
        )
        categories_tested = sorted(categories)
        metrics = ScanMetrics(
            total_generated_cases=len(cases),
            total_executed_cases=len(executions),
            successful_executions=sum(
                execution.status == "completed" for execution in executions
            ),
            failed_executions=sum(
                execution.status != "completed" for execution in executions
            ),
            timeouts=sum(execution.status == "timeout" for execution in executions),
            retries=sum(execution.retries for execution in executions),
            mutations_generated=sum(case.mutation_depth > 0 for case in cases),
            mutation_strategies_used=strategies,
            categories_tested=categories_tested,
            vulnerable_cases=sum(analysis.vulnerable for analysis in analyses),
            findings=sum(len(analysis.findings) for analysis in analyses),
            average_execution_time_ms=(total_duration / len(durations)) if durations else 0.0,
            total_execution_time_ms=round(total_duration, 2),
            category_statistics=categories,
        )
        coverage = FuzzingCoverage(
            categories_tested=categories_tested,
            mutation_strategies_tested=strategies,
            mutation_depths=sorted({case.mutation_depth for case in cases}),
            unique_prompts=len({case.prompt for case in cases}),
            unique_test_cases=len({case.case_id for case in cases}),
            target_responses=sum(execution.response_body is not None for execution in executions),
        )
        return metrics, coverage


scan_scheduler = ScanScheduler()
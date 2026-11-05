from __future__ import annotations

import logging
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
from app.database.store import Database, database
from app.fuzzing.engine import FUZZ_TEMPLATES
from app.attacks.registry import attack_registry


class ScanScheduler:
    def __init__(
        self,
        max_workers: int = 2,
        *,
        store: Database | None = None,
        recover: bool = False,
    ) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._lock = Lock()
        self._store = store
        self._scans: dict[str, ScanRecord] = {}
        self._requests: dict[str, ScanCreateRequest] = {}
        self._results: dict[str, list[dict[str, object]]] = {}
        self._cancel_events: dict[str, Event] = {}
        self._futures: dict[str, Future[None]] = {}
        if self._store is not None:
            if recover:
                self._store.recover_incomplete_scans()
            self._scans = {scan.scan_id: scan for scan in self._store.list_scans()}
            self._requests = {
                scan.scan_id: request
                for scan in self._scans.values()
                if (request := self._store.get_scan_request(scan.scan_id)) is not None
            }
            self._results = {
                scan_id: self._store.get_results(scan_id) or []
                for scan_id in self._scans
            }

    def start(
        self,
        request: ScanCreateRequest,
        *,
        idempotency_key: str | None = None,
    ) -> ScanRecord:
        scan_id = str(uuid4())
        requested_categories = list(
            request.categories
            or sorted(set(attack_registry.list_categories()) | set(FUZZ_TEMPLATES))
        )
        scan = ScanRecord(
            scan_id=scan_id,
            target_id=request.target_id,
            status=ScanStatus.QUEUED,
            requested_case_count=request.count,
            requested_categories=requested_categories,
            coverage_warning=(
                f"Requested {request.count} total test cases for "
                f"{len(requested_categories)} categories; "
                "not every selected category can receive a base case."
                if request.count < len(requested_categories)
                else None
            ),
        )
        with self._lock:
            if self._store is not None and idempotency_key:
                existing = self._store.get_scan_by_idempotency_key(idempotency_key)
                if existing is not None:
                    return existing
            if self._store is not None:
                self._store.save_scan(scan, request, idempotency_key)
            self._scans[scan_id] = scan
            self._requests[scan_id] = request.model_copy(deep=True)
            self._results[scan_id] = []
            self._cancel_events[scan_id] = Event()
            self._futures[scan_id] = self._executor.submit(self._run, scan_id)
        return scan.model_copy(deep=True)

    def get(self, scan_id: str) -> ScanRecord | None:
        if self._store is not None:
            return self._store.get_scan(scan_id)
        with self._lock:
            scan = self._scans.get(scan_id)
            return scan.model_copy(deep=True) if scan is not None else None

    def list(self) -> list[ScanRecord]:
        if self._store is not None:
            return self._store.list_scans()
        with self._lock:
            return [scan.model_copy(deep=True) for scan in self._scans.values()]

    def get_results(self, scan_id: str) -> list[dict[str, object]] | None:
        if self._store is not None:
            return self._store.get_results(scan_id)
        with self._lock:
            results = self._results.get(scan_id)
            return [dict(result) for result in results] if results is not None else None

    def get_request(self, scan_id: str) -> ScanCreateRequest | None:
        if self._store is not None:
            return self._store.get_scan_request(scan_id)
        with self._lock:
            request = self._requests.get(scan_id)
            return request.model_copy(deep=True) if request is not None else None

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
            cancel_event = self._cancel_events.get(scan_id)
            future = self._futures.get(scan_id)
            if cancel_event is None or future is None:
                return scan.model_copy(deep=True)
            cancel_event.set()
            if future.cancel():
                scan.status = ScanStatus.CANCELLED
                scan.completed_at = datetime.now(timezone.utc)
                if self._store is not None:
                    self._store.update_scan(scan)
            return scan.model_copy(deep=True)

    def _run(self, scan_id: str) -> None:
        with self._lock:
            scan = self._scans[scan_id]
            request = self._requests[scan_id]
            cancel_event = self._cancel_events[scan_id]
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            if self._store is not None:
                self._store.update_scan(scan)

        try:
            generated_cases: list[FuzzCase] | None = None

            def record_generated_cases(cases: list[FuzzCase]) -> None:
                nonlocal generated_cases
                generated_cases = list(cases)
                if self._store is not None:
                    self._store.save_generated_cases(scan_id, cases)
                with self._lock:
                    scan = self._scans[scan_id]
                    scan.generated_case_count = len(cases)
                    scan.generated_categories = sorted({case.category for case in cases})
                    scan.coverage.generated_categories = list(scan.generated_categories)
                    if self._store is not None:
                        self._store.update_scan(scan)

            def record_result(result: dict[str, object]) -> None:
                if self._store is not None:
                    self._store.save_result(scan_id, result)
                with self._lock:
                    self._results[scan_id].append(result)
                    scan = self._scans[scan_id]
                    results_so_far = self._results[scan_id]
                    scan.executed_case_count = len(results_so_far)
                    scan.error_count = sum(
                        getattr(item.get("execution"), "status", None) != "completed"
                        for item in results_so_far
                    )
                    scan.finding_count = sum(
                        len(getattr(item.get("analysis"), "findings", []))
                        for item in results_so_far
                    )
                    scan.executed_categories = sorted({
                        item["case"].category
                        for item in results_so_far
                        if isinstance(item.get("case"), FuzzCase)
                    })
                    scan.category_coverage_percent = (
                        round(
                            len(
                                set(scan.requested_categories).intersection(
                                    scan.executed_categories
                                )
                            )
                            / len(scan.requested_categories)
                            * 100,
                            2,
                        )
                        if scan.requested_categories
                        else 100.0
                    )
                    scan.coverage.executed_categories = list(scan.executed_categories)
                    scan.coverage.category_coverage_percent = scan.category_coverage_percent
                    scan.metrics.total_executed_cases = scan.executed_case_count
                    scan.metrics.failed_executions = scan.error_count
                    scan.metrics.findings = scan.finding_count
                    scan.metrics.categories_tested = list(scan.executed_categories)
                    if self._store is not None:
                        self._store.update_scan(scan)

            results = fuzz_orchestrator.run(
                target_id=request.target_id,
                count=request.count,
                categories=scan.requested_categories,
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
                scan_id=scan_id,
                cancel_event=cancel_event,
                on_cases_generated=record_generated_cases,
                on_result=record_result,
            )
            if results is None:
                raise ValueError("Target no longer exists")
            if self._store is not None:
                for result in results:
                    self._store.save_result(scan_id, result)
            metrics, coverage = self._calculate_metrics(results, generated_cases)
            with self._lock:
                scan = self._scans[scan_id]
                self._results[scan_id] = results
                scan.generated_case_count = metrics.total_generated_cases
                scan.executed_case_count = metrics.total_executed_cases
                scan.finding_count = metrics.findings
                scan.error_count = metrics.failed_executions
                scan.generated_categories = sorted({
                    case.category for case in (generated_cases or [])
                })
                scan.executed_categories = sorted({
                    result["case"].category
                    for result in results
                    if isinstance(result.get("case"), FuzzCase)
                })
                requested_categories = set(scan.requested_categories)
                scan.category_coverage_percent = (
                    round(
                        len(requested_categories.intersection(scan.executed_categories))
                        / len(requested_categories)
                        * 100,
                        2,
                    )
                    if requested_categories
                    else 100.0
                )
                scan.metrics = metrics
                scan.coverage = coverage
                scan.coverage.requested_categories = list(scan.requested_categories)
                scan.coverage.generated_categories = list(scan.generated_categories)
                scan.coverage.executed_categories = list(scan.executed_categories)
                scan.coverage.category_coverage_percent = scan.category_coverage_percent
                scan.status = (
                    ScanStatus.CANCELLED if cancel_event.is_set() else ScanStatus.COMPLETED
                )
                scan.completed_at = datetime.now(timezone.utc)
                if self._store is not None:
                    self._store.update_scan(scan)
        except Exception as exc:
            logging.getLogger(__name__).error(
                "Scan failed for scan_id=%s; exception_type=%s",
                scan_id,
                type(exc).__name__,
            )
            with self._lock:
                scan = self._scans[scan_id]
                scan.status = ScanStatus.FAILED
                scan.failure_reason = (
                    "Target no longer exists."
                    if isinstance(exc, ValueError)
                    and str(exc) == "Target no longer exists"
                    else "Scan failed due to an internal execution error."
                )
                scan.error_count += 1
                scan.completed_at = datetime.now(timezone.utc)
                if self._store is not None:
                    self._store.update_scan(scan)

    def _calculate_metrics(
        self,
        results: list[dict[str, object]],
        generated_cases: list[FuzzCase] | None = None,
    ) -> tuple[ScanMetrics, FuzzingCoverage]:
        cases = [result["case"] for result in results]
        all_generated_cases = generated_cases if generated_cases is not None else cases
        executions = [result["execution"] for result in results]
        analyses = [result["analysis"] for result in results]
        categories: dict[str, dict[str, int]] = {}
        for case in all_generated_cases:
            category_stats = categories.setdefault(
                case.category,
                {"generated": 0, "executed": 0, "vulnerable": 0, "findings": 0},
            )
            category_stats["generated"] += 1
        for case, execution, analysis in zip(cases, executions, analyses):
            category_stats = categories.setdefault(
                case.category,
                {"generated": 0, "executed": 0, "vulnerable": 0, "findings": 0},
            )
            category_stats["executed"] += 1
            category_stats["vulnerable"] += int(analysis.vulnerable)
            category_stats["findings"] += len(analysis.findings)

        durations = [execution.response_time_ms or 0.0 for execution in executions]
        total_duration = sum(durations)
        strategies = sorted(
            {
                case.mutation_strategy
                for case in all_generated_cases
                if case.mutation_strategy
            }
        )
        executed_strategies = sorted(
            {case.mutation_strategy for case in cases if case.mutation_strategy}
        )
        categories_tested = sorted({case.category for case in cases})
        metrics = ScanMetrics(
            total_generated_cases=len(all_generated_cases),
            total_executed_cases=len(executions),
            successful_executions=sum(
                execution.status == "completed" for execution in executions
            ),
            failed_executions=sum(
                execution.status != "completed" for execution in executions
            ),
            timeouts=sum(execution.status == "timeout" for execution in executions),
            retries=sum(execution.retries for execution in executions),
            mutations_generated=sum(
                case.mutation_depth > 0 for case in all_generated_cases
            ),
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
            mutation_strategies_tested=executed_strategies,
            mutation_depths=sorted({case.mutation_depth for case in cases}),
            unique_prompts=len({case.prompt for case in cases}),
            unique_test_cases=len({case.case_id for case in cases}),
            target_responses=sum(execution.response_body is not None for execution in executions),
        )
        return metrics, coverage


scan_scheduler = ScanScheduler(store=database, recover=True)
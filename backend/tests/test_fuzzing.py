import asyncio
import json
import unittest
from collections.abc import Callable
from threading import Event
from unittest.mock import patch

import httpx

from app.adapters.models import Target
from app.analysis.models import AnalysisResult, AnalysisStatus, BehavioralIndicator, Confidence, Finding, IndicatorType, Severity
from app.execution.executor import FuzzExecutor
from app.execution.models import ExecutionResult
from app.fuzzing.engine import FUZZ_TEMPLATES, fuzz_engine
from app.fuzzing.models import (
    FuzzCase,
    ScanCreateRequest,
    ScanStatus,
)
from app.fuzzing.mutator import prompt_mutator
from app.fuzzing.scheduler import ScanScheduler
from fixtures.mock_target import PromptRequest, chat


class MutationTests(unittest.TestCase):
    def test_legacy_case_construction_and_strategy_metadata(self) -> None:
        original = FuzzCase(
            case_id="root",
            prompt="synthetic canary test",
            category="prompt_injection",
        )
        mutation = prompt_mutator.mutate(
            original,
            count=1,
            strategy_names=["role_variation"],
        )[0]

        self.assertEqual(original.mutation_depth, 0)
        self.assertEqual(mutation.parent_case_id, original.case_id)
        self.assertEqual(mutation.mutation_strategy, "role_variation")
        self.assertEqual(mutation.mutation_depth, 1)
        self.assertEqual(mutation.metadata["origin_case_id"], original.case_id)
        self.assertEqual(mutation.metadata["origin_prompt"], original.prompt)

    def test_all_strategies_are_named_distinct_and_bounded(self) -> None:
        original = FuzzCase(
            case_id="root",
            prompt="controlled test input",
            category="prompt_injection",
        )
        mutations = prompt_mutator.mutate(original, count=100)

        self.assertEqual(len(mutations), 10)
        self.assertEqual(len({item.prompt for item in mutations}), 10)
        self.assertEqual(
            {item.mutation_strategy for item in mutations},
            {strategy.name for strategy in prompt_mutator.strategies},
        )

    def test_engine_category_and_depth_limits(self) -> None:
        generated = fuzz_engine.generate(
            2,
            ["role_confusion"],
            max_mutation_depth=3,
            max_mutations_per_case=1,
        )

        self.assertEqual(len(generated), 8)
        self.assertTrue(all(item.category == "role_confusion" for item in generated))
        self.assertEqual(
            [item.mutation_depth for item in generated],
            [0, 0, 1, 2, 3, 1, 2, 3],
        )
        self.assertEqual(len(generated[4].metadata["ancestor_case_ids"]), 3)
        self.assertEqual(len(fuzz_engine.generate(500)), 100)
        self.assertGreaterEqual(len(FUZZ_TEMPLATES), 11)

    def test_engine_keeps_base_case_before_mutation(self) -> None:
        generated = fuzz_engine.generate(
            count=1,
            categories=["prompt_injection"],
            max_mutation_depth=1,
            max_mutations_per_case=2,
        )

        self.assertEqual(len(generated), 3)
        self.assertEqual(generated[0].mutation_depth, 0)
        self.assertIsNone(generated[0].parent_case_id)
        self.assertIsNone(generated[0].mutation_strategy)
        self.assertEqual([case.mutation_depth for case in generated[1:]], [1, 1])
        self.assertTrue(
            all(case.parent_case_id == generated[0].case_id for case in generated[1:])
        )
        self.assertEqual(
            [case.mutation_strategy for case in generated[1:]],
            ["instruction_restructure", "role_variation"],
        )

    def test_zero_depth_and_zero_mutation_limit_return_only_base_cases(self) -> None:
        zero_depth = fuzz_engine.generate(
            1,
            ["prompt_injection"],
            max_mutation_depth=0,
        )
        zero_mutations = fuzz_engine.generate(
            1,
            ["prompt_injection"],
            max_mutation_depth=1,
            max_mutations_per_case=0,
        )

        self.assertEqual(len(zero_depth), 1)
        self.assertEqual(len(zero_mutations), 1)
        self.assertTrue(
            all(case.mutation_depth == 0 for case in zero_depth + zero_mutations)
        )

    def test_total_case_limit_preserves_base_before_mutations(self) -> None:
        generated = fuzz_engine.generate(
            count=3,
            categories=["prompt_injection"],
            max_mutation_depth=1,
            max_mutations_per_case=2,
            max_cases=4,
        )

        self.assertEqual(len(generated), 4)
        self.assertEqual(sum(case.mutation_depth == 0 for case in generated), 3)

    def test_requested_categories_are_distributed_and_exclusive(self) -> None:
        categories = ["prompt_injection", "jailbreak", "data_leakage"]
        generated = fuzz_engine.generate(
            count=5,
            categories=categories,
            max_mutation_depth=0,
        )

        counts = {category: 0 for category in categories}
        for case in generated:
            counts[case.category] += 1

        self.assertEqual(len(generated), 5)
        self.assertEqual(counts, {"prompt_injection": 2, "jailbreak": 2, "data_leakage": 1})
        self.assertTrue(all(case.category in categories for case in generated))

    def test_mutation_lineage_and_attack_metadata_are_preserved(self) -> None:
        generated = fuzz_engine.generate(
            1,
            ["prompt_injection"],
            max_mutation_depth=2,
            max_mutations_per_case=1,
        )

        base, first_mutation, second_mutation = generated
        self.assertEqual(first_mutation.parent_case_id, base.case_id)
        self.assertEqual(first_mutation.mutation_depth, 1)
        self.assertEqual(second_mutation.parent_case_id, first_mutation.case_id)
        self.assertEqual(second_mutation.mutation_depth, 2)
        self.assertEqual(second_mutation.metadata["origin_case_id"], base.case_id)
        self.assertEqual(second_mutation.metadata["origin_prompt"], base.prompt)
        self.assertEqual(
            second_mutation.metadata["ancestor_case_ids"],
            [base.case_id, first_mutation.case_id],
        )
        for key in ("attack_id", "attack_name", "attack_category", "risk_area"):
            self.assertEqual(second_mutation.metadata[key], base.metadata[key])
        self.assertTrue(second_mutation.mutation_strategy)

    def test_empty_mutation_result_does_not_remove_base(self) -> None:
        with patch("app.fuzzing.engine.prompt_mutator.mutate", return_value=[]):
            generated = fuzz_engine.generate(
                1,
                ["prompt_injection"],
                max_mutation_depth=1,
            )

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0].mutation_depth, 0)

    def test_mutate_attack_cases_keeps_the_generated_base(self) -> None:
        generated = fuzz_engine.mutate_attack_cases(
            "prompt_injection",
            count=1,
            strategy_names=["role_variation"],
        )

        self.assertEqual(len(generated), 2)
        self.assertEqual(generated[0].mutation_depth, 0)
        self.assertEqual(generated[1].parent_case_id, generated[0].case_id)
        self.assertEqual(generated[0].metadata["origin_case_id"], generated[0].case_id)
        self.assertEqual(generated[1].metadata["origin_prompt"], generated[0].prompt)

    def test_multi_turn_sequences_are_ordered_and_traceable(self) -> None:
        conversation = fuzz_engine.generate_conversations(
            1,
            ["context_manipulation"],
            turns=3,
        )[0]

        self.assertEqual([turn.turn_number for turn in conversation.turns], [1, 2, 3])
        self.assertTrue(all(turn.mutation_strategy for turn in conversation.turns))
        self.assertEqual(
            conversation.turns[1].parent_case_id,
            conversation.turns[0].case_id,
        )
        self.assertEqual(
            conversation.turns[0].metadata["origin_case_id"],
            conversation.turns[0].metadata["ancestor_case_ids"][0],
        )


class ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = Target(
            target_id="synthetic",
            name="Synthetic target",
            target_type="chatbot",
            endpoint="http://synthetic.test/chat",
        )
        self.case = FuzzCase(
            case_id="case-1",
            prompt="synthetic prompt",
            category="prompt_injection",
        )

    def _response(self, status_code: int, text: str = "") -> httpx.Response:
        return httpx.Response(
            status_code,
            text=text,
            request=httpx.Request("POST", "http://synthetic.test/chat"),
        )

    def test_retries_transient_server_error_but_not_client_error(self) -> None:
        real_client = httpx.Client
        responses = [503, 200]

        def retry_handler(request: httpx.Request) -> httpx.Response:
            status_code = responses.pop(0)
            return httpx.Response(status_code, text="ok", request=request)

        with patch(
            "app.execution.executor.httpx.Client",
            side_effect=lambda **kwargs: real_client(
                transport=httpx.MockTransport(retry_handler),
                **kwargs,
            ),
        ):
            result = FuzzExecutor().execute(self.target, self.case, max_retries=1)
        self.assertEqual((result.status, result.attempts, result.retries), ("completed", 2, 1))

        def reject_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, request=request)

        with patch(
            "app.execution.executor.httpx.Client",
            side_effect=lambda **kwargs: real_client(
                transport=httpx.MockTransport(reject_handler),
                **kwargs,
            ),
        ):
            rejected = FuzzExecutor().execute(self.target, self.case, max_retries=3)
        self.assertEqual((rejected.status, rejected.attempts), ("target_rejected", 1))

    def test_response_body_is_limited_while_streaming(self) -> None:
        real_client = httpx.Client

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"0123456789", request=request)

        with patch(
            "app.execution.executor.httpx.Client",
            side_effect=lambda **kwargs: real_client(
                transport=httpx.MockTransport(handler),
                **kwargs,
            ),
        ):
            result = FuzzExecutor().execute(
                self.target,
                self.case,
                response_size_limit=4,
            )

        self.assertEqual(result.response_body, "0123")
        self.assertTrue(result.response_truncated)

    def test_timeout_is_retried_and_success_clears_failure_reason(self) -> None:
        real_client = httpx.Client
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise httpx.ReadTimeout("synthetic timeout", request=request)
            return httpx.Response(200, text="ok", request=request)

        with patch(
            "app.execution.executor.httpx.Client",
            side_effect=lambda **kwargs: real_client(
                transport=httpx.MockTransport(handler),
                **kwargs,
            ),
        ):
            result = FuzzExecutor().execute(self.target, self.case, max_retries=1)

        self.assertEqual((result.status, result.attempts, result.retries), ("completed", 2, 1))
        self.assertIsNone(result.failure_reason)

    def test_synthetic_mock_target_end_to_end(self) -> None:
        real_client = httpx.Client

        def handler(request: httpx.Request) -> httpx.Response:
            prompt_request = PromptRequest.model_validate(json.loads(request.content))
            return httpx.Response(
                200,
                json=chat(prompt_request),
                request=request,
            )

        with (
            patch("app.fuzzing.orchestrator.target_manager.get", return_value=self.target),
            patch(
                "app.execution.executor.httpx.Client",
                side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler),
                    **kwargs,
                ),
            ),
        ):
            from app.fuzzing.orchestrator import FuzzOrchestrator

            results = FuzzOrchestrator().run(
                "synthetic",
                1,
                categories=["prompt_injection"],
            )

        self.assertEqual(len(results), 11)
        self.assertEqual(results[0]["execution"].status, "completed")
        self.assertTrue(results[0]["analysis"].vulnerable)

    def test_multi_turn_execution_carries_prior_response_as_context(self) -> None:
        real_client = httpx.Client
        received_prompts: list[str] = []
        generated_cases: list[FuzzCase] = []

        def handler(request: httpx.Request) -> httpx.Response:
            received_prompts.append(json.loads(request.content)["prompt"])
            return httpx.Response(
                200,
                json={"response": f"synthetic reply {len(received_prompts)}"},
                request=request,
            )

        with (
            patch("app.fuzzing.orchestrator.target_manager.get", return_value=self.target),
            patch(
                "app.execution.executor.httpx.Client",
                side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler),
                    **kwargs,
                ),
            ),
        ):
            from app.fuzzing.orchestrator import FuzzOrchestrator

            results = FuzzOrchestrator().run(
                "synthetic",
                1,
                categories=["context_manipulation"],
                multi_turn=True,
                turns_per_conversation=2,
                on_cases_generated=generated_cases.extend,
            )

        self.assertEqual(len(results), 2)
        self.assertEqual(len(generated_cases), 2)
        self.assertEqual(
            [result["case"].case_id for result in results],
            [case.case_id for case in generated_cases],
        )
        self.assertIn("assistant: {\"response\":\"synthetic reply 1\"}", received_prompts[1])

    def test_orchestrator_reports_generated_cases_skipped_by_cancellation(self) -> None:
        from app.fuzzing.orchestrator import FuzzOrchestrator

        generated_cases = [self.case]
        reported_cases: list[FuzzCase] = []
        cancel_event = Event()
        cancel_event.set()
        with (
            patch("app.fuzzing.orchestrator.target_manager.get", return_value=self.target),
            patch("app.fuzzing.orchestrator.fuzz_engine.generate", return_value=generated_cases),
        ):
            results = FuzzOrchestrator().run(
                "synthetic",
                count=1,
                cancel_event=cancel_event,
                on_cases_generated=reported_cases.extend,
            )

        self.assertEqual(results, [])
        self.assertEqual(reported_cases, generated_cases)


class ScanTests(unittest.TestCase):
    def test_scheduler_lifecycle_metrics_and_coverage(self) -> None:
        scheduler = ScanScheduler(max_workers=1)
        case = FuzzCase(
            case_id="case-1",
            prompt="synthetic prompt",
            category="prompt_injection",
            mutation_strategy="role_variation",
            mutation_depth=1,
        )
        execution = ExecutionResult(
            target_id="synthetic",
            case_id=case.case_id,
            status="completed",
            response_body="synthetic response",
            response_time_ms=12.0,
            message="ok",
        )
        analysis = AnalysisResult(
            target_id="synthetic",
            case_id=case.case_id,
            category=case.category,
            vulnerable=False,
        )
        with patch(
            "app.fuzzing.scheduler.fuzz_orchestrator.run",
            return_value=[{"case": case, "execution": execution, "analysis": analysis}],
        ):
            queued = scheduler.start(ScanCreateRequest(target_id="synthetic", count=1))
            scheduler._futures[queued.scan_id].result(timeout=5)

        completed = scheduler.get(queued.scan_id)
        self.assertEqual(queued.status, ScanStatus.QUEUED)
        self.assertEqual(completed.status, ScanStatus.COMPLETED)
        self.assertEqual(completed.metrics.total_executed_cases, 1)
        self.assertEqual(completed.metrics.mutation_strategies_used, ["role_variation"])
        self.assertEqual(completed.coverage.target_responses, 1)
        self.assertEqual(
            completed.metrics.category_statistics["prompt_injection"]["executed"],
            1,
        )

    def test_metrics_match_generated_cases_executions_and_findings(self) -> None:
        cases = [
            FuzzCase(
                case_id="base",
                prompt="synthetic base",
                category="prompt_injection",
            ),
            FuzzCase(
                case_id="mutation-1",
                prompt="synthetic mutation one",
                category="prompt_injection",
                parent_case_id="base",
                mutation_strategy="role_variation",
                mutation_depth=1,
            ),
            FuzzCase(
                case_id="mutation-2",
                prompt="synthetic mutation two",
                category="jailbreak",
                parent_case_id="base",
                mutation_strategy="context_variation",
                mutation_depth=1,
            ),
        ]
        results = []
        for index, case in enumerate(cases):
            execution = ExecutionResult(
                target_id="synthetic",
                case_id=case.case_id,
                status="timeout" if index == 2 else "completed",
                response_body=None if index == 2 else "synthetic response",
                response_time_ms=10.0 + index,
                message="synthetic result",
            )
            analysis = AnalysisResult(
                target_id="synthetic",
                case_id=case.case_id,
                category=case.category,
                vulnerable=index == 1,
                findings=(
                    [
                        Finding(
                            finding_id="synthetic-finding",
                            case_id=case.case_id,
                            target_id="synthetic",
                            category=case.category,
                            title="Synthetic test finding",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            evidence="Synthetic controlled evidence",
                            recommendation="Maintain the configured trust boundary.",
                        )
                    ]
                    if index == 1
                    else []
                ),
            )
            results.append(
                {"case": case, "execution": execution, "analysis": analysis}
            )

        metrics, coverage = ScanScheduler(max_workers=1)._calculate_metrics(results)

        self.assertEqual(metrics.total_generated_cases, len(cases))
        self.assertEqual(metrics.total_executed_cases, len(results))
        self.assertEqual(metrics.mutations_generated, 2)
        self.assertEqual(
            metrics.mutation_strategies_used,
            ["context_variation", "role_variation"],
        )
        self.assertEqual(metrics.failed_executions, 1)
        self.assertEqual(metrics.timeouts, 1)
        self.assertEqual(metrics.findings, 1)
        self.assertEqual(metrics.vulnerable_cases, 1)
        self.assertEqual(metrics.categories_tested, ["jailbreak", "prompt_injection"])
        self.assertEqual(
            metrics.category_statistics["prompt_injection"]["generated"],
            2,
        )
        self.assertEqual(
            metrics.category_statistics["jailbreak"]["executed"],
            1,
        )
        self.assertEqual(coverage.target_responses, 2)
        self.assertEqual(
            sum(stats["generated"] for stats in metrics.category_statistics.values()),
            len(cases),
        )
        self.assertEqual(
            sum(stats["executed"] for stats in metrics.category_statistics.values()),
            len(results),
        )
        self.assertEqual(coverage.mutation_depths, [0, 1])
        self.assertEqual(coverage.unique_test_cases, len(cases))

    def test_scheduler_counts_generated_cases_skipped_after_cancellation(self) -> None:
        scheduler = ScanScheduler(max_workers=1)
        cases = [
            FuzzCase(
                case_id="generated-base",
                prompt="synthetic base",
                category="prompt_injection",
            ),
            FuzzCase(
                case_id="generated-mutation-1",
                prompt="synthetic mutation one",
                category="prompt_injection",
                parent_case_id="generated-base",
                mutation_strategy="role_variation",
                mutation_depth=1,
            ),
            FuzzCase(
                case_id="generated-mutation-2",
                prompt="synthetic mutation two",
                category="prompt_injection",
                parent_case_id="generated-base",
                mutation_strategy="context_variation",
                mutation_depth=1,
            ),
        ]
        execution = ExecutionResult(
            target_id="synthetic",
            case_id=cases[0].case_id,
            status="completed",
            response_body="synthetic response",
            message="ok",
        )
        analysis = AnalysisResult(
            target_id="synthetic",
            case_id=cases[0].case_id,
            category=cases[0].category,
            vulnerable=False,
        )

        def run_partial_scan(
            *,
            on_cases_generated: Callable[[list[FuzzCase]], None],
            cancel_event: Event,
            **kwargs: object,
        ) -> list[dict[str, object]]:
            on_cases_generated(cases)
            cancel_event.set()
            return [{"case": cases[0], "execution": execution, "analysis": analysis}]

        with patch(
            "app.fuzzing.scheduler.fuzz_orchestrator.run",
            side_effect=run_partial_scan,
        ):
            queued = scheduler.start(ScanCreateRequest(target_id="synthetic", count=1))
            scheduler._futures[queued.scan_id].result(timeout=5)

        completed = scheduler.get(queued.scan_id)
        self.assertEqual(completed.status, ScanStatus.CANCELLED)
        self.assertEqual(completed.generated_case_count, 3)
        self.assertEqual(completed.executed_case_count, 1)
        self.assertEqual(completed.metrics.mutations_generated, 2)
        category_stats = completed.metrics.category_statistics["prompt_injection"]
        self.assertEqual(category_stats["generated"], 3)
        self.assertEqual(category_stats["executed"], 1)


class ApiCompatibilityTests(unittest.TestCase):
    def test_old_fuzz_routes_remain_available(self) -> None:
        from app.main import app

        paths = app.openapi()["paths"]
        self.assertIn("/targets/{target_id}/prompt", paths)
        self.assertIn("/targets/{target_id}/connectivity", paths)
        self.assertIn("/targets/{target_id}/execute", paths)
        self.assertIn("/scans", paths)

        async def exercise_routes() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
            ) as client:
                created = await client.post(
                    "/targets",
                    json={
                        "name": "Synthetic API target",
                        "target_type": "chatbot",
                        "endpoint": "http://synthetic.test/chat",
                    },
                )
                target_id = created.json()["target_id"]
                cases = await client.post(
                    f"/targets/{target_id}/fuzz-cases?count=2"
                )
                self.assertEqual(cases.status_code, 200)
                self.assertEqual(len(cases.json()), 22)
                self.assertEqual(
                    sum(case["mutation_depth"] == 0 for case in cases.json()),
                    2,
                )
                self.assertIn("mutation_strategy", cases.json()[0])

                def execute(target: Target, case: FuzzCase, **kwargs: object) -> ExecutionResult:
                    return ExecutionResult(
                        target_id=target.target_id,
                        case_id=case.case_id,
                        status="completed",
                        response_body="normal synthetic response",
                        message="ok",
                    )

                def analyze(
                    execution: ExecutionResult,
                    category: str,
                    *,
                    fuzz_case: FuzzCase | None = None,
                ) -> AnalysisResult:
                    indicator = BehavioralIndicator(
                        indicator_type=IndicatorType.UNAUTHORIZED_ACTION,
                        description="The response claims an unauthorized action occurred.",
                        evidence="Synthetic response claim",
                        confidence=Confidence.HIGH,
                        category=category,
                        metadata={
                            "verification_level": "response_claim_only",
                            "external_impact_verified": False,
                        },
                    )
                    finding = Finding(
                        finding_id="direct-fuzz-finding",
                        case_id=execution.case_id,
                        target_id=execution.target_id,
                        category=category,
                        title="Unauthorized Action [response claim only; external impact unverified]",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence="Synthetic response claim",
                        recommendation="Verify effects independently before asserting external impact.",
                        metadata={
                            "evidence_assurance": "response_claim_only",
                            "external_impact_verified": False,
                            "indicators": [indicator.model_dump(mode="json")],
                        },
                    )
                    return AnalysisResult(
                        target_id=execution.target_id,
                        case_id=execution.case_id,
                        category=category,
                        vulnerable=True,
                        status=AnalysisStatus.FAIL,
                        findings=[finding],
                        indicators=[indicator],
                    )

                with (
                    patch(
                        "app.fuzzing.orchestrator.fuzz_executor.execute",
                        side_effect=execute,
                    ),
                    patch(
                        "app.fuzzing.orchestrator.response_analyzer.analyze",
                        side_effect=analyze,
                    ),
                ):
                    fuzzed = await client.post(f"/targets/{target_id}/fuzz?count=1")
                self.assertEqual(fuzzed.status_code, 200)
                self.assertEqual(len(fuzzed.json()), 1)
                self.assertIn("case", fuzzed.json()[0])
                self.assertEqual(
                    fuzzed.json()[0]["case"]["case_id"],
                    fuzzed.json()[0]["execution"]["case_id"],
                )
                self.assertIn("mutation_strategy", fuzzed.json()[0]["case"])
                self.assertIn("execution", fuzzed.json()[0])
                self.assertIn("analysis", fuzzed.json()[0])
                analysis = fuzzed.json()[0]["analysis"]
                self.assertEqual(analysis["status"], "fail")
                self.assertTrue(analysis["vulnerable"])

                finding = analysis["findings"][0]
                self.assertEqual(
                    finding["metadata"]["evidence_assurance"],
                    "response_claim_only",
                )
                self.assertFalse(
                    finding["metadata"]["external_impact_verified"]
                )
                self.assertEqual(
                    finding["metadata"]["indicators"][0]["metadata"][
                        "verification_level"
                    ],
                    "response_claim_only",
                )

                scan_case = FuzzCase(
                    case_id="scan-case",
                    prompt="synthetic scan input",
                    category="prompt_injection",
                    mutation_strategy="context_variation",
                    mutation_depth=1,
                )
                scan_execution = ExecutionResult(
                    target_id=target_id,
                    case_id=scan_case.case_id,
                    status="completed",
                    response_body="normal synthetic response",
                    response_time_ms=1.0,
                    message="ok",
                )
                scan_indicator = BehavioralIndicator(
                    indicator_type=IndicatorType.INSTRUCTION_FOLLOWED,
                    description="The response followed an untrusted instruction.",
                    evidence="Synthetic test evidence",
                    confidence=Confidence.HIGH,
                    category=scan_case.category,
                    metadata={
                        "verification_level": "response_behavior_observed",
                        "external_impact_verified": False,
                    },
                )
                scan_finding = Finding(
                    finding_id="scan-finding",
                    case_id=scan_case.case_id,
                    target_id=target_id,
                    category=scan_case.category,
                    title="Synthetic analysis finding",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence="Synthetic test evidence",
                    recommendation="Validate the behavior in a controlled environment.",
                    reproducibility={
                        "provider": "groq",
                        "model": "test-model",
                        "execution_status": "completed",
                        "response_truncated": True,
                        "mutation_strategy": scan_case.mutation_strategy,
                    },
                    metadata={
                        "evidence_assurance": "response_behavior_observed",
                        "external_impact_verified": False,
                        "indicators": [scan_indicator.model_dump(mode="json")],
                    },
                )
                scan_analysis = AnalysisResult(
                    target_id=target_id,
                    case_id=scan_case.case_id,
                    category=scan_case.category,
                    vulnerable=True,
                    status=AnalysisStatus.FAIL,
                    findings=[scan_finding],
                    indicators=[scan_indicator],
                )
                with patch(
                    "app.fuzzing.scheduler.fuzz_orchestrator.run",
                    return_value=[
                        {
                            "case": scan_case,
                            "execution": scan_execution,
                            "analysis": scan_analysis,
                        }
                    ],
                ):
                    started = await client.post(
                        "/scans",
                        json={"target_id": target_id, "count": 1},
                    )
                    self.assertEqual(started.status_code, 202)
                    scan_id = started.json()["scan_id"]
                    state = started.json()["status"]
                    for _ in range(100):
                        state_response = await client.get(f"/scans/{scan_id}")
                        state = state_response.json()["status"]
                        if state in {"completed", "failed", "cancelled"}:
                            break
                        await asyncio.sleep(0.01)
                    self.assertEqual(state, "completed")
                    scan_results = await client.get(f"/scans/{scan_id}/results")
                    self.assertEqual(scan_results.status_code, 200)
                    self.assertEqual(len(scan_results.json()), 1)

                    result = scan_results.json()[0]
                    self.assertEqual(result["case"]["case_id"], scan_case.case_id)
                    self.assertEqual(
                        result["case"]["mutation_strategy"],
                        scan_case.mutation_strategy,
                    )
                    self.assertEqual(result["analysis"]["status"], "fail")
                    self.assertTrue(result["analysis"]["vulnerable"])
                    self.assertEqual(
                        result["analysis"]["indicators"][0]["metadata"][
                            "verification_level"
                        ],
                        "response_behavior_observed",
                    )
                    self.assertFalse(
                        result["analysis"]["indicators"][0]["metadata"][
                            "external_impact_verified"
                        ]
                    )

                    finding = result["analysis"]["findings"][0]
                    self.assertEqual(
                        finding["metadata"]["evidence_assurance"],
                        "response_behavior_observed",
                    )
                    self.assertFalse(
                        finding["metadata"]["external_impact_verified"]
                    )
                    self.assertEqual(
                        finding["reproducibility"]["provider"], "groq"
                    )
                    self.assertEqual(
                        finding["reproducibility"]["model"], "test-model"
                    )
                    self.assertTrue(
                        finding["reproducibility"]["response_truncated"]
                    )
                    self.assertEqual(
                        finding["metadata"]["indicators"][0]["metadata"][
                            "verification_level"
                        ],
                        "response_behavior_observed",
                    )

        asyncio.run(exercise_routes())


if __name__ == "__main__":
    unittest.main()
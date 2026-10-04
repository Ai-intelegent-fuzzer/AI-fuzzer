import asyncio
import json
import unittest
from unittest.mock import patch

import httpx

from app.adapters.models import Target
from app.analysis.models import AnalysisResult
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
        )

        self.assertEqual(len(generated), 2)
        self.assertTrue(all(item.category == "role_confusion" for item in generated))
        self.assertTrue(all(item.mutation_depth == 3 for item in generated))
        self.assertTrue(all(len(item.metadata["ancestor_case_ids"]) == 3 for item in generated))
        self.assertEqual(len(fuzz_engine.generate(500)), 100)
        self.assertGreaterEqual(len(FUZZ_TEMPLATES), 11)

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

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["execution"].status, "completed")
        self.assertTrue(results[0]["analysis"].vulnerable)

    def test_multi_turn_execution_carries_prior_response_as_context(self) -> None:
        real_client = httpx.Client
        received_prompts: list[str] = []

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
            )

        self.assertEqual(len(results), 2)
        self.assertIn("assistant: {\"response\":\"synthetic reply 1\"}", received_prompts[1])


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


class ApiCompatibilityTests(unittest.TestCase):
    def test_old_fuzz_routes_remain_available(self) -> None:
        from app.main import app

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
                self.assertEqual(len(cases.json()), 2)
                self.assertIn("mutation_strategy", cases.json()[0])

                def execute(target: Target, case: FuzzCase, **kwargs: object) -> ExecutionResult:
                    return ExecutionResult(
                        target_id=target.target_id,
                        case_id=case.case_id,
                        status="completed",
                        response_body="normal synthetic response",
                        message="ok",
                    )

                with patch("app.fuzzing.orchestrator.fuzz_executor.execute", side_effect=execute):
                    fuzzed = await client.post(f"/targets/{target_id}/fuzz?count=1")
                self.assertEqual(fuzzed.status_code, 200)
                self.assertEqual(len(fuzzed.json()), 1)
                self.assertIn("execution", fuzzed.json()[0])
                self.assertIn("analysis", fuzzed.json()[0])

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
                scan_analysis = AnalysisResult(
                    target_id=target_id,
                    case_id=scan_case.case_id,
                    category=scan_case.category,
                    vulnerable=False,
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

        asyncio.run(exercise_routes())


if __name__ == "__main__":
    unittest.main()
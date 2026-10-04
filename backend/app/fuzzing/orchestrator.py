import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

from app.adapters.manager import target_manager
from app.analysis.analyzer import response_analyzer
from app.execution.executor import fuzz_executor
from app.fuzzing.engine import fuzz_engine
from app.fuzzing.models import FuzzCase, FuzzConversation


class FuzzOrchestrator:
    def run(
        self,
        target_id: str,
        count: int = 4,
        *,
        categories: list[str] | None = None,
        max_mutation_depth: int = 1,
        max_cases: int = 100,
        max_mutations_per_case: int = 10,
        timeout_seconds: float = 30.0,
        max_retries: int = 0,
        concurrency: int = 1,
        delay_seconds: float = 0.0,
        execution_order: str = "generated",
        multi_turn: bool = False,
        turns_per_conversation: int = 3,
        cancel_event: Event | None = None,
    ) -> list[dict[str, object]] | None:
        target = target_manager.get(target_id)
        if target is None:
            return None

        def execute_case(
            fuzz_case: FuzzCase,
            conversation_context: list[str] | None = None,
        ) -> dict[str, object] | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            if delay_seconds > 0:
                wait_for_rate_limit()
            execution = fuzz_executor.execute(
                target,
                fuzz_case,
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
                conversation_context=conversation_context,
            )
            analysis = response_analyzer.analyze(
                execution=execution,
                category=fuzz_case.category,
            )
            return {"case": fuzz_case, "execution": execution, "analysis": analysis}

        worker_count = min(max(concurrency, 1), 8)
        rate_lock = Lock()
        next_execution_at = 0.0

        def wait_for_rate_limit() -> None:
            nonlocal next_execution_at
            if delay_seconds <= 0:
                return
            with rate_lock:
                now = time.monotonic()
                time.sleep(max(0.0, next_execution_at - now))
                next_execution_at = time.monotonic() + min(delay_seconds, 10.0)

        if multi_turn:
            turns = min(max(turns_per_conversation, 1), 10)
            conversation_count = min(max(count, 0), max_cases // turns)
            conversations = fuzz_engine.generate_conversations(
                conversation_count,
                categories,
                turns=turns,
            )

            def execute_conversation(
                conversation: FuzzConversation,
            ) -> list[dict[str, object]]:
                history: list[str] = []
                conversation_results: list[dict[str, object]] = []
                for turn in conversation.turns:
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    fuzz_case = FuzzCase(
                        case_id=turn.case_id,
                        prompt=turn.prompt,
                        category=conversation.category,
                        parent_case_id=turn.parent_case_id,
                        mutation_strategy=turn.mutation_strategy,
                        mutation_depth=turn.turn_number,
                        sequence_id=conversation.conversation_id,
                        metadata={"origin_prompt": conversation.metadata["origin_prompt"]},
                    )
                    result = execute_case(fuzz_case, history)
                    if result is not None:
                        conversation_results.append(result)
                        execution = result["execution"]
                        history.extend(
                            [
                                f"user: {turn.prompt}",
                                f"assistant: {execution.response_body or ''}",
                            ]
                        )
                return conversation_results

            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                nested_results = list(pool.map(execute_conversation, conversations))
            return [result for group in nested_results for result in group]

        fuzz_cases = fuzz_engine.generate(
            count,
            categories,
            max_mutation_depth=max_mutation_depth,
            max_cases=max_cases,
            max_mutations_per_case=max_mutations_per_case,
        )
        if execution_order == "reverse":
            fuzz_cases.reverse()
        elif execution_order == "category":
            fuzz_cases.sort(key=lambda item: (item.category, item.case_id))

        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            results = list(pool.map(execute_case, fuzz_cases))
        return [result for result in results if result is not None]


fuzz_orchestrator = FuzzOrchestrator()

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

from app.adapters.manager import target_manager
from app.analysis.analyzer import response_analyzer
from app.execution.executor import fuzz_executor
from app.adapters.factory import get_adapter
from app.analysis.models import EvidenceProvenance
from app.analysis.provenance import (
    build_evidence_provenance,
    verified_active_canaries,
)
from app.rag.capabilities import category_supported_by_profile
from app.fuzzing.engine import FUZZ_TEMPLATES
from app.fuzzing.engine import fuzz_engine
from app.fuzzing.models import FuzzCase, FuzzConversation, FuzzTurn


class FuzzOrchestrator:
    def run(
        self,
        target_id: str,
        count: int = 4,
        *,
        categories: list[str] | None = None,
        max_mutation_depth: int = 1,
        max_cases: int = 1000,
        total_case_limit: int | None = None,
        max_mutations_per_case: int = 10,
        timeout_seconds: float = 30.0,
        max_retries: int = 0,
        concurrency: int = 1,
        delay_seconds: float = 0.0,
        execution_order: str = "generated",
        multi_turn: bool = False,
        turns_per_conversation: int = 3,
        scan_id: str | None = None,
        cancel_event: Event | None = None,
        on_cases_generated: Callable[[list[FuzzCase]], None] | None = None,
        on_provenance: Callable[[list[EvidenceProvenance]], None] | None = None,
        on_result: Callable[[dict[str, object]], None] | None = None,
        cases: list[FuzzCase] | None = None,
    ) -> list[dict[str, object]] | None:
        target = target_manager.get(target_id)
        if target is None:
            return None
        selected_categories = (
            list(FUZZ_TEMPLATES)
            if categories is None
            else list(categories)
        )
        selected_categories = [
            category
            for category in selected_categories
            if category_supported_by_profile(
                category,
                target.capability_profile,
                target.target_scope,
            )
        ]
        adapter = get_adapter(target)

        def execute_case(
            fuzz_case: FuzzCase,
            conversation_context: list[str] | None = None,
        ) -> dict[str, object] | None:
            if cancel_event is not None and cancel_event.is_set():
                return None
            if delay_seconds > 0:
                wait_for_rate_limit()
            execution = adapter.execute_case(
                fuzz_case,
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
                conversation_context=conversation_context,
            )
            if scan_id is not None:
                execution = execution.model_copy(update={"scan_id": scan_id})
            provenance = build_evidence_provenance(
                target,
                fuzz_case,
                execution,
                scan_id=scan_id,
                conversation_context=conversation_context,
            )
            analysis_case = fuzz_case.model_copy(deep=True)
            analysis_case.metadata["active_protected_canaries"] = (
                verified_active_canaries(fuzz_case.metadata, provenance)
            )
            analysis_case.metadata["evidence_provenance"] = [
                item.model_dump(mode="json") for item in provenance
            ]
            analysis = response_analyzer.analyze(
                execution=execution,
                category=fuzz_case.category,
                fuzz_case=analysis_case,
            )
            if on_provenance is not None:
                on_provenance(analysis.evidence_provenance)
            result = {"case": fuzz_case, "execution": execution, "analysis": analysis}
            if on_result is not None:
                on_result(result)
            return result

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
            total_case_limit = min(max(count, 0), max_cases)

            def conversation_case(
                conversation: FuzzConversation,
                turn: FuzzTurn,
            ) -> FuzzCase:
                return FuzzCase(
                    case_id=turn.case_id,
                    prompt=turn.prompt,
                    category=conversation.category,
                    parent_case_id=turn.parent_case_id,
                    mutation_strategy=turn.mutation_strategy,
                    mutation_depth=turn.turn_number - 1,
                    sequence_id=conversation.conversation_id,
                    metadata={**conversation.metadata, **turn.metadata},
                )

            conversations = fuzz_engine.generate_conversations(
                total_case_limit,
                selected_categories,
                turns=turns,
            )
            generated_cases = [
                conversation_case(conversation, turn)
                for conversation in conversations
                for turn in conversation.turns
            ]

            if on_cases_generated is not None:
                on_cases_generated(generated_cases)

            def execute_conversation(
                conversation: FuzzConversation,
            ) -> list[dict[str, object]]:
                history: list[str] = []
                conversation_results: list[dict[str, object]] = []
                for turn in conversation.turns:
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    fuzz_case = conversation_case(conversation, turn)
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

        fuzz_cases = list(cases) if cases is not None else fuzz_engine.generate(
            count,
            selected_categories,
            max_mutation_depth=max_mutation_depth,
            max_cases=min(max_cases, count),
            max_mutations_per_case=max_mutations_per_case,
        )
        if total_case_limit is not None:
            fuzz_cases = fuzz_cases[:max(total_case_limit, 0)]
        if on_cases_generated is not None:
            on_cases_generated(list(fuzz_cases))
        if execution_order == "reverse":
            fuzz_cases.reverse()
        elif execution_order == "category":
            fuzz_cases.sort(key=lambda item: (item.category, item.case_id))

        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            results = list(pool.map(execute_case, fuzz_cases))
        return [result for result in results if result is not None]


fuzz_orchestrator = FuzzOrchestrator()

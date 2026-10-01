from app.adapters.manager import target_manager
from app.analysis.analyzer import response_analyzer
from app.execution.executor import fuzz_executor
from app.fuzzing.engine import fuzz_engine


class FuzzOrchestrator:

    def run(self, target_id: str, count: int = 4):
        target = target_manager.get(target_id)

        if target is None:
            return None

        fuzz_cases = fuzz_engine.generate(count)

        results = []

        for fuzz_case in fuzz_cases:
            execution = fuzz_executor.execute(
                target,
                fuzz_case,
            )

            analysis = response_analyzer.analyze(
                execution=execution,
                category=fuzz_case.category,
            )

            results.append(
                {
                    "execution": execution,
                    "analysis": analysis,
                }
            )

        return results


fuzz_orchestrator = FuzzOrchestrator()

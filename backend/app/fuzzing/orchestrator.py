from app.adapters.manager import target_manager
from app.execution.executor import fuzz_executor
from app.fuzzing.engine import fuzz_engine
from app.fuzzing.models import FuzzCase


class FuzzOrchestrator:

    def run(self, target_id: str, count: int = 4):
        target = target_manager.get(target_id)

        if target is None:
            return None

        fuzz_cases = fuzz_engine.generate(count)

        results = []

        for fuzz_case in fuzz_cases:
            result = fuzz_executor.execute(
                target,
                fuzz_case,
            )
            results.append(result)

        return results


fuzz_orchestrator = FuzzOrchestrator()

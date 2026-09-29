import time

import httpx

from app.adapters.models import Target
from app.fuzzing.models import FuzzCase
from .models import ExecutionResult


class FuzzExecutor:

    def execute(
        self,
        target: Target,
        fuzz_case: FuzzCase,
    ) -> ExecutionResult:

        start = time.perf_counter()

        try:
            with httpx.Client(timeout=30.0) as client:

                response = client.post(
                    str(target.endpoint),
                    json={
                        "prompt": fuzz_case.prompt,
                    },
                )

            elapsed = (time.perf_counter() - start) * 1000

            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status="completed",
                status_code=response.status_code,
                response_time_ms=round(elapsed, 2),
                response_body=response.text[:10000],
                message="Fuzz case executed successfully.",
            )

        except httpx.TimeoutException:
            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status="timeout",
                message="Target request timed out.",
            )

        except httpx.HTTPError as exc:
            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status="error",
                message=f"HTTP error: {exc}",
            )

        except Exception as exc:
            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status="error",
                message=f"Unexpected error: {exc}",
            )


fuzz_executor = FuzzExecutor()

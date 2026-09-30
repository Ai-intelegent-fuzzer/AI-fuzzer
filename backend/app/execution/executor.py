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

            if 200 <= response.status_code < 300:
                execution_status = "completed"
                execution_message = "Fuzz case executed successfully."
            elif 400 <= response.status_code < 500:
                execution_status = "target_rejected"
                execution_message = (
                    f"Target rejected the fuzz request with HTTP {response.status_code}."
                )
            elif 500 <= response.status_code < 600:
                execution_status = "target_error"
                execution_message = (
                    f"Target returned server error HTTP {response.status_code}."
                )
            else:
                execution_status = "completed"
                execution_message = (
                    f"Target returned HTTP {response.status_code}."
                )

            return ExecutionResult(
                target_id=target.target_id,
                case_id=fuzz_case.case_id,
                status=execution_status,
                status_code=response.status_code,
                response_time_ms=round(elapsed, 2),
                response_body=response.text[:10000],
                message=execution_message,
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

import logging
import time

import httpx

from app.adapters.endpoint_policy import (
    UnsafeTargetEndpointError,
    validate_target_endpoint,
)
from app.adapters.models import Target, TargetType
from app.fuzzing.models import FuzzCase
from app.execution.executor import fuzz_executor
from .models import ConnectivityResult, ConnectivityStatus


class ConnectivityTester:

    def test(self, target: Target) -> ConnectivityResult:
        start = time.perf_counter()

        if target.target_type == TargetType.OPENAI_COMPATIBLE:
            execution = fuzz_executor.execute(
                target,
                FuzzCase(
                    case_id="connectivity-check",
                    prompt="Reply with exactly: AI-Fuzzer connectivity OK",
                    category="connectivity_check",
                ),
                timeout_seconds=30.0,
                max_retries=0,
            )
            status = (
                ConnectivityStatus.REACHABLE
                if execution.status == "completed"
                else ConnectivityStatus.TIMEOUT
                if execution.status == "timeout"
                else ConnectivityStatus.ERROR
            )
            return ConnectivityResult(
                target_id=target.target_id,
                status=status,
                status_code=execution.status_code,
                response_time_ms=execution.response_time_ms,
                message=(
                    "Authenticated model inference succeeded."
                    if status == ConnectivityStatus.REACHABLE
                    else f"Model inference failed ({execution.status}): {execution.message}"
                ),
            )

        try:
            validate_target_endpoint(str(target.endpoint))
        except UnsafeTargetEndpointError:
            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.ERROR,
                message="Target endpoint is not allowed by the server's endpoint policy.",
            )

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(
                    str(target.endpoint),
                    follow_redirects=False,
                )

            elapsed = (time.perf_counter() - start) * 1000

            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.REACHABLE,
                status_code=response.status_code,
                response_time_ms=round(elapsed, 2),
                message="Target endpoint is reachable.",
            )

        except httpx.TimeoutException:
            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.TIMEOUT,
                message="Target request timed out.",
            )

        except httpx.HTTPError:
            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.ERROR,
                message="Could not connect to the target endpoint.",
            )

        except Exception as exc:
            logging.getLogger(__name__).error(
                "Unexpected connectivity error for target_id=%s; exception_type=%s",
                target.target_id,
                type(exc).__name__,
            )
            return ConnectivityResult(
                target_id=target.target_id,
                status=ConnectivityStatus.ERROR,
                message="Unexpected connectivity error.",
            )


connectivity_tester = ConnectivityTester()

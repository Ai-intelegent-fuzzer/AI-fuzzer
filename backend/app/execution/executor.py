import time
from collections.abc import Sequence

import httpx

from app.adapters.models import Target
from app.fuzzing.models import FuzzCase
from .models import ExecutionResult


class FuzzExecutor:
    MAX_TIMEOUT_SECONDS = 120.0
    MAX_RETRIES = 5
    MAX_RESPONSE_SIZE = 10000

    def execute(
        self,
        target: Target,
        fuzz_case: FuzzCase,
        *,
        timeout_seconds: float = 30.0,
        max_retries: int = 0,
        response_size_limit: int = MAX_RESPONSE_SIZE,
        conversation_context: Sequence[str] | None = None,
    ) -> ExecutionResult:
        start = time.perf_counter()
        timeout = min(max(timeout_seconds, 0.1), self.MAX_TIMEOUT_SECONDS)
        retry_limit = min(max(max_retries, 0), self.MAX_RETRIES)
        response_limit = min(max(response_size_limit, 0), self.MAX_RESPONSE_SIZE)
        prompt = fuzz_case.prompt
        if conversation_context:
            history = "\n".join(
                f"Turn {index}: {turn}"
                for index, turn in enumerate(conversation_context, start=1)
            )
            prompt = f"Conversation history:\n{history}\n\nCurrent turn:\n{prompt}"

        attempts = 0
        response: httpx.Response | None = None
        failure_reason: str | None = None
        final_status = "error"
        response_truncated = False

        while attempts <= retry_limit:
            attempts += 1
            try:
                with httpx.Client(timeout=timeout) as client:
                    with client.stream(
                        "POST",
                        str(target.endpoint),
                        json={"prompt": prompt},
                    ) as streamed:
                        if streamed.status_code >= 500 and attempts <= retry_limit:
                            continue
                        response_content = bytearray()
                        for chunk in streamed.iter_bytes():
                            remaining = response_limit + 1 - len(response_content)
                            if remaining <= 0:
                                break
                            response_content.extend(chunk[:remaining])
                            if len(response_content) > response_limit:
                                break
                        response_truncated = len(response_content) > response_limit
                        response = httpx.Response(
                            status_code=streamed.status_code,
                            headers=streamed.headers,
                            content=bytes(response_content[:response_limit]),
                            request=streamed.request,
                        )
                if 200 <= response.status_code < 300:
                    final_status = "completed"
                elif 400 <= response.status_code < 500:
                    final_status = "target_rejected"
                elif response.status_code >= 500:
                    final_status = "target_error"
                else:
                    final_status = "completed"
                break
            except httpx.TimeoutException as exc:
                failure_reason = str(exc) or "Target request timed out."
                final_status = "timeout"
            except httpx.NetworkError as exc:
                failure_reason = str(exc) or "Target network request failed."
                final_status = "error"
            except httpx.HTTPError as exc:
                failure_reason = str(exc)
                final_status = "error"
                break
            except Exception as exc:
                failure_reason = str(exc)
                final_status = "error"
                break

        elapsed = (time.perf_counter() - start) * 1000
        body = response.text if response is not None else None

        if response is not None:
            message = (
                "Fuzz case executed successfully."
                if final_status == "completed"
                else f"Target returned HTTP {response.status_code}."
            )
            if final_status == "target_rejected":
                message = f"Target rejected the fuzz request with HTTP {response.status_code}."
            elif final_status == "target_error":
                message = f"Target returned server error HTTP {response.status_code}."
            failure_reason = (
                message
                if final_status in {"target_rejected", "target_error"}
                else None
            )
        else:
            message = failure_reason or "Target request failed."

        return ExecutionResult(
            target_id=target.target_id,
            case_id=fuzz_case.case_id,
            status=final_status,
            status_code=response.status_code if response is not None else None,
            response_time_ms=round(elapsed, 2),
            response_body=body,
            message=message,
            attempts=attempts,
            retries=max(attempts - 1, 0),
            failure_reason=failure_reason,
            response_truncated=response_truncated,
        )


fuzz_executor = FuzzExecutor()
